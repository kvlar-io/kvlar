//! Cloud audit sink — forwards audit events to SHIELD and RADAR in batches.
//!
//! `KvlarCloudSink` batches events and forwards them asynchronously to
//! both SHIELD (`/api/v1/events`) and RADAR (`/api/v1/events`).
//! Failures are logged to stderr but never block the proxy (fire-and-forget).

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::interval;

use crate::event::AuditEvent;

const MAX_BATCH_SIZE: usize = 100;
const FLUSH_INTERVAL: Duration = Duration::from_secs(5);
const MAX_RETRIES: u32 = 3;

/// Configuration for `KvlarCloudSink`.
#[derive(Debug, Clone)]
pub struct CloudSinkConfig {
    /// SHIELD event ingestion URL (e.g., `https://app.kvlar.io/api/v1/events`).
    pub shield_url: Option<String>,
    /// RADAR event ingestion URL (e.g., `https://radar.kvlar.io/api/v1/events`).
    pub radar_url: Option<String>,
    /// API key for authentication (`Authorization: Bearer <key>`).
    pub api_key: String,
}

/// Handle for sending events to `KvlarCloudSink`.
#[derive(Clone)]
pub struct KvlarCloudSink {
    tx: mpsc::Sender<AuditEvent>,
}

impl KvlarCloudSink {
    /// Creates a new cloud sink and spawns background flush task.
    ///
    /// Events are collected in a channel and flushed every 5 seconds or
    /// when 100 events accumulate. Both SHIELD and RADAR receive each batch.
    pub fn new(config: CloudSinkConfig) -> Self {
        let (tx, mut rx) = mpsc::channel::<AuditEvent>(1024);

        let config = Arc::new(config);

        tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("failed to build reqwest client");

            let mut batch: Vec<AuditEvent> = Vec::with_capacity(MAX_BATCH_SIZE);
            let mut ticker = interval(FLUSH_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    event = rx.recv() => {
                        match event {
                            Some(e) => {
                                batch.push(e);
                                if batch.len() >= MAX_BATCH_SIZE {
                                    flush_batch(&client, &config, std::mem::take(&mut batch)).await;
                                }
                            }
                            None => {
                                // Channel closed — flush remaining and exit
                                if !batch.is_empty() {
                                    flush_batch(&client, &config, std::mem::take(&mut batch)).await;
                                }
                                break;
                            }
                        }
                    }
                    _ = ticker.tick() => {
                        if !batch.is_empty() {
                            flush_batch(&client, &config, std::mem::take(&mut batch)).await;
                        }
                    }
                }
            }
        });

        Self { tx }
    }

    /// Send an audit event to be forwarded to SHIELD and RADAR.
    ///
    /// This is non-blocking. If the channel is full, the event is dropped
    /// and the error is logged to stderr.
    pub fn log(&self, event: AuditEvent) {
        if let Err(e) = self.tx.try_send(event) {
            eprintln!("[kvlar-audit] Cloud sink dropped event: {}", e);
        }
    }
}

async fn flush_batch(client: &reqwest::Client, config: &CloudSinkConfig, batch: Vec<AuditEvent>) {
    if batch.is_empty() {
        return;
    }

    let payload = serde_json::json!({ "events": batch });

    let targets: Vec<&str> = [config.shield_url.as_deref(), config.radar_url.as_deref()]
        .into_iter()
        .flatten()
        .collect();

    for url in targets {
        if let Err(e) = post_with_retry(client, url, &config.api_key, &payload).await {
            eprintln!(
                "[kvlar-audit] Failed to flush {} events to {}: {}",
                batch.len(),
                url,
                e
            );
        }
    }
}

async fn post_with_retry(
    client: &reqwest::Client,
    url: &str,
    api_key: &str,
    payload: &serde_json::Value,
) -> Result<(), String> {
    let mut delay_ms = 50u64;

    for attempt in 0..=MAX_RETRIES {
        let res = client
            .post(url)
            .bearer_auth(api_key)
            .json(payload)
            .send()
            .await;

        match res {
            Ok(r) if r.status().is_success() => return Ok(()),
            Ok(r) if r.status().is_server_error() && attempt < MAX_RETRIES => {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                delay_ms *= 2;
            }
            Ok(r) => return Err(format!("HTTP {}", r.status())),
            Err(e) if attempt < MAX_RETRIES => {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                delay_ms *= 2;
                let _ = e; // continue retrying
            }
            Err(e) => return Err(e.to_string()),
        }
    }

    Err("max retries exceeded".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_creation() {
        let config = CloudSinkConfig {
            shield_url: Some("https://app.kvlar.io/api/v1/events".to_string()),
            radar_url: Some("https://radar.kvlar.io/api/v1/events".to_string()),
            api_key: "kvlar_sk_test".to_string(),
        };
        assert!(config.shield_url.is_some());
        assert!(config.radar_url.is_some());
    }

    #[tokio::test]
    async fn test_sink_log_does_not_block() {
        use crate::event::EventOutcome;

        let config = CloudSinkConfig {
            shield_url: None, // no URLs → flush is a no-op
            radar_url: None,
            api_key: "test".to_string(),
        };
        let sink = KvlarCloudSink::new(config);

        // Log 10 events — should not block
        for i in 0..10 {
            let event = AuditEvent::new(
                "tool_call",
                format!("resource-{}", i),
                "agent-1",
                EventOutcome::Allowed,
                "test-rule",
            );
            sink.log(event);
        }
        // No panic = pass
    }
}
