//! Integration test: KvlarCloudSink forwards batched audit events to a mock HTTP server.
//!
//! Spins up a real TCP listener that speaks minimal HTTP/1.1, sends events
//! through KvlarCloudSink, and asserts the server received a valid JSON batch.

use std::sync::Arc;
use std::time::Duration;

use kvlar_audit::event::{AuditEvent, EventOutcome};
use kvlar_audit::sink::{CloudSinkConfig, KvlarCloudSink};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

/// Read a full HTTP/1.1 request from a TCP stream and return the body.
/// Parses Content-Length to ensure the entire body is read.
async fn read_http_body<S>(stream: &mut S) -> String
where
    S: AsyncReadExt + Unpin,
{
    let mut raw = Vec::new();

    // Read until we find the header/body separator "\r\n\r\n"
    let mut header_end = None;
    let mut header_buf = [0u8; 1];
    loop {
        match stream.read(&mut header_buf).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                raw.push(header_buf[0]);
                if raw.ends_with(b"\r\n\r\n") {
                    header_end = Some(raw.len());
                    break;
                }
                // Safety limit: stop if headers are absurdly large
                if raw.len() > 64 * 1024 {
                    break;
                }
            }
        }
    }

    let Some(header_len) = header_end else {
        return String::new();
    };

    // Parse Content-Length from headers
    let headers_str = String::from_utf8_lossy(&raw[..header_len]);
    let content_length: usize = headers_str
        .lines()
        .find_map(|line| {
            let lower = line.to_lowercase();
            if lower.starts_with("content-length:") {
                lower.split(':').nth(1).and_then(|v| v.trim().parse().ok())
            } else {
                None
            }
        })
        .unwrap_or(0);

    if content_length == 0 {
        return String::new();
    }

    // Read exactly content_length bytes for the body
    let mut body = vec![0u8; content_length];
    let mut read = 0;
    while read < content_length {
        match stream.read(&mut body[read..]).await {
            Ok(0) | Err(_) => break,
            Ok(n) => read += n,
        }
    }

    String::from_utf8_lossy(&body[..read]).into_owned()
}

/// Reply helper
async fn http_ok(stream: &mut (impl AsyncWriteExt + Unpin)) {
    let _ = stream
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}",
        )
        .await;
}

async fn http_500(stream: &mut (impl AsyncWriteExt + Unpin)) {
    let _ = stream
        .write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n")
        .await;
}

/// Minimal HTTP/1.1 server that always responds 200 and captures the first body.
async fn start_mock_server() -> (u16, Arc<Mutex<Option<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let captured_body: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let captured_clone = captured_body.clone();

    tokio::spawn(async move {
        // Accept up to 10 connections (retry attempts may send multiple requests)
        for _ in 0..10 {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let captured = captured_clone.clone();
            tokio::spawn(async move {
                let body = read_http_body(&mut stream).await;
                {
                    let mut guard = captured.lock().await;
                    if guard.is_none() && !body.is_empty() {
                        *guard = Some(body);
                    }
                }
                http_ok(&mut stream).await;
            });
        }
    });

    (port, captured_body)
}

#[tokio::test]
async fn test_cloud_sink_forwards_events_to_mock_server() {
    let (port, captured) = start_mock_server().await;
    let url = format!("http://127.0.0.1:{}/api/v1/events", port);

    let config = CloudSinkConfig {
        shield_url: Some(url.clone()),
        radar_url: None,
        api_key: "kvlar_sk_integration_test".to_string(),
    };

    let sink = KvlarCloudSink::new(config);

    // Send exactly MAX_BATCH_SIZE (100) events to trigger an immediate flush
    // without waiting for the 5-second timer.
    for i in 0..100 {
        let event = AuditEvent::new(
            "tool_call",
            format!("resource-{}", i),
            "integration-agent",
            EventOutcome::Allowed,
            "allow-all",
        );
        sink.log(event);
    }

    // Give the background task time to flush
    tokio::time::sleep(Duration::from_millis(500)).await;

    let guard = captured.lock().await;
    let body = guard
        .as_ref()
        .expect("mock server should have received a request");

    // Verify the body is valid JSON with an "events" array
    let parsed: serde_json::Value =
        serde_json::from_str(body).unwrap_or_else(|e| panic!("invalid JSON: {e}: body={body:?}"));

    let events_array = parsed
        .get("events")
        .and_then(|v| v.as_array())
        .expect("body should have an 'events' array");

    assert_eq!(
        events_array.len(),
        100,
        "all 100 events should be in the batch"
    );

    // Verify event structure
    let first = &events_array[0];
    assert!(first.get("id").is_some(), "event should have 'id'");
    assert_eq!(first["action_type"], "tool_call");
    assert_eq!(first["agent_id"], "integration-agent");
    assert_eq!(first["outcome"], "allowed");
}

#[tokio::test]
async fn test_cloud_sink_retries_on_5xx_then_succeeds() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let attempts = Arc::new(Mutex::new(0u32));
    let attempts_clone = attempts.clone();

    tokio::spawn(async move {
        for _ in 0..5 {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let attempts_ref = attempts_clone.clone();
            tokio::spawn(async move {
                // Read and discard the body so the connection is consumed
                let _ = read_http_body(&mut stream).await;

                let mut guard = attempts_ref.lock().await;
                *guard += 1;
                let current = *guard;
                drop(guard);

                // First 2 attempts fail with 500; 3rd succeeds
                if current < 3 {
                    http_500(&mut stream).await;
                } else {
                    http_ok(&mut stream).await;
                }
            });
        }
    });

    let url = format!("http://127.0.0.1:{}/api/v1/events", port);
    let config = CloudSinkConfig {
        shield_url: Some(url),
        radar_url: None,
        api_key: "kvlar_sk_retry_test".to_string(),
    };

    let sink = KvlarCloudSink::new(config);

    // Trigger immediate flush with 100 events
    for i in 0..100 {
        let event = AuditEvent::new(
            "tool_call",
            format!("res-{}", i),
            "retry-agent",
            EventOutcome::Denied,
            "deny-rule",
        );
        sink.log(event);
    }

    // Allow enough time for retries (exponential backoff: 50ms + 100ms + flush)
    tokio::time::sleep(Duration::from_millis(800)).await;

    let count = *attempts.lock().await;
    assert!(
        count >= 2,
        "should have retried at least twice (got {count} attempts)",
    );
}

#[tokio::test]
async fn test_cloud_sink_sends_to_both_shield_and_radar() {
    let (shield_port, shield_captured) = start_mock_server().await;
    let (radar_port, radar_captured) = start_mock_server().await;

    let config = CloudSinkConfig {
        shield_url: Some(format!("http://127.0.0.1:{}/api/v1/events", shield_port)),
        radar_url: Some(format!("http://127.0.0.1:{}/api/v1/events", radar_port)),
        api_key: "kvlar_sk_dual_test".to_string(),
    };

    let sink = KvlarCloudSink::new(config);

    // Trigger immediate flush with 100 events
    for i in 0..100 {
        let event = AuditEvent::new(
            "tool_call",
            format!("resource-{}", i),
            "dual-agent",
            EventOutcome::PendingApproval,
            "escalate-rule",
        );
        sink.log(event);
    }

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Both endpoints should have received the batch
    {
        let guard = shield_captured.lock().await;
        assert!(
            guard.is_some(),
            "SHIELD endpoint should have received events"
        );
    }
    {
        let guard = radar_captured.lock().await;
        assert!(
            guard.is_some(),
            "RADAR endpoint should have received events"
        );
    }
}
