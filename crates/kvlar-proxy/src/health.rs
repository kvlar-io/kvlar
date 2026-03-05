//! Health check endpoint and proxy statistics.
//!
//! Provides a lightweight HTTP `/health` endpoint for liveness probes
//! (Docker, K8s, load balancers) and tracks proxy runtime statistics.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use serde::Serialize;

/// Tracks proxy runtime statistics.
///
/// Uses atomics for lock-free, concurrent counter updates.
#[derive(Debug)]
pub struct ProxyStats {
    /// When the proxy was started.
    started_at: Instant,

    /// Total requests evaluated by the policy engine.
    requests_evaluated: AtomicU64,

    /// Total requests allowed.
    requests_allowed: AtomicU64,

    /// Total requests denied.
    requests_denied: AtomicU64,

    /// Total requests pending approval.
    requests_approval: AtomicU64,

    /// Number of policy rules loaded.
    rules_count: AtomicU64,

    /// Whether a policy is currently loaded.
    policy_loaded: AtomicU64,
}

impl ProxyStats {
    /// Creates a new stats tracker.
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            requests_evaluated: AtomicU64::new(0),
            requests_allowed: AtomicU64::new(0),
            requests_denied: AtomicU64::new(0),
            requests_approval: AtomicU64::new(0),
            rules_count: AtomicU64::new(0),
            policy_loaded: AtomicU64::new(0),
        }
    }

    /// Records an allowed request.
    pub fn record_allow(&self) {
        self.requests_evaluated.fetch_add(1, Ordering::Relaxed);
        self.requests_allowed.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a denied request.
    pub fn record_deny(&self) {
        self.requests_evaluated.fetch_add(1, Ordering::Relaxed);
        self.requests_denied.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a require-approval request.
    pub fn record_approval(&self) {
        self.requests_evaluated.fetch_add(1, Ordering::Relaxed);
        self.requests_approval.fetch_add(1, Ordering::Relaxed);
    }

    /// Updates the policy metadata.
    pub fn set_policy_info(&self, loaded: bool, rules: u64) {
        self.policy_loaded
            .store(if loaded { 1 } else { 0 }, Ordering::Relaxed);
        self.rules_count.store(rules, Ordering::Relaxed);
    }

    /// Returns a snapshot of current health status.
    pub fn health_snapshot(&self) -> HealthStatus {
        HealthStatus {
            status: "ok".into(),
            uptime_secs: self.started_at.elapsed().as_secs(),
            policy_loaded: self.policy_loaded.load(Ordering::Relaxed) != 0,
            rules_count: self.rules_count.load(Ordering::Relaxed),
            requests_evaluated: self.requests_evaluated.load(Ordering::Relaxed),
            requests_allowed: self.requests_allowed.load(Ordering::Relaxed),
            requests_denied: self.requests_denied.load(Ordering::Relaxed),
            requests_approval: self.requests_approval.load(Ordering::Relaxed),
            version: crate::VERSION.into(),
        }
    }
}

impl Default for ProxyStats {
    fn default() -> Self {
        Self::new()
    }
}

/// JSON response for the `/health` endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct HealthStatus {
    /// Always "ok" if the server is responding.
    pub status: String,

    /// Seconds since the proxy started.
    pub uptime_secs: u64,

    /// Whether at least one policy is loaded.
    pub policy_loaded: bool,

    /// Total number of policy rules loaded.
    pub rules_count: u64,

    /// Total tool call requests evaluated.
    pub requests_evaluated: u64,

    /// Total requests allowed.
    pub requests_allowed: u64,

    /// Total requests denied.
    pub requests_denied: u64,

    /// Total requests pending approval.
    pub requests_approval: u64,

    /// Kvlar proxy version.
    pub version: String,
}

/// Runs a lightweight HTTP health check server on the given address.
///
/// Responds to `GET /health` with a JSON `HealthStatus` body.
/// Any other request gets a 404. This is intentionally minimal —
/// no framework dependencies, just raw TCP + HTTP parsing.
pub async fn run_health_server(
    addr: &str,
    stats: Arc<ProxyStats>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(addr = %addr, "health check endpoint listening");

    loop {
        let (mut stream, _) = listener.accept().await?;
        let stats = stats.clone();

        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let mut buf = vec![0u8; 1024];
            let n = match stream.read(&mut buf).await {
                Ok(n) => n,
                Err(_) => return,
            };

            let request = String::from_utf8_lossy(&buf[..n]);

            // Simple HTTP request parsing — check for GET /health
            let (status, body) = if request.starts_with("GET /health") {
                let health = stats.health_snapshot();
                let json = serde_json::to_string(&health).unwrap_or_default();
                ("200 OK", json)
            } else {
                ("404 Not Found", r#"{"error":"not found"}"#.into())
            };

            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status,
                body.len(),
                body,
            );

            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_stats_new() {
        let stats = ProxyStats::new();
        let health = stats.health_snapshot();
        assert_eq!(health.status, "ok");
        assert_eq!(health.requests_evaluated, 0);
        assert!(!health.policy_loaded);
    }

    #[test]
    fn test_proxy_stats_record() {
        let stats = ProxyStats::new();

        stats.record_allow();
        stats.record_allow();
        stats.record_deny();
        stats.record_approval();

        let health = stats.health_snapshot();
        assert_eq!(health.requests_evaluated, 4);
        assert_eq!(health.requests_allowed, 2);
        assert_eq!(health.requests_denied, 1);
        assert_eq!(health.requests_approval, 1);
    }

    #[test]
    fn test_proxy_stats_policy_info() {
        let stats = ProxyStats::new();

        stats.set_policy_info(true, 5);
        let health = stats.health_snapshot();
        assert!(health.policy_loaded);
        assert_eq!(health.rules_count, 5);
    }

    #[test]
    fn test_health_status_serialization() {
        let stats = ProxyStats::new();
        stats.set_policy_info(true, 3);
        stats.record_allow();

        let health = stats.health_snapshot();
        let json = serde_json::to_value(&health).unwrap();
        assert_eq!(json["status"], "ok");
        assert_eq!(json["policy_loaded"], true);
        assert_eq!(json["rules_count"], 3);
        assert_eq!(json["requests_evaluated"], 1);
        assert!(json["version"].is_string());
    }

    #[tokio::test]
    async fn test_health_server_responds() {
        let stats = Arc::new(ProxyStats::new());
        stats.set_policy_info(true, 5);
        stats.record_allow();
        stats.record_deny();

        // Start health server on random port
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let stats_clone = stats.clone();
        let addr_str = addr.to_string();
        let server = tokio::spawn(async move {
            let _ = run_health_server(&addr_str, stats_clone).await;
        });

        // Give server a moment to start
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Send a GET /health request
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut response = vec![0u8; 4096];
        let n = stream.read(&mut response).await.unwrap();
        let response_str = String::from_utf8_lossy(&response[..n]);

        assert!(response_str.contains("200 OK"));
        assert!(response_str.contains("\"status\":\"ok\""));
        assert!(response_str.contains("\"policy_loaded\":true"));
        assert!(response_str.contains("\"requests_evaluated\":2"));

        server.abort();
    }
}
