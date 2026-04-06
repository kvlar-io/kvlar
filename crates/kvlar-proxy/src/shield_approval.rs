//! SHIELD cloud approval backend.
//!
//! When the proxy evaluates a policy and gets `RequireApproval`, this backend
//! creates an escalation in SHIELD and polls for the human decision.

use std::time::Duration;

use kvlar_core::{ApprovalRequest, ApprovalResponse};

use crate::approval::{ApprovalBackend, ApprovalError};

/// Default polling interval between SHIELD status checks.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Default timeout before treating an unanswered escalation as deny.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

/// Approval backend that integrates with SHIELD's escalation center.
///
/// When called, it:
/// 1. POSTs to `{shield_url}/api/v1/escalations` to register the escalation
/// 2. Polls `GET {shield_url}/api/v1/escalations/{id}` every `poll_interval`
/// 3. Returns the human decision (approved / denied) or times out after `timeout`
pub struct ShieldApprovalBackend {
    shield_url: String,
    api_key: String,
    client: reqwest::Client,
    /// How long to wait for a human decision before treating as deny.
    timeout: Duration,
    /// How frequently to poll the escalation status endpoint.
    poll_interval: Duration,
}

impl ShieldApprovalBackend {
    /// Creates a new SHIELD approval backend with the default 5-second poll interval.
    ///
    /// # Arguments
    /// * `shield_url` — Base URL of the SHIELD instance (e.g., `https://app.kvlar.io`)
    /// * `api_key` — API key for authentication
    /// * `timeout` — How long to poll before timing out (default: 300s)
    pub fn new(
        shield_url: impl Into<String>,
        api_key: impl Into<String>,
        timeout: Duration,
    ) -> Self {
        Self::with_poll_interval(shield_url, api_key, timeout, DEFAULT_POLL_INTERVAL)
    }

    /// Creates a new SHIELD approval backend with a custom poll interval.
    ///
    /// Primarily used in tests to keep poll times short.
    ///
    /// # Arguments
    /// * `shield_url` — Base URL of the SHIELD instance
    /// * `api_key` — API key for authentication
    /// * `timeout` — How long to poll before timing out
    /// * `poll_interval` — How often to check the escalation status
    pub fn with_poll_interval(
        shield_url: impl Into<String>,
        api_key: impl Into<String>,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("failed to build reqwest client");

        Self {
            shield_url: shield_url.into().trim_end_matches('/').to_string(),
            api_key: api_key.into(),
            client,
            timeout,
            poll_interval,
        }
    }
}

impl ApprovalBackend for ShieldApprovalBackend {
    fn request_approval(
        &self,
        request: &ApprovalRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ApprovalResponse, ApprovalError>> + Send + '_>,
    > {
        let shield_url = self.shield_url.clone();
        let api_key = self.api_key.clone();
        let client = self.client.clone();
        let timeout = self.timeout;
        let poll_interval = self.poll_interval;
        let request = request.clone();

        Box::pin(async move {
            // Step 1: Create escalation in SHIELD
            let create_url = format!("{}/api/v1/escalations", shield_url);
            let body = serde_json::json!({
                "actionType": "tool_call",
                "resource": request.tool_name,
                "parameters": request.tool_arguments,
                "ruleMatched": request.rule_id,
                "reason": request.reason,
                "timeoutSeconds": timeout.as_secs(),
            });

            let create_resp = client
                .post(&create_url)
                .bearer_auth(&api_key)
                .json(&body)
                .send()
                .await
                .map_err(|e| ApprovalError::Backend(format!("failed to create escalation: {e}")))?;

            if !create_resp.status().is_success() {
                return Err(ApprovalError::Backend(format!(
                    "SHIELD returned {} when creating escalation",
                    create_resp.status()
                )));
            }

            let created: serde_json::Value = create_resp.json().await.map_err(|e| {
                ApprovalError::Backend(format!("failed to parse create response: {e}"))
            })?;

            let escalation_id = created["id"]
                .as_str()
                .ok_or_else(|| {
                    ApprovalError::Backend("missing id in escalation response".to_string())
                })?
                .to_string();

            tracing::info!(
                escalation_id = %escalation_id,
                tool = %request.tool_name,
                "escalation created in SHIELD, polling for decision"
            );

            // Step 2: Poll for decision
            let poll_url = format!("{}/api/v1/escalations/{}", shield_url, escalation_id);
            let deadline = std::time::Instant::now() + timeout;

            loop {
                tokio::time::sleep(poll_interval).await;

                if std::time::Instant::now() >= deadline {
                    tracing::warn!(
                        escalation_id = %escalation_id,
                        timeout_secs = %timeout.as_secs(),
                        "escalation timed out — treating as deny"
                    );
                    return Err(ApprovalError::Timeout(timeout));
                }

                let poll_resp = client
                    .get(&poll_url)
                    .bearer_auth(&api_key)
                    .send()
                    .await
                    .map_err(|e| ApprovalError::Backend(format!("poll request failed: {e}")))?;

                if !poll_resp.status().is_success() {
                    // Transient error — keep polling
                    tracing::debug!(
                        status = %poll_resp.status(),
                        "transient poll error, will retry"
                    );
                    continue;
                }

                let status_body: serde_json::Value = poll_resp.json().await.map_err(|e| {
                    ApprovalError::Backend(format!("failed to parse poll response: {e}"))
                })?;

                let status = status_body["status"].as_str().unwrap_or("pending");
                let decision_reason = status_body["decisionReason"].as_str().map(str::to_string);

                match status {
                    "approved" => {
                        tracing::info!(
                            escalation_id = %escalation_id,
                            "escalation approved by human reviewer"
                        );
                        return Ok(ApprovalResponse::Approved);
                    }
                    "denied" => {
                        let reason = decision_reason
                            .or_else(|| Some("Denied by human reviewer".to_string()));
                        tracing::warn!(
                            escalation_id = %escalation_id,
                            reason = ?reason,
                            "escalation denied by human reviewer"
                        );
                        return Ok(ApprovalResponse::Denied { reason });
                    }
                    "expired" => {
                        tracing::warn!(
                            escalation_id = %escalation_id,
                            "escalation expired in SHIELD — treating as timeout"
                        );
                        return Err(ApprovalError::Timeout(timeout));
                    }
                    _ => {
                        // Still pending — keep polling
                        tracing::debug!(
                            escalation_id = %escalation_id,
                            status = %status,
                            "escalation still pending, will poll again"
                        );
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::ApprovalBackend;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Reads one HTTP request body from a raw TCP connection.
    async fn read_http_request(stream: &mut tokio::net::TcpStream) -> String {
        let mut buf = vec![0u8; 8192];
        let n = stream.read(&mut buf).await.unwrap_or(0);
        String::from_utf8_lossy(&buf[..n]).to_string()
    }

    /// Sends an HTTP 200 JSON response.
    async fn send_json(stream: &mut tokio::net::TcpStream, body: &str) {
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes()).await;
    }

    fn sample_request() -> ApprovalRequest {
        ApprovalRequest::new(
            "send_email",
            serde_json::json!({"to": "user@example.com", "subject": "Hello"}),
            "approve-email",
            "Email requires approval",
            "agent-test",
        )
    }

    // ── unit tests ────────────────────────────────────────────────────────────

    #[test]
    fn test_shield_backend_creation() {
        let backend = ShieldApprovalBackend::new(
            "https://app.kvlar.io",
            "kvlar_sk_test",
            Duration::from_secs(300),
        );
        assert_eq!(backend.shield_url, "https://app.kvlar.io");
        assert_eq!(backend.timeout, Duration::from_secs(300));
        assert_eq!(backend.poll_interval, DEFAULT_POLL_INTERVAL);
    }

    #[test]
    fn test_url_trailing_slash_stripped() {
        let backend =
            ShieldApprovalBackend::new("https://app.kvlar.io/", "key", Duration::from_secs(60));
        assert_eq!(backend.shield_url, "https://app.kvlar.io");
    }

    #[test]
    fn test_custom_poll_interval() {
        let backend = ShieldApprovalBackend::with_poll_interval(
            "https://app.kvlar.io",
            "key",
            Duration::from_secs(300),
            Duration::from_millis(100),
        );
        assert_eq!(backend.poll_interval, Duration::from_millis(100));
    }

    // ── mock SHIELD API tests ─────────────────────────────────────────────────

    /// Spawn a mock HTTP server that handles ONE create call then ONE poll call.
    ///
    /// `poll_status` – the status string the poll endpoint returns.
    /// `poll_reason` – optional decisionReason string.
    ///
    /// Returns the server's base URL.
    async fn spawn_mock_shield(
        escalation_id: &'static str,
        poll_status: &'static str,
        poll_reason: Option<&'static str>,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let id = escalation_id;

        tokio::spawn(async move {
            // Handle create request
            let (mut stream, _) = listener.accept().await.unwrap();
            let _req = read_http_request(&mut stream).await;
            let create_body = format!(r#"{{"id":"{id}","status":"pending"}}"#);
            send_json(&mut stream, &create_body).await;
            drop(stream);

            // Handle poll request
            let (mut stream, _) = listener.accept().await.unwrap();
            let _req = read_http_request(&mut stream).await;
            let reason_field = match poll_reason {
                Some(r) => format!(r#","decisionReason":"{r}""#),
                None => String::new(),
            };
            let poll_body = format!(r#"{{"id":"{id}","status":"{poll_status}"{reason_field}}}"#);
            send_json(&mut stream, &poll_body).await;
            drop(stream);
        });

        format!("http://127.0.0.1:{}", port)
    }

    /// Mock that serves `pending` for the first N polls then resolves.
    async fn spawn_mock_shield_with_pending_first(
        escalation_id: &'static str,
        pending_count: usize,
        final_status: &'static str,
        final_reason: Option<&'static str>,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let id = escalation_id;

        tokio::spawn(async move {
            // Handle create request
            let (mut stream, _) = listener.accept().await.unwrap();
            let _req = read_http_request(&mut stream).await;
            let create_body = format!(r#"{{"id":"{id}","status":"pending"}}"#);
            send_json(&mut stream, &create_body).await;
            drop(stream);

            // Serve `pending` responses first
            for _ in 0..pending_count {
                let (mut stream, _) = listener.accept().await.unwrap();
                let _req = read_http_request(&mut stream).await;
                let body = format!(r#"{{"id":"{id}","status":"pending"}}"#);
                send_json(&mut stream, &body).await;
                drop(stream);
            }

            // Final resolution
            let (mut stream, _) = listener.accept().await.unwrap();
            let _req = read_http_request(&mut stream).await;
            let reason_field = match final_reason {
                Some(r) => format!(r#","decisionReason":"{r}""#),
                None => String::new(),
            };
            let body = format!(r#"{{"id":"{id}","status":"{final_status}"{reason_field}}}"#);
            send_json(&mut stream, &body).await;
            drop(stream);
        });

        format!("http://127.0.0.1:{}", port)
    }

    #[tokio::test]
    async fn test_mock_shield_approved() {
        let base_url = spawn_mock_shield("esc-001", "approved", None).await;

        let backend = ShieldApprovalBackend::with_poll_interval(
            &base_url,
            "kvlar_sk_test",
            Duration::from_secs(30),
            Duration::from_millis(50), // fast poll for tests
        );

        let req = sample_request();
        let result = backend.request_approval(&req).await.unwrap();

        assert!(
            matches!(result, ApprovalResponse::Approved),
            "expected Approved, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_mock_shield_denied_with_reason() {
        let base_url = spawn_mock_shield("esc-002", "denied", Some("Too risky")).await;

        let backend = ShieldApprovalBackend::with_poll_interval(
            &base_url,
            "kvlar_sk_test",
            Duration::from_secs(30),
            Duration::from_millis(50),
        );

        let req = sample_request();
        let result = backend.request_approval(&req).await.unwrap();

        match result {
            ApprovalResponse::Denied { reason } => {
                assert_eq!(reason.as_deref(), Some("Too risky"));
            }
            other => panic!("expected Denied, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_mock_shield_denied_without_reason_uses_default() {
        let base_url = spawn_mock_shield("esc-003", "denied", None).await;

        let backend = ShieldApprovalBackend::with_poll_interval(
            &base_url,
            "kvlar_sk_test",
            Duration::from_secs(30),
            Duration::from_millis(50),
        );

        let req = sample_request();
        let result = backend.request_approval(&req).await.unwrap();

        match result {
            ApprovalResponse::Denied { reason } => {
                assert!(
                    reason.as_deref().unwrap().contains("reviewer"),
                    "expected fallback reason, got {:?}",
                    reason
                );
            }
            other => panic!("expected Denied, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_mock_shield_timeout_treated_as_deny() {
        // Server that never resolves (only serves create + infinite pending).
        // We set a very short timeout so it fires quickly.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let _req = read_http_request(&mut stream).await;
                // Always return pending (both POST create and GET poll)
                let body = r#"{"id":"esc-timeout","status":"pending"}"#;
                send_json(&mut stream, body).await;
            }
        });

        let base_url = format!("http://127.0.0.1:{}", port);
        // Timeout after 200ms so test is fast; poll every 50ms
        let backend = ShieldApprovalBackend::with_poll_interval(
            &base_url,
            "kvlar_sk_test",
            Duration::from_millis(200),
            Duration::from_millis(50),
        );

        let req = sample_request();
        let result = backend.request_approval(&req).await;

        assert!(
            matches!(result, Err(ApprovalError::Timeout(_))),
            "expected Timeout error, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_mock_shield_expired_status_treated_as_timeout() {
        // SHIELD can also return "expired" status (the escalation expired on the server side)
        let base_url = spawn_mock_shield("esc-004", "expired", None).await;

        let backend = ShieldApprovalBackend::with_poll_interval(
            &base_url,
            "kvlar_sk_test",
            Duration::from_secs(30),
            Duration::from_millis(50),
        );

        let req = sample_request();
        let result = backend.request_approval(&req).await;

        assert!(
            matches!(result, Err(ApprovalError::Timeout(_))),
            "expected Timeout error for 'expired' status, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_mock_shield_polls_multiple_times_then_approves() {
        // Serves 2 pending responses, then approved
        let base_url = spawn_mock_shield_with_pending_first("esc-005", 2, "approved", None).await;

        let backend = ShieldApprovalBackend::with_poll_interval(
            &base_url,
            "kvlar_sk_test",
            Duration::from_secs(30),
            Duration::from_millis(50),
        );

        let req = sample_request();
        let result = backend.request_approval(&req).await.unwrap();

        assert!(
            matches!(result, ApprovalResponse::Approved),
            "expected Approved after pending polls, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_mock_shield_create_sends_correct_fields() {
        // Verify the POST body contains required fields
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let captured_body = Arc::new(tokio::sync::Mutex::new(String::new()));
        let captured_body_clone = captured_body.clone();

        tokio::spawn(async move {
            // Capture create request body
            let (mut stream, _) = listener.accept().await.unwrap();
            let raw = read_http_request(&mut stream).await;
            // Extract JSON body (after blank line)
            if let Some(pos) = raw.find("\r\n\r\n") {
                let body = raw[pos + 4..].to_string();
                *captured_body_clone.lock().await = body;
            }
            let create_body = r#"{"id":"esc-006","status":"pending"}"#;
            send_json(&mut stream, create_body).await;
            drop(stream);

            // Handle poll
            let (mut stream, _) = listener.accept().await.unwrap();
            let _req = read_http_request(&mut stream).await;
            send_json(&mut stream, r#"{"id":"esc-006","status":"approved"}"#).await;
        });

        let base_url = format!("http://127.0.0.1:{}", port);
        let backend = ShieldApprovalBackend::with_poll_interval(
            &base_url,
            "kvlar_sk_test",
            Duration::from_secs(30),
            Duration::from_millis(50),
        );

        let req = ApprovalRequest::new(
            "delete_database",
            serde_json::json!({"db": "production"}),
            "approve-delete",
            "Database deletion requires approval",
            "agent-007",
        );

        let _ = backend.request_approval(&req).await.unwrap();

        // Verify the request body
        let body = captured_body.lock().await.clone();
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["actionType"], "tool_call");
        assert_eq!(parsed["resource"], "delete_database");
        assert_eq!(parsed["ruleMatched"], "approve-delete");
        assert_eq!(parsed["reason"], "Database deletion requires approval");
        assert!(parsed["parameters"]["db"] == "production");
        assert!(parsed["timeoutSeconds"].is_number());
    }

    // ── proxy integration tests ───────────────────────────────────────────────
    //
    // These tests exercise the full chain: proxy loop → ShieldApprovalBackend
    // → mock SHIELD API → proxy output.

    use crate::handler::run_proxy_loop;
    use kvlar_audit::AuditLogger;
    use kvlar_core::Engine;
    use std::io::Cursor;
    use tokio::io::BufReader;
    use tokio::sync::{Mutex, RwLock};

    fn engine_with_approve_policy() -> Engine {
        let mut engine = Engine::new();
        engine
            .load_policy_yaml(
                r#"
name: test-approve
description: Require approval for email sends
version: "1"
rules:
  - id: approve-email
    description: Require approval for email
    match_on:
      resources: ["send_email"]
    effect:
      type: require_approval
      reason: "Email requires human approval"
  - id: allow-rest
    description: Allow everything else
    match_on:
      resources: ["*"]
    effect:
      type: allow
"#,
            )
            .unwrap();
        engine
    }

    async fn run_proxy_with_shield_backend(
        client_input: &str,
        base_url: &str,
    ) -> (Vec<u8>, Vec<u8>) {
        let client_reader = BufReader::new(Cursor::new(client_input.as_bytes().to_vec()));
        let client_output = Arc::new(Mutex::new(Vec::<u8>::new()));
        let upstream_reader = BufReader::new(Cursor::new(Vec::<u8>::new()));
        let upstream_output = Arc::new(Mutex::new(Vec::<u8>::new()));

        let backend = Arc::new(ShieldApprovalBackend::with_poll_interval(
            base_url,
            "kvlar_sk_test",
            Duration::from_secs(30),
            Duration::from_millis(50),
        ));

        run_proxy_loop(
            client_reader,
            client_output.clone(),
            upstream_reader,
            upstream_output.clone(),
            Arc::new(RwLock::new(engine_with_approve_policy())),
            Arc::new(Mutex::new(AuditLogger::default())),
            false,
            Some(backend),
        )
        .await
        .unwrap();

        let client_out = client_output.lock().await.clone();
        let upstream_out = upstream_output.lock().await.clone();
        (client_out, upstream_out)
    }

    #[tokio::test]
    async fn test_proxy_requires_approval_and_shield_approves_forwards_to_upstream() {
        let base_url = spawn_mock_shield("prx-001", "approved", None).await;

        let msg = r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"send_email","arguments":{"to":"user@example.com"}}}"#;
        let client_input = format!("{}\n", msg);

        let (client_out, upstream_out) =
            run_proxy_with_shield_backend(&client_input, &base_url).await;

        // Approved: tool call should be forwarded to upstream
        let upstream_str = String::from_utf8(upstream_out).unwrap();
        assert!(
            upstream_str.contains("send_email"),
            "approved tool call should be forwarded to upstream; upstream got: {:?}",
            upstream_str
        );

        // No denial in client output
        let client_str = String::from_utf8(client_out).unwrap();
        assert!(
            !client_str.contains("BLOCKED"),
            "approved tool call should not produce a deny response; client got: {:?}",
            client_str
        );
    }

    #[tokio::test]
    async fn test_proxy_requires_approval_and_shield_denies_returns_error_to_agent() {
        let base_url = spawn_mock_shield("prx-002", "denied", Some("Too sensitive")).await;

        let msg = r#"{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"send_email","arguments":{"to":"user@example.com"}}}"#;
        let client_input = format!("{}\n", msg);

        let (client_out, upstream_out) =
            run_proxy_with_shield_backend(&client_input, &base_url).await;

        // Denied: should NOT be forwarded to upstream
        let upstream_str = String::from_utf8(upstream_out).unwrap();
        assert!(
            upstream_str.is_empty(),
            "denied tool call should not be forwarded to upstream; upstream got: {:?}",
            upstream_str
        );

        // Client should receive a JSON-RPC deny response with the denial reason
        let client_str = String::from_utf8(client_out).unwrap();
        assert!(
            client_str.contains("BLOCKED BY KVLAR") || client_str.contains("Too sensitive"),
            "client should receive deny response with reason; client got: {:?}",
            client_str
        );

        // The response must be valid JSON-RPC with the correct request ID
        let resp: serde_json::Value = serde_json::from_str(client_str.trim()).unwrap();
        assert_eq!(
            resp["id"], 11,
            "response must carry the original request ID"
        );
        assert_eq!(
            resp["result"]["isError"], true,
            "isError must be true for denied tool calls"
        );
    }

    #[tokio::test]
    async fn test_proxy_requires_approval_timeout_treated_as_deny() {
        // A server that always returns pending
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let _req = read_http_request(&mut stream).await;
                // Always return pending (both POST create and GET poll)
                send_json(&mut stream, r#"{"id":"prx-timeout","status":"pending"}"#).await;
            }
        });

        let base_url = format!("http://127.0.0.1:{}", port);

        let client_reader = BufReader::new(Cursor::new(
            b"{\"jsonrpc\":\"2.0\",\"id\":12,\"method\":\"tools/call\",\"params\":{\"name\":\"send_email\",\"arguments\":{\"to\":\"user@example.com\"}}}\n".to_vec(),
        ));
        let client_output = Arc::new(Mutex::new(Vec::<u8>::new()));
        let upstream_reader = BufReader::new(Cursor::new(Vec::<u8>::new()));
        let upstream_output = Arc::new(Mutex::new(Vec::<u8>::new()));

        // Very short timeout: 200ms, poll every 50ms
        let backend = Arc::new(ShieldApprovalBackend::with_poll_interval(
            &base_url,
            "kvlar_sk_test",
            Duration::from_millis(200),
            Duration::from_millis(50),
        ));

        run_proxy_loop(
            client_reader,
            client_output.clone(),
            upstream_reader,
            upstream_output.clone(),
            Arc::new(RwLock::new(engine_with_approve_policy())),
            Arc::new(Mutex::new(AuditLogger::default())),
            false,
            Some(backend),
        )
        .await
        .unwrap();

        let client_out = client_output.lock().await.clone();
        let upstream_out = upstream_output.lock().await.clone();

        // Timed-out escalation: must NOT be forwarded to upstream
        let upstream_str = String::from_utf8(upstream_out).unwrap();
        assert!(
            upstream_str.is_empty(),
            "timed-out tool call should not be forwarded; upstream got: {:?}",
            upstream_str
        );

        // Client must receive a denial / approval-required response
        let client_str = String::from_utf8(client_out).unwrap();
        assert!(
            !client_str.is_empty(),
            "client must receive a response for timed-out escalation"
        );
        // Response must be valid JSON-RPC
        let resp: serde_json::Value = serde_json::from_str(client_str.trim()).unwrap();
        assert_eq!(resp["id"], 12);
        assert_eq!(resp["result"]["isError"], true);
    }

    // Verify polling interval constant
    #[test]
    fn test_default_poll_interval_is_5_seconds() {
        assert_eq!(DEFAULT_POLL_INTERVAL, Duration::from_secs(5));
    }

    #[test]
    fn test_default_timeout_is_300_seconds() {
        assert_eq!(DEFAULT_TIMEOUT, Duration::from_secs(300));
    }

    // Counter-based test to verify poll count
    #[tokio::test]
    async fn test_proxy_polls_at_least_twice_before_resolving() {
        let poll_count = Arc::new(AtomicUsize::new(0));
        let poll_count_clone = poll_count.clone();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            // Create
            let (mut stream, _) = listener.accept().await.unwrap();
            let _req = read_http_request(&mut stream).await;
            send_json(&mut stream, r#"{"id":"esc-count","status":"pending"}"#).await;
            drop(stream);

            // First poll: pending
            let (mut stream, _) = listener.accept().await.unwrap();
            let _req = read_http_request(&mut stream).await;
            poll_count_clone.fetch_add(1, Ordering::SeqCst);
            send_json(&mut stream, r#"{"id":"esc-count","status":"pending"}"#).await;
            drop(stream);

            // Second poll: pending
            let (mut stream, _) = listener.accept().await.unwrap();
            let _req = read_http_request(&mut stream).await;
            poll_count_clone.fetch_add(1, Ordering::SeqCst);
            send_json(&mut stream, r#"{"id":"esc-count","status":"pending"}"#).await;
            drop(stream);

            // Third poll: approved
            let (mut stream, _) = listener.accept().await.unwrap();
            let _req = read_http_request(&mut stream).await;
            poll_count_clone.fetch_add(1, Ordering::SeqCst);
            send_json(&mut stream, r#"{"id":"esc-count","status":"approved"}"#).await;
            drop(stream);
        });

        let base_url = format!("http://127.0.0.1:{}", port);
        let backend = ShieldApprovalBackend::with_poll_interval(
            &base_url,
            "kvlar_sk_test",
            Duration::from_secs(30),
            Duration::from_millis(50),
        );

        let req = sample_request();
        let result = backend.request_approval(&req).await.unwrap();

        assert!(matches!(result, ApprovalResponse::Approved));
        assert_eq!(
            poll_count.load(Ordering::SeqCst),
            3,
            "should have polled exactly 3 times before approval"
        );
    }
}
