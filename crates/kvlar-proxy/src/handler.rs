//! Transport-agnostic proxy message handler.
//!
//! Contains the core bidirectional proxy loop that reads MCP messages,
//! evaluates tool calls against the policy engine, and forwards or blocks
//! them. This module is used by both TCP and stdio transports.

use std::sync::Arc;

use kvlar_audit::AuditLogger;
use kvlar_audit::event::{AuditEvent, EventOutcome};
use kvlar_core::{Action, ApprovalRequest, Decision, Engine};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, RwLock};

use crate::approval::ApprovalBackend;
use crate::mcp::{self, McpMessage};

/// Runs the bidirectional proxy loop.
///
/// Reads MCP JSON-RPC messages from `client_reader`, evaluates tool calls
/// against the policy engine, forwards allowed messages to `upstream_writer`,
/// and sends deny/approval responses back through `client_writer`. Server
/// responses from `upstream_reader` are forwarded back to `client_writer`.
///
/// If `approval_backend` is provided, `RequireApproval` decisions will be
/// sent to the backend for human review. If not provided, they are denied
/// by default (fail-closed).
#[allow(clippy::too_many_arguments)]
pub async fn run_proxy_loop<CR, CW, UR, UW>(
    client_reader: CR,
    client_writer: Arc<Mutex<CW>>,
    upstream_reader: UR,
    upstream_writer: Arc<Mutex<UW>>,
    engine: Arc<RwLock<Engine>>,
    audit: Arc<Mutex<AuditLogger>>,
    _fail_open: bool,
    approval_backend: Option<Arc<dyn ApprovalBackend>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    CR: AsyncBufRead + Unpin + Send + 'static,
    CW: AsyncWrite + Unpin + Send + 'static,
    UR: AsyncBufRead + Unpin + Send + 'static,
    UW: AsyncWrite + Unpin + Send + 'static,
{
    // Client → Upstream (with policy enforcement)
    let engine_clone = engine.clone();
    let audit_clone = audit.clone();
    let client_writer_clone = client_writer.clone();
    let client_to_upstream = tokio::spawn(async move {
        if let Err(e) = proxy_client_to_upstream(
            client_reader,
            client_writer_clone,
            upstream_writer,
            engine_clone,
            audit_clone,
            approval_backend,
        )
        .await
        {
            tracing::error!(error = %e, "client-to-upstream error");
        }
    });

    // Upstream → Client (pass-through)
    let upstream_to_client = tokio::spawn(async move {
        if let Err(e) = proxy_upstream_to_client(upstream_reader, client_writer).await {
            tracing::error!(error = %e, "upstream-to-client error");
        }
    });

    let _ = tokio::join!(client_to_upstream, upstream_to_client);
    Ok(())
}

/// Reads messages from the client, evaluates tool calls, and forwards or denies.
#[allow(clippy::too_many_arguments)]
async fn proxy_client_to_upstream<CR, CW, UW>(
    mut client_reader: CR,
    client_writer: Arc<Mutex<CW>>,
    upstream_writer: Arc<Mutex<UW>>,
    engine: Arc<RwLock<Engine>>,
    audit: Arc<Mutex<AuditLogger>>,
    approval_backend: Option<Arc<dyn ApprovalBackend>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    CR: AsyncBufRead + Unpin,
    CW: AsyncWrite + Unpin,
    UW: AsyncWrite + Unpin,
{
    let mut line = String::new();
    loop {
        line.clear();
        match client_reader.read_line(&mut line).await {
            Ok(0) => break, // EOF
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                match McpMessage::parse(trimmed) {
                    Ok(msg) => {
                        if let Some(req) = msg.as_request()
                            && let Some(tool_call) = req.extract_tool_call()
                        {
                            // Build action with tool arguments bridged to parameters
                            let mut action =
                                Action::new("tool_call", &tool_call.tool_name, "mcp-agent");
                            if let Some(obj) = tool_call.arguments.as_object() {
                                for (key, value) in obj {
                                    action.parameters.insert(key.clone(), value.clone());
                                }
                            }

                            // Evaluate against policy
                            let eng = engine.read().await;
                            let decision = eng.evaluate(&action);
                            drop(eng);

                            // Record audit event
                            let (outcome, reason) = match &decision {
                                Decision::Allow { .. } => (EventOutcome::Allowed, None),
                                Decision::Deny { reason, .. } => {
                                    (EventOutcome::Denied, Some(reason.clone()))
                                }
                                Decision::RequireApproval { reason, .. } => {
                                    (EventOutcome::PendingApproval, Some(reason.clone()))
                                }
                            };

                            let matched_rule = match &decision {
                                Decision::Allow { matched_rule }
                                | Decision::Deny { matched_rule, .. }
                                | Decision::RequireApproval { matched_rule, .. } => {
                                    matched_rule.clone()
                                }
                            };

                            let mut event = AuditEvent::new(
                                "tool_call",
                                &tool_call.tool_name,
                                "mcp-agent",
                                outcome,
                                &matched_rule,
                            );
                            if let Some(r) = &reason {
                                event = event.with_reason(r);
                            }
                            event = event.with_parameters(tool_call.arguments.clone());
                            let mut aud = audit.lock().await;
                            aud.record(event);
                            drop(aud);

                            // Route based on decision
                            match decision {
                                Decision::Allow { .. } => {
                                    tracing::info!(
                                        tool = %tool_call.tool_name,
                                        rule = %matched_rule,
                                        "ALLOW"
                                    );
                                    let mut writer = upstream_writer.lock().await;
                                    let _ = writer.write_all(line.as_bytes()).await;
                                    let _ = writer.flush().await;
                                }
                                Decision::Deny { reason, .. } => {
                                    tracing::warn!(
                                        tool = %tool_call.tool_name,
                                        rule = %matched_rule,
                                        reason = %reason,
                                        "DENY"
                                    );
                                    let request_id =
                                        req.id.clone().unwrap_or(serde_json::json!(null));
                                    let resp = mcp::deny_response(
                                        request_id,
                                        &reason,
                                        &tool_call.tool_name,
                                        &matched_rule,
                                    );
                                    if let Ok(json) = serde_json::to_string(&resp) {
                                        let mut writer = client_writer.lock().await;
                                        let _ = writer
                                            .write_all(format!("{}\n", json).as_bytes())
                                            .await;
                                        let _ = writer.flush().await;
                                    }
                                }
                                Decision::RequireApproval { reason, .. } => {
                                    tracing::warn!(
                                        tool = %tool_call.tool_name,
                                        rule = %matched_rule,
                                        reason = %reason,
                                        "REQUIRE_APPROVAL"
                                    );
                                    let request_id =
                                        req.id.clone().unwrap_or(serde_json::json!(null));

                                    // If an approval backend is configured, request approval
                                    if let Some(ref backend) = approval_backend {
                                        let approval_req = ApprovalRequest::new(
                                            &tool_call.tool_name,
                                            tool_call.arguments.clone(),
                                            &matched_rule,
                                            &reason,
                                            "mcp-agent",
                                        );

                                        match backend.request_approval(&approval_req).await {
                                            Ok(kvlar_core::ApprovalResponse::Approved) => {
                                                tracing::info!(
                                                    tool = %tool_call.tool_name,
                                                    rule = %matched_rule,
                                                    "APPROVED (via webhook)"
                                                );
                                                let mut writer = upstream_writer.lock().await;
                                                let _ = writer.write_all(line.as_bytes()).await;
                                                let _ = writer.flush().await;
                                                continue;
                                            }
                                            Ok(kvlar_core::ApprovalResponse::Denied {
                                                reason: deny_reason,
                                            }) => {
                                                let final_reason =
                                                    deny_reason.unwrap_or_else(|| {
                                                        "denied by human reviewer".into()
                                                    });
                                                tracing::warn!(
                                                    tool = %tool_call.tool_name,
                                                    reason = %final_reason,
                                                    "DENIED (by human reviewer)"
                                                );
                                                let resp = mcp::deny_response(
                                                    request_id,
                                                    &final_reason,
                                                    &tool_call.tool_name,
                                                    &matched_rule,
                                                );
                                                if let Ok(json) = serde_json::to_string(&resp) {
                                                    let mut writer = client_writer.lock().await;
                                                    let _ = writer
                                                        .write_all(format!("{}\n", json).as_bytes())
                                                        .await;
                                                    let _ = writer.flush().await;
                                                }
                                                continue;
                                            }
                                            Err(e) => {
                                                tracing::error!(
                                                    tool = %tool_call.tool_name,
                                                    error = %e,
                                                    "approval backend error, denying"
                                                );
                                                // Fall through to default behavior below
                                            }
                                        }
                                    }

                                    // No approval backend or backend error — send approval-required response
                                    let resp = mcp::approval_required_response(
                                        request_id,
                                        &reason,
                                        &tool_call.tool_name,
                                        &matched_rule,
                                    );
                                    if let Ok(json) = serde_json::to_string(&resp) {
                                        let mut writer = client_writer.lock().await;
                                        let _ = writer
                                            .write_all(format!("{}\n", json).as_bytes())
                                            .await;
                                        let _ = writer.flush().await;
                                    }
                                }
                            }
                            continue;
                        }
                        // Non-tool-call requests: pass through
                        let mut writer = upstream_writer.lock().await;
                        let _ = writer.write_all(line.as_bytes()).await;
                        let _ = writer.flush().await;
                    }
                    Err(e) => {
                        // Malformed JSON-RPC — send parse error back to client
                        tracing::warn!(error = %e, "malformed JSON-RPC message from client");
                        let resp = mcp::parse_error_response(&e.to_string());
                        if let Ok(json) = serde_json::to_string(&resp) {
                            let mut writer = client_writer.lock().await;
                            let _ = writer.write_all(format!("{}\n", json).as_bytes()).await;
                            let _ = writer.flush().await;
                        }
                    }
                }
            }
            Err(e) => {
                tracing::debug!(error = %e, "client read error");
                break;
            }
        }
    }
    Ok(())
}

/// Forwards all messages from upstream back to the client.
///
/// If the upstream disconnects (EOF) or errors, logs the event
/// and exits gracefully without crashing the proxy.
async fn proxy_upstream_to_client<UR, CW>(
    mut upstream_reader: UR,
    client_writer: Arc<Mutex<CW>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    UR: AsyncBufRead + Unpin,
    CW: AsyncWrite + Unpin,
{
    let mut line = String::new();
    loop {
        line.clear();
        match upstream_reader.read_line(&mut line).await {
            Ok(0) => {
                tracing::warn!("upstream server disconnected (EOF)");
                break;
            }
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let mut writer = client_writer.lock().await;
                let _ = writer.write_all(line.as_bytes()).await;
                let _ = writer.flush().await;
            }
            Err(e) => {
                tracing::error!(error = %e, "upstream read error — connection may be broken");
                break;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tokio::io::BufReader;

    /// Helper: create engine loaded with the default policy inline.
    fn engine_with_default_policy() -> Engine {
        let mut engine = Engine::new();
        engine
            .load_policy_yaml(
                r#"
name: test-default
description: Test policy
version: "1"
rules:
  - id: deny-shell
    description: Block shell execution
    match_on:
      resources: ["bash", "shell"]
    effect:
      type: deny
      reason: "Shell execution denied"
  - id: approve-email
    description: Require approval for email
    match_on:
      resources: ["send_email"]
    effect:
      type: require_approval
      reason: "Email requires approval"
  - id: allow-read
    description: Allow file reads
    match_on:
      resources: ["read_file"]
    effect:
      type: allow
"#,
            )
            .unwrap();
        engine
    }

    /// Helper: run the proxy loop with in-memory buffers and return outputs.
    async fn run_with_buffers(
        client_input: &str,
        upstream_input: &str,
        engine: Engine,
    ) -> (Vec<u8>, Vec<u8>) {
        let client_reader = BufReader::new(Cursor::new(client_input.as_bytes().to_vec()));
        let client_output = Arc::new(Mutex::new(Vec::<u8>::new()));
        let upstream_reader = BufReader::new(Cursor::new(upstream_input.as_bytes().to_vec()));
        let upstream_output = Arc::new(Mutex::new(Vec::<u8>::new()));
        let audit = AuditLogger::default();

        run_proxy_loop(
            client_reader,
            client_output.clone(),
            upstream_reader,
            upstream_output.clone(),
            Arc::new(RwLock::new(engine)),
            Arc::new(Mutex::new(audit)),
            false,
            None,
        )
        .await
        .unwrap();

        let client_out = client_output.lock().await.clone();
        let upstream_out = upstream_output.lock().await.clone();
        (client_out, upstream_out)
    }

    #[tokio::test]
    async fn test_allowed_tool_call_forwarded_to_upstream() {
        let msg = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/test.txt"}}}"#;
        let client_input = format!("{}\n", msg);

        let (client_out, upstream_out) =
            run_with_buffers(&client_input, "", engine_with_default_policy()).await;

        // Allowed tool call should be forwarded to upstream
        let upstream_str = String::from_utf8(upstream_out).unwrap();
        assert!(
            upstream_str.contains("read_file"),
            "allowed request should be forwarded to upstream"
        );

        // No deny response should be sent to client
        let client_str = String::from_utf8(client_out).unwrap();
        assert!(
            !client_str.contains("denied"),
            "allowed request should not produce a deny response"
        );
    }

    #[tokio::test]
    async fn test_denied_tool_call_blocked() {
        let msg = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"bash","arguments":{"command":"rm -rf /"}}}"#;
        let client_input = format!("{}\n", msg);

        let (client_out, upstream_out) =
            run_with_buffers(&client_input, "", engine_with_default_policy()).await;

        // Denied tool call should NOT be forwarded to upstream
        let upstream_str = String::from_utf8(upstream_out).unwrap();
        assert!(
            !upstream_str.contains("bash"),
            "denied request should not be forwarded"
        );

        // Deny response should be sent back to client as tool result with isError
        let client_str = String::from_utf8(client_out).unwrap();
        assert!(
            client_str.contains("BLOCKED BY KVLAR"),
            "client should get Kvlar deny response"
        );
        assert!(
            client_str.contains("Shell execution denied"),
            "deny response should contain the reason"
        );

        // Response should include the correct request ID and isError flag
        let resp: serde_json::Value = serde_json::from_str(client_str.trim()).unwrap();
        assert_eq!(resp["id"], 2);
        assert_eq!(resp["result"]["isError"], true);
    }

    #[tokio::test]
    async fn test_approval_required_tool_call_blocked() {
        let msg = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"send_email","arguments":{"to":"user@example.com"}}}"#;
        let client_input = format!("{}\n", msg);

        let (client_out, upstream_out) =
            run_with_buffers(&client_input, "", engine_with_default_policy()).await;

        // Should NOT be forwarded to upstream
        let upstream_str = String::from_utf8(upstream_out).unwrap();
        assert!(upstream_str.is_empty());

        // Client should get approval-required response as tool result
        let client_str = String::from_utf8(client_out).unwrap();
        assert!(client_str.contains("APPROVAL REQUIRED"));
        assert!(client_str.contains("Email requires approval"));
    }

    #[tokio::test]
    async fn test_non_tool_call_request_passthrough() {
        let msg = r#"{"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"file:///tmp/test.txt"}}"#;
        let client_input = format!("{}\n", msg);

        let (client_out, upstream_out) =
            run_with_buffers(&client_input, "", engine_with_default_policy()).await;

        // Non-tool-call should pass through to upstream
        let upstream_str = String::from_utf8(upstream_out).unwrap();
        assert!(
            upstream_str.contains("resources/read"),
            "non-tool-call requests should pass through"
        );

        // No response sent to client
        let client_str = String::from_utf8(client_out).unwrap();
        assert!(client_str.is_empty());
    }

    #[tokio::test]
    async fn test_upstream_response_forwarded_to_client() {
        let upstream_resp =
            r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hello"}]}}"#;
        let upstream_input = format!("{}\n", upstream_resp);

        let (client_out, _upstream_out) =
            run_with_buffers("", &upstream_input, engine_with_default_policy()).await;

        // Upstream response should be forwarded to client
        let client_str = String::from_utf8(client_out).unwrap();
        assert!(
            client_str.contains("hello"),
            "upstream response should be forwarded to client"
        );
    }

    #[tokio::test]
    async fn test_tool_args_bridged_to_action_parameters() {
        // Use a policy that matches on conditions (parameters)
        let mut engine = Engine::new();
        engine
            .load_policy_yaml(
                r#"
name: param-test
description: Test parameter bridging
version: "1"
rules:
  - id: deny-dangerous-path
    description: Deny access to /etc
    match_on:
      resources: ["read_file"]
      conditions:
        - field: path
          operator: starts_with
          value: "/etc"
    effect:
      type: deny
      reason: "Access to /etc is denied"
  - id: allow-read
    description: Allow other reads
    match_on:
      resources: ["read_file"]
    effect:
      type: allow
"#,
            )
            .unwrap();

        // Request with path=/etc/passwd should be DENIED
        let msg_denied = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/passwd"}}}"#;
        let (client_out, upstream_out) =
            run_with_buffers(&format!("{}\n", msg_denied), "", engine).await;
        let client_str = String::from_utf8(client_out).unwrap();
        let upstream_str = String::from_utf8(upstream_out).unwrap();
        assert!(
            client_str.contains("BLOCKED BY KVLAR"),
            "should deny /etc access"
        );
        assert!(upstream_str.is_empty(), "should not forward denied request");

        // Request with path=/tmp/file.txt should be ALLOWED
        let mut engine2 = Engine::new();
        engine2
            .load_policy_yaml(
                r#"
name: param-test
description: Test parameter bridging
version: "1"
rules:
  - id: deny-dangerous-path
    description: Deny access to /etc
    match_on:
      resources: ["read_file"]
      conditions:
        - field: path
          operator: starts_with
          value: "/etc"
    effect:
      type: deny
      reason: "Access to /etc is denied"
  - id: allow-read
    description: Allow other reads
    match_on:
      resources: ["read_file"]
    effect:
      type: allow
"#,
            )
            .unwrap();

        let msg_allowed = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/file.txt"}}}"#;
        let (_client_out2, upstream_out2) =
            run_with_buffers(&format!("{}\n", msg_allowed), "", engine2).await;
        let upstream_str2 = String::from_utf8(upstream_out2).unwrap();
        assert!(
            upstream_str2.contains("read_file"),
            "should forward allowed request"
        );
    }

    #[tokio::test]
    async fn test_default_deny_unmatched_tool() {
        let msg = r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"unknown_tool","arguments":{}}}"#;
        let client_input = format!("{}\n", msg);

        let (client_out, upstream_out) =
            run_with_buffers(&client_input, "", engine_with_default_policy()).await;

        // Unmatched tool should be DENIED (fail-closed)
        let upstream_str = String::from_utf8(upstream_out).unwrap();
        assert!(
            upstream_str.is_empty(),
            "unmatched tool should not be forwarded"
        );

        let client_str = String::from_utf8(client_out).unwrap();
        assert!(
            client_str.contains("BLOCKED BY KVLAR"),
            "unmatched tool should be denied by Kvlar"
        );
    }

    #[tokio::test]
    async fn test_audit_records_created() {
        let msg = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bash","arguments":{"command":"ls"}}}"#;
        let client_input = format!("{}\n", msg);

        let client_reader = BufReader::new(Cursor::new(client_input.as_bytes().to_vec()));
        let client_output = Arc::new(Mutex::new(Vec::<u8>::new()));
        let upstream_reader = BufReader::new(Cursor::new(Vec::<u8>::new()));
        let upstream_output = Arc::new(Mutex::new(Vec::<u8>::new()));
        let audit = Arc::new(Mutex::new(AuditLogger::default()));

        run_proxy_loop(
            client_reader,
            client_output,
            upstream_reader,
            upstream_output,
            Arc::new(RwLock::new(engine_with_default_policy())),
            audit.clone(),
            false,
            None,
        )
        .await
        .unwrap();

        let aud = audit.lock().await;
        let events = aud.events();
        assert_eq!(events.len(), 1, "should record one audit event");
        assert_eq!(events[0].resource, "bash");
        assert_eq!(events[0].outcome, kvlar_audit::event::EventOutcome::Denied);
        assert!(
            events[0].parameters.is_some(),
            "audit event should include parameters"
        );
    }
}
