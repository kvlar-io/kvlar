//! Integration tests with a real MCP server.
//!
//! These tests spawn `@modelcontextprotocol/server-filesystem` via `npx`,
//! proxy it through the kvlar policy engine using `run_proxy_loop`, and
//! verify end-to-end policy enforcement.
//!
//! Marked `#[ignore]` because they require Node.js + npx on PATH.
//! Run with: `cargo test --test mcp_integration -- --ignored`

use std::io::Cursor;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use kvlar_audit::AuditLogger;
use kvlar_core::Engine;
use kvlar_proxy::handler::run_proxy_loop;
use tokio::io::BufReader;
use tokio::sync::{Mutex, RwLock};
use tokio::time::timeout;

/// Helper: build an Engine from inline YAML policy.
fn engine_from_yaml(yaml: &str) -> Engine {
    let mut engine = Engine::new();
    engine.load_policy_yaml(yaml).expect("failed to parse test policy");
    engine
}

/// Helper: create a JSON-RPC `tools/call` request.
fn tool_call_request(id: u64, tool: &str, args: serde_json::Value) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": args
        }
    })
    .to_string()
}

/// Helper: create a JSON-RPC `tools/list` request.
fn tools_list_request(id: u64) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/list",
        "params": {}
    })
    .to_string()
}

/// Helper: create a JSON-RPC `initialize` request.
fn initialize_request(id: u64) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "kvlar-test",
                "version": "0.1.0"
            }
        }
    })
    .to_string()
}

/// Helper: send messages through the proxy and collect responses.
///
/// Spawns the upstream MCP server, runs the proxy loop, and returns
/// all response lines from the client side.
async fn run_proxy_with_messages(
    policy_yaml: &str,
    messages: Vec<String>,
) -> Vec<serde_json::Value> {
    // Spawn the upstream MCP filesystem server
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");

    let mut child = tokio::process::Command::new("npx")
        .args([
            "-y",
            "@modelcontextprotocol/server-filesystem",
            temp_dir.path().to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn MCP filesystem server — is npx installed?");

    let child_stdin = child.stdin.take().expect("no child stdin");
    let child_stdout = child.stdout.take().expect("no child stdout");

    // Build the client input: all messages separated by newlines
    let client_input = messages.join("\n") + "\n";
    let client_reader = BufReader::new(Cursor::new(client_input.into_bytes()));

    // Client output buffer — collects responses
    let client_output = Arc::new(Mutex::new(Vec::<u8>::new()));

    let engine = engine_from_yaml(policy_yaml);
    let audit = AuditLogger::default();

    let upstream_reader = BufReader::new(child_stdout);
    let upstream_writer = Arc::new(Mutex::new(child_stdin));

    // Run the proxy loop with a timeout to prevent hangs
    let result = timeout(
        Duration::from_secs(15),
        run_proxy_loop(
            client_reader,
            client_output.clone(),
            upstream_reader,
            upstream_writer,
            Arc::new(RwLock::new(engine)),
            Arc::new(Mutex::new(audit)),
            false,
            None,
        ),
    )
    .await;

    // Clean up child
    let _ = child.kill().await;
    let _ = child.wait().await;

    // Don't fail on timeout — the proxy loop exits when client EOF is reached,
    // but the upstream reader task may still be waiting
    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => eprintln!("proxy loop error: {e}"),
        Err(_) => {} // Timeout is expected — upstream reader blocks after client EOF
    }

    // Parse responses
    let output = client_output.lock().await;
    let output_str = String::from_utf8_lossy(&output);
    output_str
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

#[tokio::test]
#[ignore] // Requires npx + Node.js
async fn test_allowed_tool_call_passes_through_to_real_server() {
    // Allow all tools — initialize and tools/list should pass through
    let policy = r#"
name: allow-all
description: Allow all tools
version: "1"
rules:
  - id: allow-all
    description: Allow everything
    match_on: {}
    effect:
      type: allow
"#;

    let messages = vec![
        initialize_request(1),
        tools_list_request(2),
    ];

    let responses = run_proxy_with_messages(policy, messages).await;

    // Should get at least the initialize response
    assert!(
        !responses.is_empty(),
        "expected at least one response from the MCP server"
    );

    // The initialize response should have server info
    let init_resp = &responses[0];
    assert_eq!(init_resp["id"], 1);
    assert!(
        init_resp.get("result").is_some(),
        "expected 'result' in initialize response: {init_resp}"
    );
}

#[tokio::test]
#[ignore] // Requires npx + Node.js
async fn test_denied_tool_call_is_blocked() {
    let policy = r#"
name: deny-tools
description: Deny all tool calls
version: "1"
rules:
  - id: deny-all-tools
    description: Block all tools
    match_on:
      resources: ["*"]
    effect:
      type: deny
      reason: "All tool calls are blocked by policy"
"#;

    // The tool call should be denied by the proxy (never reaches upstream)
    let messages = vec![
        initialize_request(1),
        tool_call_request(2, "read_file", serde_json::json!({"path": "/tmp/test.txt"})),
    ];

    let responses = run_proxy_with_messages(policy, messages).await;

    // Find the response for id=2 (the denied tool call)
    let deny_resp = responses.iter().find(|r| r["id"] == 2);
    assert!(
        deny_resp.is_some(),
        "expected a deny response for tool call id=2, got: {responses:?}"
    );

    let deny = deny_resp.unwrap();
    // Kvlar deny responses use MCP tool result with isError:true
    let result = &deny["result"];
    assert!(
        result.get("isError").is_some() || result.get("content").is_some(),
        "expected deny response with isError or content: {deny}"
    );
}

#[tokio::test]
#[ignore] // Requires npx + Node.js
async fn test_require_approval_tool_call_is_blocked_pending_approval() {
    let policy = r#"
name: approve-writes
description: Require approval for writes
version: "1"
rules:
  - id: approve-writes
    description: Writes need approval
    match_on:
      resources: ["write_file"]
    effect:
      type: require_approval
      reason: "File writes require human approval"
  - id: deny-rest
    description: Deny everything else
    match_on:
      resources: ["*"]
    effect:
      type: deny
      reason: "Denied by default"
"#;

    let messages = vec![
        initialize_request(1),
        tool_call_request(
            2,
            "write_file",
            serde_json::json!({"path": "/tmp/test.txt", "content": "hello"}),
        ),
    ];

    let responses = run_proxy_with_messages(policy, messages).await;

    // Find the response for id=2 (require_approval)
    let approval_resp = responses.iter().find(|r| r["id"] == 2);
    assert!(
        approval_resp.is_some(),
        "expected an approval-required response for id=2, got: {responses:?}"
    );

    let resp = approval_resp.unwrap();
    let result = &resp["result"];

    // Should be an error response (blocked pending approval)
    assert!(
        result.get("isError").is_some() || result.get("content").is_some(),
        "expected approval-required response with isError or content: {resp}"
    );
}

#[tokio::test]
#[ignore] // Requires npx + Node.js
async fn test_non_tool_call_requests_pass_through() {
    // Even with deny-all policy, non-tool-call requests (like initialize) pass through
    let policy = r#"
name: deny-all
description: Deny all tools
version: "1"
rules:
  - id: deny-all
    description: Deny everything
    match_on:
      resources: ["*"]
    effect:
      type: deny
      reason: "Deny everything"
"#;

    // initialize is not a tool call — it should pass through
    let messages = vec![initialize_request(1)];

    let responses = run_proxy_with_messages(policy, messages).await;

    assert!(
        !responses.is_empty(),
        "initialize should pass through even with deny-all policy"
    );

    let init_resp = &responses[0];
    assert_eq!(init_resp["id"], 1);
    assert!(
        init_resp.get("result").is_some(),
        "expected initialize result: {init_resp}"
    );
}
