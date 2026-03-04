//! MCP JSON-RPC message parsing.
//!
//! Parses Model Context Protocol messages according to the JSON-RPC 2.0
//! specification. Extracts tool call names and parameters for policy evaluation.

use serde::{Deserialize, Serialize};

/// A parsed MCP message — either a request or a response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum McpMessage {
    /// A JSON-RPC request (has a "method" field).
    Request(McpRequest),
    /// A JSON-RPC response (has a "result" or "error" field).
    Response(McpResponse),
}

/// A JSON-RPC 2.0 request from an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpRequest {
    /// JSON-RPC version — must be "2.0".
    pub jsonrpc: String,

    /// Request ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,

    /// The method being called (e.g., "tools/call", "resources/read").
    pub method: String,

    /// Request parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

/// A JSON-RPC 2.0 response from a tool server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpResponse {
    /// JSON-RPC version — must be "2.0".
    pub jsonrpc: String,

    /// Response ID (matches the request ID).
    pub id: serde_json::Value,

    /// The result (present on success).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,

    /// The error (present on failure).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<McpError>,
}

/// A JSON-RPC error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpError {
    /// Error code.
    pub code: i64,
    /// Error message.
    pub message: String,
    /// Optional additional data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// Extracted tool call parameters from an MCP `tools/call` request.
#[derive(Debug, Clone)]
pub struct ToolCallParams {
    /// The name of the tool being called.
    pub tool_name: String,
    /// The arguments passed to the tool.
    pub arguments: serde_json::Value,
}

impl McpRequest {
    /// Returns true if this is a tool call request.
    pub fn is_tool_call(&self) -> bool {
        self.method == "tools/call"
    }

    /// Extracts tool call parameters from this request.
    ///
    /// Returns `None` if this is not a `tools/call` request or if the
    /// params don't contain the expected `name` and `arguments` fields.
    pub fn extract_tool_call(&self) -> Option<ToolCallParams> {
        if !self.is_tool_call() {
            return None;
        }

        let params = self.params.as_ref()?;
        let name = params.get("name")?.as_str()?.to_string();
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

        Some(ToolCallParams {
            tool_name: name,
            arguments,
        })
    }
}

impl McpMessage {
    /// Parses a JSON string into an MCP message.
    pub fn parse(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Returns the request if this is a request message.
    pub fn as_request(&self) -> Option<&McpRequest> {
        match self {
            McpMessage::Request(req) => Some(req),
            _ => None,
        }
    }

    /// Returns the response if this is a response message.
    pub fn as_response(&self) -> Option<&McpResponse> {
        match self {
            McpMessage::Response(resp) => Some(resp),
            _ => None,
        }
    }

    /// Returns true if this message is a tool call request.
    pub fn is_tool_call(&self) -> bool {
        self.as_request().is_some_and(|r| r.is_tool_call())
    }

    /// Serializes this message back to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// Creates a JSON-RPC error response for a denied tool call.
///
/// Returns the denial as a tool result with `isError: true` so the LLM
/// receives the message as conversation content (not a transport error)
/// and can relay the policy decision to the user.
pub fn deny_response(
    request_id: serde_json::Value,
    reason: &str,
    tool_name: &str,
    rule_id: &str,
) -> McpResponse {
    let message = format!(
        "[BLOCKED BY KVLAR]\n\
         Tool: {tool_name}\n\
         Policy rule: {rule_id}\n\
         Reason: {reason}\n\n\
         This action was blocked by the Kvlar security policy. \
         Tell the user exactly what was blocked and why.",
    );
    McpResponse {
        jsonrpc: "2.0".into(),
        id: request_id,
        result: Some(serde_json::json!({
            "content": [{"type": "text", "text": message}],
            "isError": true
        })),
        error: None,
    }
}

/// Creates a JSON-RPC error response for an action requiring approval.
///
/// Returns the denial as a tool result with `isError: true` so the LLM
/// receives the message as conversation content and can inform the user.
pub fn approval_required_response(
    request_id: serde_json::Value,
    reason: &str,
    tool_name: &str,
    rule_id: &str,
) -> McpResponse {
    let message = format!(
        "[KVLAR — APPROVAL REQUIRED]\n\
         Tool: {tool_name}\n\
         Policy rule: {rule_id}\n\
         Reason: {reason}\n\n\
         This action requires explicit human approval before it can proceed. \
         Tell the user what action needs their approval and why.",
    );
    McpResponse {
        jsonrpc: "2.0".into(),
        id: request_id,
        result: Some(serde_json::json!({
            "content": [{"type": "text", "text": message}],
            "isError": true
        })),
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tool_call_request() {
        let json = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "bash",
                "arguments": {
                    "command": "ls -la"
                }
            }
        }"#;

        let msg = McpMessage::parse(json).unwrap();
        assert!(msg.is_tool_call());

        let req = msg.as_request().unwrap();
        let tool_call = req.extract_tool_call().unwrap();
        assert_eq!(tool_call.tool_name, "bash");
        assert_eq!(
            tool_call
                .arguments
                .get("command")
                .unwrap()
                .as_str()
                .unwrap(),
            "ls -la"
        );
    }

    #[test]
    fn test_parse_non_tool_call_request() {
        let json = r#"{
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/read",
            "params": {
                "uri": "file:///tmp/test.txt"
            }
        }"#;

        let msg = McpMessage::parse(json).unwrap();
        assert!(!msg.is_tool_call());

        let req = msg.as_request().unwrap();
        assert!(req.extract_tool_call().is_none());
    }

    #[test]
    fn test_parse_response() {
        let json = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [{"type": "text", "text": "hello"}]
            }
        }"#;

        let msg = McpMessage::parse(json).unwrap();
        assert!(!msg.is_tool_call());
        assert!(msg.as_response().is_some());
        assert!(msg.as_request().is_none());
    }

    #[test]
    fn test_parse_error_response() {
        let json = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32600,
                "message": "Invalid request"
            }
        }"#;

        let msg = McpMessage::parse(json).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.result.is_none());
        assert!(resp.error.is_some());
        assert_eq!(resp.error.as_ref().unwrap().code, -32600);
    }

    #[test]
    fn test_deny_response() {
        let resp = deny_response(
            serde_json::json!(42),
            "bash is not allowed",
            "bash",
            "deny-shell",
        );
        assert_eq!(resp.id, serde_json::json!(42));
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["isError"], true);
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("BLOCKED BY KVLAR"));
        assert!(text.contains("bash is not allowed"));
        assert!(text.contains("deny-shell"));
        assert!(text.contains("Tool: bash"));
    }

    #[test]
    fn test_approval_required_response() {
        let resp = approval_required_response(
            serde_json::json!(7),
            "email requires approval",
            "send_email",
            "approve-email",
        );
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["isError"], true);
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("APPROVAL REQUIRED"));
        assert!(text.contains("email requires approval"));
        assert!(text.contains("approve-email"));
    }

    #[test]
    fn test_tool_call_no_arguments() {
        let json = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "list_files"
            }
        }"#;

        let msg = McpMessage::parse(json).unwrap();
        let req = msg.as_request().unwrap();
        let tool_call = req.extract_tool_call().unwrap();
        assert_eq!(tool_call.tool_name, "list_files");
        assert!(tool_call.arguments.is_object());
    }

    #[test]
    fn test_message_roundtrip() {
        let json = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bash","arguments":{"cmd":"ls"}}}"#;
        let msg = McpMessage::parse(json).unwrap();
        let back = msg.to_json().unwrap();
        let msg2 = McpMessage::parse(&back).unwrap();
        assert!(msg2.is_tool_call());
    }
}
