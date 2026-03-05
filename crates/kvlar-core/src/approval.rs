//! Approval types for human-in-the-loop decisions.
//!
//! When a policy evaluates to `RequireApproval`, the system needs to request
//! and await a human decision. These types define the request/response contract.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A request for human approval of a blocked action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Unique identifier for this approval request.
    pub request_id: Uuid,

    /// The tool that was called.
    pub tool_name: String,

    /// The arguments passed to the tool (for context).
    pub tool_arguments: serde_json::Value,

    /// The policy rule that triggered the approval requirement.
    pub rule_id: String,

    /// Human-readable reason why approval is needed.
    pub reason: String,

    /// The agent that requested the action.
    pub agent_id: String,

    /// When this approval was requested.
    pub requested_at: DateTime<Utc>,
}

impl ApprovalRequest {
    /// Creates a new approval request.
    pub fn new(
        tool_name: impl Into<String>,
        tool_arguments: serde_json::Value,
        rule_id: impl Into<String>,
        reason: impl Into<String>,
        agent_id: impl Into<String>,
    ) -> Self {
        Self {
            request_id: Uuid::new_v4(),
            tool_name: tool_name.into(),
            tool_arguments,
            rule_id: rule_id.into(),
            reason: reason.into(),
            agent_id: agent_id.into(),
            requested_at: Utc::now(),
        }
    }
}

/// The human's decision on an approval request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum ApprovalResponse {
    /// The action is approved — forward it to the tool server.
    Approved,
    /// The action is denied by the human reviewer.
    Denied {
        /// Optional reason for the denial.
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

impl ApprovalResponse {
    /// Returns true if the action was approved.
    pub fn is_approved(&self) -> bool {
        matches!(self, ApprovalResponse::Approved)
    }

    /// Returns true if the action was denied.
    pub fn is_denied(&self) -> bool {
        matches!(self, ApprovalResponse::Denied { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_approval_request_creation() {
        let req = ApprovalRequest::new(
            "delete_file",
            serde_json::json!({"path": "/etc/passwd"}),
            "approve-file-delete",
            "File deletion requires approval",
            "agent-1",
        );
        assert_eq!(req.tool_name, "delete_file");
        assert_eq!(req.rule_id, "approve-file-delete");
        assert_eq!(req.reason, "File deletion requires approval");
        assert_eq!(req.agent_id, "agent-1");
    }

    #[test]
    fn test_approval_request_serialization() {
        let req = ApprovalRequest::new(
            "send_email",
            serde_json::json!({"to": "user@example.com"}),
            "approve-email",
            "Email requires approval",
            "agent-1",
        );
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["tool_name"], "send_email");
        assert_eq!(json["rule_id"], "approve-email");
        assert_eq!(json["reason"], "Email requires approval");
        assert!(json["request_id"].is_string());
        assert!(json["requested_at"].is_string());

        // Roundtrip
        let back: ApprovalRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back.request_id, req.request_id);
        assert_eq!(back.tool_name, req.tool_name);
    }

    #[test]
    fn test_approval_response_approved() {
        let resp = ApprovalResponse::Approved;
        assert!(resp.is_approved());
        assert!(!resp.is_denied());

        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["decision"], "approved");
    }

    #[test]
    fn test_approval_response_denied_with_reason() {
        let resp = ApprovalResponse::Denied {
            reason: Some("Too risky".into()),
        };
        assert!(!resp.is_approved());
        assert!(resp.is_denied());

        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["decision"], "denied");
        assert_eq!(json["reason"], "Too risky");
    }

    #[test]
    fn test_approval_response_denied_no_reason() {
        let resp = ApprovalResponse::Denied { reason: None };
        assert!(resp.is_denied());

        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["decision"], "denied");
        assert!(json.get("reason").is_none()); // skip_serializing_if
    }

    #[test]
    fn test_approval_response_deserialization() {
        let json = r#"{"decision": "approved"}"#;
        let resp: ApprovalResponse = serde_json::from_str(json).unwrap();
        assert!(resp.is_approved());

        let json = r#"{"decision": "denied", "reason": "Not authorized"}"#;
        let resp: ApprovalResponse = serde_json::from_str(json).unwrap();
        assert!(resp.is_denied());
        if let ApprovalResponse::Denied { reason } = &resp {
            assert_eq!(reason.as_deref(), Some("Not authorized"));
        }
    }
}
