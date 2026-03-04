//! Audit event types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The outcome of a policy evaluation, recorded in the audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventOutcome {
    /// The action was allowed.
    Allowed,
    /// The action was denied.
    Denied,
    /// The action requires human approval.
    PendingApproval,
}

/// A single audit event, capturing everything about a policy decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique identifier for this audit event.
    pub id: Uuid,

    /// When the event occurred.
    pub timestamp: DateTime<Utc>,

    /// The action that was evaluated.
    pub action_type: String,

    /// The resource the action targeted.
    pub resource: String,

    /// The agent that requested the action.
    pub agent_id: String,

    /// The outcome of the policy evaluation.
    pub outcome: EventOutcome,

    /// Which policy rule matched (if any).
    pub matched_rule: String,

    /// Reason for the decision (for deny/approval).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// Action parameters (for context).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<serde_json::Value>,
}

impl AuditEvent {
    /// Creates a new audit event.
    pub fn new(
        action_type: impl Into<String>,
        resource: impl Into<String>,
        agent_id: impl Into<String>,
        outcome: EventOutcome,
        matched_rule: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            action_type: action_type.into(),
            resource: resource.into(),
            agent_id: agent_id.into(),
            outcome,
            matched_rule: matched_rule.into(),
            reason: None,
            parameters: None,
        }
    }

    /// Adds a reason to this event.
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Adds parameters to this event.
    pub fn with_parameters(mut self, params: serde_json::Value) -> Self {
        self.parameters = Some(params);
        self
    }

    /// Serializes this event to a JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_creation() {
        let event = AuditEvent::new(
            "tool_call",
            "bash",
            "agent-1",
            EventOutcome::Denied,
            "deny-bash",
        )
        .with_reason("Bash commands are not allowed");

        assert_eq!(event.action_type, "tool_call");
        assert_eq!(event.resource, "bash");
        assert_eq!(event.outcome, EventOutcome::Denied);
        assert_eq!(
            event.reason.as_deref(),
            Some("Bash commands are not allowed")
        );
    }

    #[test]
    fn test_audit_event_json_roundtrip() {
        let event = AuditEvent::new(
            "tool_call",
            "read_file",
            "agent-1",
            EventOutcome::Allowed,
            "allow-read",
        );
        let json = event.to_json().unwrap();
        let parsed: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.action_type, "tool_call");
        assert_eq!(parsed.outcome, EventOutcome::Allowed);
    }
}
