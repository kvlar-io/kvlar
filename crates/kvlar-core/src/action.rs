//! Action types representing what an agent wants to do.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Represents an action an AI agent wants to perform.
///
/// Actions are the fundamental unit of evaluation. Every tool call, data access,
/// or operation an agent performs is modeled as an Action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    /// Unique identifier for this action.
    pub id: Uuid,

    /// The type of action (e.g., "tool_call", "file_read", "file_write", "network_request").
    pub action_type: String,

    /// The specific tool or resource being accessed (e.g., "bash", "read_file", "send_email").
    pub resource: String,

    /// The agent performing the action.
    pub agent_id: String,

    /// Key-value parameters of the action (e.g., command, file path, URL).
    pub parameters: HashMap<String, serde_json::Value>,

    /// When this action was requested.
    pub timestamp: DateTime<Utc>,
}

impl Action {
    /// Creates a new action with the given type, resource, and agent ID.
    pub fn new(
        action_type: impl Into<String>,
        resource: impl Into<String>,
        agent_id: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            action_type: action_type.into(),
            resource: resource.into(),
            agent_id: agent_id.into(),
            parameters: HashMap::new(),
            timestamp: Utc::now(),
        }
    }

    /// Adds a parameter to this action.
    pub fn with_param(
        mut self,
        key: impl Into<String>,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        self.parameters.insert(key.into(), value.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_creation() {
        let action = Action::new("tool_call", "bash", "agent-1");
        assert_eq!(action.action_type, "tool_call");
        assert_eq!(action.resource, "bash");
        assert_eq!(action.agent_id, "agent-1");
        assert!(action.parameters.is_empty());
    }

    #[test]
    fn test_action_with_params() {
        let action = Action::new("tool_call", "bash", "agent-1")
            .with_param("command", serde_json::Value::String("ls -la".into()));
        assert_eq!(action.parameters.len(), 1);
        assert_eq!(
            action.parameters.get("command").unwrap(),
            &serde_json::Value::String("ls -la".into())
        );
    }
}
