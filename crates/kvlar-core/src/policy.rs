//! Policy definitions — rules that govern agent behavior.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A security policy containing rules for evaluating agent actions.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Policy {
    /// Human-readable name for this policy.
    pub name: String,

    /// Description of what this policy enforces.
    pub description: String,

    /// Version of this policy (for tracking changes).
    pub version: String,

    /// The rules in this policy, evaluated in order.
    pub rules: Vec<Rule>,
}

/// A single rule within a policy.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Rule {
    /// Unique identifier for this rule.
    pub id: String,

    /// Human-readable description.
    pub description: String,

    /// What this rule matches on.
    pub match_on: MatchCriteria,

    /// What to do when this rule matches.
    pub effect: Effect,
}

/// Criteria for matching an action to a rule.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MatchCriteria {
    /// Action types to match (e.g., "tool_call"). Empty = match all.
    #[serde(default)]
    pub action_types: Vec<String>,

    /// Resources to match (e.g., "bash", "send_email"). Empty = match all.
    #[serde(default)]
    pub resources: Vec<String>,

    /// Agent IDs to match. Empty = match all agents.
    #[serde(default)]
    pub agent_ids: Vec<String>,

    /// Parameter patterns to match (key = param name, value = regex pattern).
    #[serde(default)]
    pub parameters: std::collections::HashMap<String, String>,

    /// Conditional expressions for advanced parameter matching.
    /// Each condition must be satisfied for the rule to match.
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

/// A conditional expression for matching action parameters.
///
/// Conditions allow more expressive matching than regex patterns,
/// supporting equality checks, containment, numeric comparisons, and more.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Condition {
    /// The parameter key to check (dot-notation for nested: "args.path").
    pub field: String,

    /// The comparison operator.
    pub operator: ConditionOperator,

    /// The value to compare against.
    pub value: serde_json::Value,
}

/// Comparison operators for conditions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOperator {
    /// Field equals value exactly.
    Equals,
    /// Field does not equal value.
    NotEquals,
    /// String field contains value as substring.
    Contains,
    /// String field starts with value.
    StartsWith,
    /// String field ends with value.
    EndsWith,
    /// Numeric field is greater than value.
    GreaterThan,
    /// Numeric field is less than value.
    LessThan,
    /// Field exists (value is ignored).
    Exists,
    /// Field does not exist (value is ignored).
    NotExists,
    /// String field matches one of the listed values.
    OneOf,
}

/// The effect of a matched rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Effect {
    /// Allow the action.
    Allow,
    /// Deny the action with a reason.
    Deny { reason: String },
    /// Require human approval.
    RequireApproval { reason: String },
}

impl Policy {
    /// Loads a policy from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, crate::error::KvlarError> {
        let policy: Policy = serde_yaml::from_str(yaml)?;
        Ok(policy)
    }

    /// Serializes this policy to a YAML string.
    pub fn to_yaml(&self) -> Result<String, crate::error::KvlarError> {
        let yaml = serde_yaml::to_string(self)?;
        Ok(yaml)
    }

    /// Loads a policy from a YAML file on disk.
    pub fn from_file(path: &std::path::Path) -> Result<Self, crate::error::KvlarError> {
        let yaml = std::fs::read_to_string(path).map_err(|e| {
            crate::error::KvlarError::PolicyParse(format!(
                "failed to read {}: {}",
                path.display(),
                e
            ))
        })?;
        Self::from_yaml(&yaml)
    }

    /// Loads all policies from a directory (non-recursive, *.yaml and *.yml files).
    pub fn from_dir(dir: &std::path::Path) -> Result<Vec<Self>, crate::error::KvlarError> {
        let entries = std::fs::read_dir(dir).map_err(|e| {
            crate::error::KvlarError::PolicyParse(format!(
                "failed to read directory {}: {}",
                dir.display(),
                e
            ))
        })?;

        let mut policies = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| {
                crate::error::KvlarError::PolicyParse(format!("failed to read entry: {}", e))
            })?;
            let path = entry.path();
            if path.is_file()
                && let Some(ext) = path.extension()
                && (ext == "yaml" || ext == "yml")
            {
                policies.push(Self::from_file(&path)?);
            }
        }
        Ok(policies)
    }

    /// Generates a JSON Schema for the Policy type.
    pub fn json_schema() -> schemars::schema::RootSchema {
        schemars::schema_for!(Policy)
    }

    /// Returns the JSON Schema as a pretty-printed JSON string.
    pub fn json_schema_string() -> Result<String, crate::error::KvlarError> {
        let schema = Self::json_schema();
        serde_json::to_string_pretty(&schema).map_err(crate::error::KvlarError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_from_yaml() {
        let yaml = r#"
name: test-policy
description: A test policy
version: "1.0"
rules:
  - id: deny-bash
    description: Deny all bash commands
    match_on:
      action_types: ["tool_call"]
      resources: ["bash"]
    effect:
      type: deny
      reason: "Bash commands are not allowed"
"#;
        let policy = Policy::from_yaml(yaml).unwrap();
        assert_eq!(policy.name, "test-policy");
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].id, "deny-bash");
    }

    #[test]
    fn test_policy_roundtrip() {
        let policy = Policy {
            name: "roundtrip".into(),
            description: "Test roundtrip".into(),
            version: "1.0".into(),
            rules: vec![],
        };
        let yaml = policy.to_yaml().unwrap();
        let parsed = Policy::from_yaml(&yaml).unwrap();
        assert_eq!(parsed.name, "roundtrip");
    }

    #[test]
    fn test_json_schema_generation() {
        let schema_str = Policy::json_schema_string().unwrap();
        assert!(schema_str.contains("\"Policy\""));
        assert!(schema_str.contains("\"name\""));
        assert!(schema_str.contains("\"rules\""));
        assert!(schema_str.contains("\"effect\""));

        // Verify it parses as valid JSON
        let _: serde_json::Value = serde_json::from_str(&schema_str).unwrap();
    }

    #[test]
    fn test_json_schema_has_all_types() {
        let schema = Policy::json_schema();
        let json = serde_json::to_value(&schema).unwrap();
        let defs = json.get("definitions").unwrap();
        assert!(defs.get("Effect").is_some());
        assert!(defs.get("MatchCriteria").is_some());
        assert!(defs.get("Rule").is_some());
    }

    #[test]
    fn test_policy_from_file() {
        let dir = std::env::temp_dir().join("kvlar-test-policy-file");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.yaml");
        std::fs::write(
            &path,
            r#"
name: file-policy
description: Loaded from file
version: "1.0"
rules: []
"#,
        )
        .unwrap();

        let policy = Policy::from_file(&path).unwrap();
        assert_eq!(policy.name, "file-policy");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_policy_from_dir() {
        let dir = std::env::temp_dir().join("kvlar-test-policy-dir");
        std::fs::create_dir_all(&dir).unwrap();

        std::fs::write(
            dir.join("a.yaml"),
            "name: a\ndescription: A\nversion: '1'\nrules: []\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("b.yml"),
            "name: b\ndescription: B\nversion: '1'\nrules: []\n",
        )
        .unwrap();
        std::fs::write(dir.join("c.txt"), "not a policy").unwrap();

        let policies = Policy::from_dir(&dir).unwrap();
        assert_eq!(policies.len(), 2);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_policy_from_file_not_found() {
        let result = Policy::from_file(std::path::Path::new("/nonexistent/policy.yaml"));
        assert!(result.is_err());
    }
}
