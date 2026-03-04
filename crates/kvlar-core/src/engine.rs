//! Policy evaluation engine — the heart of Kvlar.
//!
//! The [`Engine`] takes an [`Action`] and evaluates it against loaded
//! [`Policy`] rules to produce a [`Decision`].

use regex::Regex;

use crate::action::Action;
use crate::decision::Decision;
use crate::error::KvlarError;
use crate::policy::{Condition, ConditionOperator, Effect, MatchCriteria, Policy, Rule};

/// Characters that indicate a glob pattern (not a plain string).
const GLOB_META_CHARS: &[char] = &['*', '?', '['];

/// Returns true if `value` matches `pattern`, where `pattern` may be:
/// - A plain string (exact match, no regex overhead)
/// - A glob pattern using `*`, `?`, or `[abc]` character classes
fn glob_matches(pattern: &str, value: &str) -> bool {
    if !pattern.contains(GLOB_META_CHARS) {
        return pattern == value;
    }
    match glob_to_regex(pattern) {
        Some(re) => re.is_match(value),
        None => pattern == value,
    }
}

/// Converts a glob pattern to a compiled regex.
/// Returns None if the resulting regex is invalid.
fn glob_to_regex(pattern: &str) -> Option<Regex> {
    let mut regex_str = String::with_capacity(pattern.len() + 4);
    regex_str.push('^');

    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '*' => regex_str.push_str(".*"),
            '?' => regex_str.push('.'),
            '[' => {
                regex_str.push('[');
                if chars.peek() == Some(&'!') {
                    chars.next();
                    regex_str.push('^');
                }
                let mut found_close = false;
                for inner in chars.by_ref() {
                    regex_str.push(inner);
                    if inner == ']' {
                        found_close = true;
                        break;
                    }
                }
                if !found_close {
                    return None;
                }
            }
            '.' | '+' | '^' | '$' | '|' | '\\' | '(' | ')' | '{' | '}' => {
                regex_str.push('\\');
                regex_str.push(c);
            }
            _ => regex_str.push(c),
        }
    }

    regex_str.push('$');
    Regex::new(&regex_str).ok()
}

/// Returns true if any pattern in `patterns` matches `value`.
fn any_pattern_matches(patterns: &[String], value: &str) -> bool {
    patterns.iter().any(|p| glob_matches(p, value))
}

/// The policy evaluation engine.
///
/// Loads one or more policies and evaluates incoming actions against them.
/// Rules are evaluated in order; the first matching rule determines the outcome.
/// If no rule matches, the default is to **deny** (fail-closed).
#[derive(Debug, Clone)]
pub struct Engine {
    policies: Vec<Policy>,
}

impl Engine {
    /// Creates a new engine with no policies loaded.
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    /// Loads a policy into the engine.
    pub fn load_policy(&mut self, policy: Policy) {
        self.policies.push(policy);
    }

    /// Loads a policy from a YAML string.
    pub fn load_policy_yaml(&mut self, yaml: &str) -> Result<(), KvlarError> {
        let policy = Policy::from_yaml(yaml)?;
        self.load_policy(policy);
        Ok(())
    }

    /// Returns the number of loaded policies.
    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }

    /// Returns the total number of rules across all loaded policies.
    pub fn rule_count(&self) -> usize {
        self.policies.iter().map(|p| p.rules.len()).sum()
    }

    /// Evaluates an action against all loaded policies.
    ///
    /// Rules are checked in order across policies (first policy's rules first).
    /// The first matching rule determines the decision. If no rule matches,
    /// the action is **denied** (fail-closed security model).
    pub fn evaluate(&self, action: &Action) -> Decision {
        for policy in &self.policies {
            for rule in &policy.rules {
                if self.matches_rule(action, rule) {
                    return self.rule_to_decision(rule);
                }
            }
        }

        // Default: deny (fail-closed)
        Decision::Deny {
            reason: "no matching policy rule — denied by default (fail-closed)".into(),
            matched_rule: "_default_deny".into(),
        }
    }

    /// Checks whether an action matches a rule's criteria.
    fn matches_rule(&self, action: &Action, rule: &Rule) -> bool {
        self.matches_criteria(action, &rule.match_on)
    }

    /// Checks whether an action matches the given criteria.
    fn matches_criteria(&self, action: &Action, criteria: &MatchCriteria) -> bool {
        // Action types: empty = match all, supports glob patterns
        if !criteria.action_types.is_empty()
            && !any_pattern_matches(&criteria.action_types, &action.action_type)
        {
            return false;
        }

        // Resources: empty = match all, supports glob patterns
        if !criteria.resources.is_empty()
            && !any_pattern_matches(&criteria.resources, &action.resource)
        {
            return false;
        }

        // Agent IDs: empty = match all, supports glob patterns
        if !criteria.agent_ids.is_empty()
            && !any_pattern_matches(&criteria.agent_ids, &action.agent_id)
        {
            return false;
        }

        // Parameter patterns: each specified pattern must match
        for (key, pattern) in &criteria.parameters {
            match action.parameters.get(key) {
                Some(value) => {
                    let value_str = match value {
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    match Regex::new(pattern) {
                        Ok(re) => {
                            if !re.is_match(&value_str) {
                                return false;
                            }
                        }
                        Err(_) => return false, // Invalid regex = no match
                    }
                }
                None => return false, // Parameter not present = no match
            }
        }

        // Conditions: each condition must be satisfied
        for condition in &criteria.conditions {
            if !self.evaluate_condition(action, condition) {
                return false;
            }
        }

        true
    }

    /// Evaluates a single condition against an action.
    fn evaluate_condition(&self, action: &Action, condition: &Condition) -> bool {
        let field_value = self.resolve_field(action, &condition.field);

        match &condition.operator {
            ConditionOperator::Exists => field_value.is_some(),
            ConditionOperator::NotExists => field_value.is_none(),
            _ => {
                let Some(field_val) = field_value else {
                    return false;
                };
                self.compare_values(&field_val, &condition.operator, &condition.value)
            }
        }
    }

    /// Resolves a field reference from an action.
    /// Supports dot-notation for nested parameter access (e.g., "args.path").
    fn resolve_field(&self, action: &Action, field: &str) -> Option<serde_json::Value> {
        // Check direct parameter first
        if let Some(value) = action.parameters.get(field) {
            return Some(value.clone());
        }

        // Try dot-notation: split on first dot
        let parts: Vec<&str> = field.splitn(2, '.').collect();
        if parts.len() == 2
            && let Some(parent) = action.parameters.get(parts[0])
        {
            return Self::resolve_nested(parent, parts[1]);
        }

        None
    }

    /// Resolves a nested field using dot notation.
    fn resolve_nested(value: &serde_json::Value, path: &str) -> Option<serde_json::Value> {
        let parts: Vec<&str> = path.splitn(2, '.').collect();
        match value.get(parts[0]) {
            Some(child) => {
                if parts.len() == 1 {
                    Some(child.clone())
                } else {
                    Self::resolve_nested(child, parts[1])
                }
            }
            None => None,
        }
    }

    /// Compares a field value against a condition value using the given operator.
    fn compare_values(
        &self,
        field_val: &serde_json::Value,
        operator: &ConditionOperator,
        cond_val: &serde_json::Value,
    ) -> bool {
        match operator {
            ConditionOperator::Equals => field_val == cond_val,
            ConditionOperator::NotEquals => field_val != cond_val,
            ConditionOperator::Contains => {
                let field_str = field_val.as_str().unwrap_or("");
                let cond_str = cond_val.as_str().unwrap_or("");
                field_str.contains(cond_str)
            }
            ConditionOperator::StartsWith => {
                let field_str = field_val.as_str().unwrap_or("");
                let cond_str = cond_val.as_str().unwrap_or("");
                field_str.starts_with(cond_str)
            }
            ConditionOperator::EndsWith => {
                let field_str = field_val.as_str().unwrap_or("");
                let cond_str = cond_val.as_str().unwrap_or("");
                field_str.ends_with(cond_str)
            }
            ConditionOperator::GreaterThan => {
                let a = field_val.as_f64();
                let b = cond_val.as_f64();
                matches!((a, b), (Some(a), Some(b)) if a > b)
            }
            ConditionOperator::LessThan => {
                let a = field_val.as_f64();
                let b = cond_val.as_f64();
                matches!((a, b), (Some(a), Some(b)) if a < b)
            }
            ConditionOperator::OneOf => {
                if let Some(arr) = cond_val.as_array() {
                    arr.contains(field_val)
                } else {
                    false
                }
            }
            ConditionOperator::Exists | ConditionOperator::NotExists => {
                unreachable!("handled above")
            }
        }
    }

    /// Converts a matched rule into a Decision.
    fn rule_to_decision(&self, rule: &Rule) -> Decision {
        match &rule.effect {
            Effect::Allow => Decision::Allow {
                matched_rule: rule.id.clone(),
            },
            Effect::Deny { reason } => Decision::Deny {
                reason: reason.clone(),
                matched_rule: rule.id.clone(),
            },
            Effect::RequireApproval { reason } => Decision::RequireApproval {
                reason: reason.clone(),
                matched_rule: rule.id.clone(),
            },
        }
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::Action;

    fn test_policy_yaml() -> &'static str {
        r#"
name: test-policy
description: Policy for unit tests
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

  - id: approve-email
    description: Require approval for sending emails
    match_on:
      action_types: ["tool_call"]
      resources: ["send_email"]
    effect:
      type: require_approval
      reason: "Email sending requires human approval"

  - id: allow-read
    description: Allow file reads
    match_on:
      action_types: ["tool_call"]
      resources: ["read_file"]
    effect:
      type: allow

  - id: deny-rm-rf
    description: Deny destructive rm commands
    match_on:
      action_types: ["tool_call"]
      resources: ["bash"]
      parameters:
        command: "rm\\s+(-rf|--force)"
    effect:
      type: deny
      reason: "Destructive rm commands are prohibited"
"#
    }

    #[test]
    fn test_engine_default_deny() {
        let engine = Engine::new();
        let action = Action::new("tool_call", "bash", "agent-1");
        let decision = engine.evaluate(&action);
        assert!(decision.is_denied());
    }

    #[test]
    fn test_engine_deny_bash() {
        let mut engine = Engine::new();
        engine.load_policy_yaml(test_policy_yaml()).unwrap();

        let action = Action::new("tool_call", "bash", "agent-1");
        let decision = engine.evaluate(&action);

        assert!(decision.is_denied());
        if let Decision::Deny { matched_rule, .. } = &decision {
            assert_eq!(matched_rule, "deny-bash");
        }
    }

    #[test]
    fn test_engine_require_approval_email() {
        let mut engine = Engine::new();
        engine.load_policy_yaml(test_policy_yaml()).unwrap();

        let action = Action::new("tool_call", "send_email", "agent-1");
        let decision = engine.evaluate(&action);

        assert!(decision.requires_approval());
        if let Decision::RequireApproval { matched_rule, .. } = &decision {
            assert_eq!(matched_rule, "approve-email");
        }
    }

    #[test]
    fn test_engine_allow_read() {
        let mut engine = Engine::new();
        engine.load_policy_yaml(test_policy_yaml()).unwrap();

        let action = Action::new("tool_call", "read_file", "agent-1");
        let decision = engine.evaluate(&action);

        assert!(decision.is_allowed());
        if let Decision::Allow { matched_rule } = &decision {
            assert_eq!(matched_rule, "allow-read");
        }
    }

    #[test]
    fn test_engine_unmatched_action_denied() {
        let mut engine = Engine::new();
        engine.load_policy_yaml(test_policy_yaml()).unwrap();

        let action = Action::new("data_access", "database", "agent-1");
        let decision = engine.evaluate(&action);

        assert!(decision.is_denied());
        if let Decision::Deny { matched_rule, .. } = &decision {
            assert_eq!(matched_rule, "_default_deny");
        }
    }

    #[test]
    fn test_engine_parameter_matching() {
        let mut engine = Engine::new();
        engine.load_policy_yaml(test_policy_yaml()).unwrap();

        // This matches deny-bash (first rule) before deny-rm-rf
        let action = Action::new("tool_call", "bash", "agent-1")
            .with_param("command", serde_json::Value::String("rm -rf /".into()));
        let decision = engine.evaluate(&action);
        assert!(decision.is_denied());
    }

    #[test]
    fn test_engine_policy_count() {
        let mut engine = Engine::new();
        assert_eq!(engine.policy_count(), 0);
        assert_eq!(engine.rule_count(), 0);

        engine.load_policy_yaml(test_policy_yaml()).unwrap();
        assert_eq!(engine.policy_count(), 1);
        assert_eq!(engine.rule_count(), 4);
    }

    #[test]
    fn test_engine_multiple_policies() {
        let mut engine = Engine::new();

        // First policy: deny bash
        engine
            .load_policy_yaml(
                r#"
name: policy-1
description: First policy
version: "1.0"
rules:
  - id: deny-bash
    description: Deny bash
    match_on:
      resources: ["bash"]
    effect:
      type: deny
      reason: "No bash"
"#,
            )
            .unwrap();

        // Second policy: allow everything
        engine
            .load_policy_yaml(
                r#"
name: policy-2
description: Second policy
version: "1.0"
rules:
  - id: allow-all
    description: Allow everything
    match_on: {}
    effect:
      type: allow
"#,
            )
            .unwrap();

        assert_eq!(engine.policy_count(), 2);

        // Bash should be denied (first policy matches first)
        let bash_action = Action::new("tool_call", "bash", "agent-1");
        assert!(engine.evaluate(&bash_action).is_denied());

        // Other actions should be allowed by second policy
        let read_action = Action::new("tool_call", "read_file", "agent-1");
        assert!(engine.evaluate(&read_action).is_allowed());
    }

    #[test]
    fn test_condition_equals() {
        let mut engine = Engine::new();
        engine
            .load_policy_yaml(
                r#"
name: cond-test
description: Condition test
version: "1"
rules:
  - id: deny-sensitive-path
    description: Deny access to /etc/passwd
    match_on:
      resources: ["read_file"]
      conditions:
        - field: path
          operator: equals
          value: "/etc/passwd"
    effect:
      type: deny
      reason: "Sensitive file"
  - id: allow-all
    description: Allow everything else
    match_on: {}
    effect:
      type: allow
"#,
            )
            .unwrap();

        // Should be denied
        let action = Action::new("tool_call", "read_file", "agent-1")
            .with_param("path", serde_json::json!("/etc/passwd"));
        assert!(engine.evaluate(&action).is_denied());

        // Should be allowed — different path
        let action2 = Action::new("tool_call", "read_file", "agent-1")
            .with_param("path", serde_json::json!("/tmp/safe.txt"));
        assert!(engine.evaluate(&action2).is_allowed());
    }

    #[test]
    fn test_condition_contains() {
        let mut engine = Engine::new();
        engine
            .load_policy_yaml(
                r#"
name: cond-contains
description: test
version: "1"
rules:
  - id: deny-secret
    description: Deny commands containing 'secret'
    match_on:
      conditions:
        - field: command
          operator: contains
          value: "secret"
    effect:
      type: deny
      reason: "Contains secret"
  - id: allow-all
    description: allow
    match_on: {}
    effect:
      type: allow
"#,
            )
            .unwrap();

        let action = Action::new("tool_call", "bash", "a")
            .with_param("command", serde_json::json!("cat /tmp/secret.txt"));
        assert!(engine.evaluate(&action).is_denied());

        let action2 = Action::new("tool_call", "bash", "a")
            .with_param("command", serde_json::json!("ls /tmp"));
        assert!(engine.evaluate(&action2).is_allowed());
    }

    #[test]
    fn test_condition_greater_than() {
        let mut engine = Engine::new();
        engine
            .load_policy_yaml(
                r#"
name: cond-gt
description: test
version: "1"
rules:
  - id: deny-large-request
    description: Deny large requests
    match_on:
      conditions:
        - field: size
          operator: greater_than
          value: 1000
    effect:
      type: deny
      reason: "Too large"
  - id: allow-all
    description: allow
    match_on: {}
    effect:
      type: allow
"#,
            )
            .unwrap();

        let action =
            Action::new("tool_call", "upload", "a").with_param("size", serde_json::json!(5000));
        assert!(engine.evaluate(&action).is_denied());

        let action2 =
            Action::new("tool_call", "upload", "a").with_param("size", serde_json::json!(500));
        assert!(engine.evaluate(&action2).is_allowed());
    }

    #[test]
    fn test_condition_exists() {
        let mut engine = Engine::new();
        engine
            .load_policy_yaml(
                r#"
name: cond-exists
description: test
version: "1"
rules:
  - id: require-token
    description: Deny if no auth token present
    match_on:
      conditions:
        - field: auth_token
          operator: not_exists
          value: null
    effect:
      type: deny
      reason: "Missing auth token"
  - id: allow-all
    description: allow
    match_on: {}
    effect:
      type: allow
"#,
            )
            .unwrap();

        // No token → denied
        let action = Action::new("tool_call", "api_call", "a");
        assert!(engine.evaluate(&action).is_denied());

        // Has token → allowed
        let action2 = Action::new("tool_call", "api_call", "a")
            .with_param("auth_token", serde_json::json!("abc123"));
        assert!(engine.evaluate(&action2).is_allowed());
    }

    #[test]
    fn test_condition_one_of() {
        let mut engine = Engine::new();
        engine
            .load_policy_yaml(
                r#"
name: cond-oneof
description: test
version: "1"
rules:
  - id: deny-unsafe-methods
    description: Deny unsafe HTTP methods
    match_on:
      conditions:
        - field: method
          operator: one_of
          value: ["DELETE", "PUT", "PATCH"]
    effect:
      type: deny
      reason: "Unsafe HTTP method"
  - id: allow-all
    description: allow
    match_on: {}
    effect:
      type: allow
"#,
            )
            .unwrap();

        let action =
            Action::new("tool_call", "http", "a").with_param("method", serde_json::json!("DELETE"));
        assert!(engine.evaluate(&action).is_denied());

        let action2 =
            Action::new("tool_call", "http", "a").with_param("method", serde_json::json!("GET"));
        assert!(engine.evaluate(&action2).is_allowed());
    }

    #[test]
    fn test_condition_nested_field() {
        let mut engine = Engine::new();
        engine
            .load_policy_yaml(
                r#"
name: cond-nested
description: test
version: "1"
rules:
  - id: deny-admin
    description: Deny admin role
    match_on:
      conditions:
        - field: user.role
          operator: equals
          value: "admin"
    effect:
      type: deny
      reason: "Admin access denied"
  - id: allow-all
    description: allow
    match_on: {}
    effect:
      type: allow
"#,
            )
            .unwrap();

        let action = Action::new("tool_call", "api", "a")
            .with_param("user", serde_json::json!({"name": "root", "role": "admin"}));
        assert!(engine.evaluate(&action).is_denied());

        let action2 = Action::new("tool_call", "api", "a")
            .with_param("user", serde_json::json!({"name": "bob", "role": "viewer"}));
        assert!(engine.evaluate(&action2).is_allowed());
    }

    // --- Glob matching tests ---

    #[test]
    fn test_glob_matches_helper() {
        // Star wildcard
        assert!(glob_matches("read_*", "read_file"));
        assert!(glob_matches("read_*", "read_"));
        assert!(!glob_matches("read_*", "write_file"));

        // Question mark
        assert!(glob_matches("?ead", "read"));
        assert!(!glob_matches("?ead", "bread"));

        // Character class
        assert!(glob_matches("[abc]_file", "a_file"));
        assert!(!glob_matches("[abc]_file", "d_file"));

        // Exact match (no metacharacters)
        assert!(glob_matches("exact", "exact"));
        assert!(!glob_matches("exact", "not_exact"));

        // Regex metachar escaping — dot is literal
        assert!(glob_matches("file.txt", "file.txt"));
        assert!(!glob_matches("file.txt", "filextxt"));
    }

    #[test]
    fn test_glob_wildcard_star() {
        let mut engine = Engine::new();
        engine
            .load_policy_yaml(
                r#"
name: glob-test
description: test
version: "1"
rules:
  - id: allow-reads
    description: Allow all read operations
    match_on:
      resources: ["read_*"]
    effect:
      type: allow
"#,
            )
            .unwrap();

        assert!(
            engine
                .evaluate(&Action::new("t", "read_file", "a"))
                .is_allowed()
        );
        assert!(
            engine
                .evaluate(&Action::new("t", "read_text_file", "a"))
                .is_allowed()
        );
        assert!(
            engine
                .evaluate(&Action::new("t", "read_media_file", "a"))
                .is_allowed()
        );

        // Should NOT match (default deny)
        assert!(
            engine
                .evaluate(&Action::new("t", "write_file", "a"))
                .is_denied()
        );
        assert!(
            engine
                .evaluate(&Action::new("t", "pre_read_file", "a"))
                .is_denied()
        );
    }

    #[test]
    fn test_glob_question_mark() {
        let mut engine = Engine::new();
        engine
            .load_policy_yaml(
                r#"
name: glob-qmark
description: test
version: "1"
rules:
  - id: deny-db-x
    description: Deny db single-char suffix
    match_on:
      resources: ["db_?"]
    effect:
      type: deny
      reason: "denied"
  - id: allow-all
    match_on: {}
    description: allow
    effect:
      type: allow
"#,
            )
            .unwrap();

        assert!(engine.evaluate(&Action::new("t", "db_x", "a")).is_denied());
        assert!(
            engine
                .evaluate(&Action::new("t", "db_xy", "a"))
                .is_allowed()
        );
    }

    #[test]
    fn test_glob_char_class() {
        let mut engine = Engine::new();
        engine
            .load_policy_yaml(
                r#"
name: glob-class
description: test
version: "1"
rules:
  - id: deny-levels
    description: Deny log levels
    match_on:
      resources: ["log_[abc]"]
    effect:
      type: deny
      reason: "denied"
  - id: allow-all
    match_on: {}
    description: allow
    effect:
      type: allow
"#,
            )
            .unwrap();

        assert!(engine.evaluate(&Action::new("t", "log_a", "a")).is_denied());
        assert!(engine.evaluate(&Action::new("t", "log_b", "a")).is_denied());
        assert!(
            engine
                .evaluate(&Action::new("t", "log_d", "a"))
                .is_allowed()
        );
    }

    #[test]
    fn test_glob_exact_match_fast_path() {
        let mut engine = Engine::new();
        engine
            .load_policy_yaml(
                r#"
name: exact
description: test
version: "1"
rules:
  - id: deny-bash
    match_on:
      resources: ["bash"]
    description: deny
    effect:
      type: deny
      reason: "no"
"#,
            )
            .unwrap();

        assert!(engine.evaluate(&Action::new("t", "bash", "a")).is_denied());
        // "basher" doesn't match "bash" exactly → default deny (still denied, different rule)
        let decision = engine.evaluate(&Action::new("t", "basher", "a"));
        assert!(decision.is_denied());
        assert_eq!(decision.matched_rule(), "_default_deny");
    }

    #[test]
    fn test_glob_on_agent_ids() {
        let mut engine = Engine::new();
        engine
            .load_policy_yaml(
                r#"
name: agent-glob
description: test
version: "1"
rules:
  - id: allow-trusted
    description: Allow trusted agents
    match_on:
      agent_ids: ["trusted-*"]
    effect:
      type: allow
"#,
            )
            .unwrap();

        assert!(
            engine
                .evaluate(&Action::new("t", "x", "trusted-agent-1"))
                .is_allowed()
        );
        assert!(
            engine
                .evaluate(&Action::new("t", "x", "trusted-bot"))
                .is_allowed()
        );
        assert!(
            engine
                .evaluate(&Action::new("t", "x", "untrusted"))
                .is_denied()
        );
    }

    #[test]
    fn test_glob_on_action_types() {
        let mut engine = Engine::new();
        engine
            .load_policy_yaml(
                r#"
name: action-glob
description: test
version: "1"
rules:
  - id: deny-file-ops
    description: Deny file operations
    match_on:
      action_types: ["file_*"]
    effect:
      type: deny
      reason: "no file ops"
  - id: allow-all
    match_on: {}
    description: allow
    effect:
      type: allow
"#,
            )
            .unwrap();

        assert!(
            engine
                .evaluate(&Action::new("file_read", "x", "a"))
                .is_denied()
        );
        assert!(
            engine
                .evaluate(&Action::new("file_write", "x", "a"))
                .is_denied()
        );
        assert!(
            engine
                .evaluate(&Action::new("tool_call", "x", "a"))
                .is_allowed()
        );
    }
}
