//! Integration tests for policy evaluation.
//!
//! Loads policies from YAML fixtures, creates actions, and verifies decisions.

use kvlar_core::{Action, Decision, Engine, Policy};

/// Helper: load policy from the fixtures directory.
fn fixture_path(name: &str) -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push(name);
    path
}

fn load_fixture_policy(name: &str) -> Policy {
    Policy::from_file(&fixture_path(name)).unwrap()
}

#[test]
fn test_default_policy_denies_bash() {
    let mut engine = Engine::new();
    engine.load_policy(load_fixture_policy("default.yaml"));

    let action = Action::new("tool_call", "bash", "test-agent");
    let decision = engine.evaluate(&action);

    assert!(decision.is_denied());
    if let Decision::Deny { matched_rule, .. } = &decision {
        assert_eq!(matched_rule, "deny-shell");
    }
}

#[test]
fn test_default_policy_allows_file_read() {
    let mut engine = Engine::new();
    engine.load_policy(load_fixture_policy("default.yaml"));

    let action = Action::new("tool_call", "read_file", "test-agent");
    assert!(engine.evaluate(&action).is_allowed());
}

#[test]
fn test_default_policy_requires_approval_for_email() {
    let mut engine = Engine::new();
    engine.load_policy(load_fixture_policy("default.yaml"));

    let action = Action::new("tool_call", "send_email", "test-agent");
    assert!(engine.evaluate(&action).requires_approval());
}

#[test]
fn test_strict_policy_denies_shell() {
    let mut engine = Engine::new();
    engine.load_policy(load_fixture_policy("strict.yaml"));

    let action = Action::new("tool_call", "bash", "test-agent");
    assert!(engine.evaluate(&action).is_denied());
}

#[test]
fn test_strict_policy_allows_reads() {
    let mut engine = Engine::new();
    engine.load_policy(load_fixture_policy("strict.yaml"));

    let action = Action::new("tool_call", "read_file", "test-agent");
    assert!(engine.evaluate(&action).is_allowed());
}

#[test]
fn test_strict_policy_requires_approval_for_writes() {
    let mut engine = Engine::new();
    engine.load_policy(load_fixture_policy("strict.yaml"));

    let action = Action::new("tool_call", "write_file", "test-agent");
    assert!(engine.evaluate(&action).requires_approval());
}

#[test]
fn test_permissive_policy_allows_most() {
    let mut engine = Engine::new();
    engine.load_policy(load_fixture_policy("permissive.yaml"));

    let action = Action::new("tool_call", "bash", "test-agent")
        .with_param("command", serde_json::json!("ls -la"));
    assert!(engine.evaluate(&action).is_allowed());

    let action2 = Action::new("tool_call", "send_email", "test-agent");
    assert!(engine.evaluate(&action2).is_allowed());
}

#[test]
fn test_multiple_policies_combined() {
    let mut engine = Engine::new();

    // Load override first, then default
    engine.load_policy(
        Policy::from_yaml(
            r#"
name: agent-override
description: Override for trusted agent
version: "1"
rules:
  - id: allow-trusted-bash
    description: Allow trusted-agent to use bash
    match_on:
      agent_ids: ["trusted-agent"]
      resources: ["bash"]
    effect:
      type: allow
"#,
        )
        .unwrap(),
    );
    engine.load_policy(load_fixture_policy("default.yaml"));

    // Trusted agent can use bash
    let trusted = Action::new("tool_call", "bash", "trusted-agent");
    assert!(engine.evaluate(&trusted).is_allowed());

    // Untrusted agent cannot
    let untrusted = Action::new("tool_call", "bash", "random-agent");
    assert!(engine.evaluate(&untrusted).is_denied());
}

#[test]
fn test_fail_closed_no_policies() {
    let engine = Engine::new();
    let action = Action::new("tool_call", "anything", "any-agent");
    assert!(engine.evaluate(&action).is_denied());
}

#[test]
fn test_json_schema_validates_policy() {
    let schema_str = Policy::json_schema_string().unwrap();
    let schema: serde_json::Value = serde_json::from_str(&schema_str).unwrap();
    assert!(schema.get("properties").is_some() || schema.get("$ref").is_some());
}

#[test]
fn test_condition_integration() {
    let mut engine = Engine::new();
    engine.load_policy(
        Policy::from_yaml(
            r#"
name: condition-integration
description: Integration test for conditions
version: "1"
rules:
  - id: deny-large-uploads
    description: Deny files larger than 10MB
    match_on:
      resources: ["upload"]
      conditions:
        - field: size_mb
          operator: greater_than
          value: 10
    effect:
      type: deny
      reason: "File too large (>10MB)"
  - id: deny-sensitive-extensions
    description: Deny sensitive file extensions
    match_on:
      resources: ["upload"]
      conditions:
        - field: filename
          operator: ends_with
          value: ".env"
    effect:
      type: deny
      reason: "Cannot upload .env files"
  - id: allow-uploads
    description: Allow other uploads
    match_on:
      resources: ["upload"]
    effect:
      type: allow
"#,
        )
        .unwrap(),
    );

    // Large file → denied
    let large = Action::new("tool_call", "upload", "agent")
        .with_param("size_mb", serde_json::json!(50))
        .with_param("filename", serde_json::json!("data.csv"));
    assert!(engine.evaluate(&large).is_denied());

    // .env file → denied
    let env_file = Action::new("tool_call", "upload", "agent")
        .with_param("size_mb", serde_json::json!(1))
        .with_param("filename", serde_json::json!("production.env"));
    assert!(engine.evaluate(&env_file).is_denied());

    // Normal file → allowed
    let normal = Action::new("tool_call", "upload", "agent")
        .with_param("size_mb", serde_json::json!(5))
        .with_param("filename", serde_json::json!("report.pdf"));
    assert!(engine.evaluate(&normal).is_allowed());
}

#[test]
fn test_audit_event_from_decision() {
    use kvlar_audit::event::{AuditEvent, EventOutcome};

    let mut engine = Engine::new();
    engine.load_policy(load_fixture_policy("default.yaml"));

    let action = Action::new("tool_call", "bash", "test-agent");
    let decision = engine.evaluate(&action);

    let (outcome, reason, matched_rule) = match &decision {
        Decision::Allow { matched_rule } => (EventOutcome::Allowed, None, matched_rule.clone()),
        Decision::Deny {
            reason,
            matched_rule,
        } => (
            EventOutcome::Denied,
            Some(reason.clone()),
            matched_rule.clone(),
        ),
        Decision::RequireApproval {
            reason,
            matched_rule,
        } => (
            EventOutcome::PendingApproval,
            Some(reason.clone()),
            matched_rule.clone(),
        ),
    };

    let mut event = AuditEvent::new(
        &action.action_type,
        &action.resource,
        &action.agent_id,
        outcome.clone(),
        &matched_rule,
    );
    if let Some(r) = reason {
        event = event.with_reason(r);
    }

    assert_eq!(event.outcome, EventOutcome::Denied);
    assert_eq!(event.matched_rule, "deny-shell");
    assert!(event.reason.is_some());
}
