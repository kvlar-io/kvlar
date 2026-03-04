//! Policy testing framework — types and runner.
//!
//! Defines test case specifications and a pure runner that evaluates
//! test cases against a loaded engine. No I/O — file loading happens
//! in kvlar-cli.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::action::Action;
use crate::engine::Engine;

/// A complete test suite: policy reference + test cases.
/// The `policy` field is a path hint for the CLI; the core runner ignores it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestSuite {
    /// Path to the policy file (resolved by CLI, not by core).
    #[serde(default)]
    pub policy: Option<String>,
    /// The test cases.
    pub tests: Vec<TestCase>,
}

/// A single test case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    /// Unique identifier for this test case.
    pub id: String,
    /// Optional human-readable description.
    #[serde(default)]
    pub description: Option<String>,
    /// The action to evaluate.
    pub action: TestAction,
    /// The expected decision type: "allow", "deny", or "require_approval".
    pub expect: String,
    /// Optionally assert which rule matched.
    #[serde(default)]
    pub rule: Option<String>,
    /// Optionally assert that the reason contains this substring.
    #[serde(default)]
    pub reason_contains: Option<String>,
}

/// Action specification for a test case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestAction {
    /// Action type (defaults to "tool_call" if omitted).
    #[serde(default = "default_action_type")]
    pub action_type: String,
    /// The resource / tool name being accessed.
    pub resource: String,
    /// Agent ID (defaults to "test-agent" if omitted).
    #[serde(default = "default_agent_id")]
    pub agent_id: String,
    /// Parameters (key-value map, values are JSON).
    #[serde(default)]
    pub parameters: HashMap<String, serde_json::Value>,
}

fn default_action_type() -> String {
    "tool_call".into()
}
fn default_agent_id() -> String {
    "test-agent".into()
}

/// Result of running a single test case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    /// The test case ID.
    pub id: String,
    /// Whether it passed.
    pub passed: bool,
    /// The actual decision type.
    pub actual_decision: String,
    /// The actual matched rule.
    pub actual_rule: String,
    /// The actual reason (if any).
    pub actual_reason: Option<String>,
    /// Failure details (empty if passed).
    #[serde(default)]
    pub failures: Vec<String>,
}

/// Result of running an entire test suite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuiteResult {
    /// Individual test results.
    pub results: Vec<TestResult>,
    /// Total number of tests.
    pub total: usize,
    /// Number of passing tests.
    pub passed: usize,
    /// Number of failing tests.
    pub failed: usize,
}

/// Runs a test suite against a loaded engine. Pure function — no I/O.
pub fn run_test_suite(engine: &Engine, suite: &TestSuite) -> SuiteResult {
    let results: Vec<TestResult> = suite
        .tests
        .iter()
        .map(|tc| run_test_case(engine, tc))
        .collect();
    let passed = results.iter().filter(|r| r.passed).count();
    let failed = results.len() - passed;
    SuiteResult {
        total: results.len(),
        passed,
        failed,
        results,
    }
}

/// Runs a single test case against the engine. Pure function.
fn run_test_case(engine: &Engine, test_case: &TestCase) -> TestResult {
    // Build Action from TestAction
    let mut action = Action::new(
        &test_case.action.action_type,
        &test_case.action.resource,
        &test_case.action.agent_id,
    );
    for (key, value) in &test_case.action.parameters {
        action.parameters.insert(key.clone(), value.clone());
    }

    let decision = engine.evaluate(&action);
    let mut failures = Vec::new();

    // Check decision type
    let actual_type = decision.decision_type();
    if !expects_match(&test_case.expect, actual_type) {
        failures.push(format!(
            "expected decision '{}', got '{}'",
            test_case.expect, actual_type
        ));
    }

    // Check matched rule
    if let Some(expected_rule) = &test_case.rule
        && decision.matched_rule() != expected_rule
    {
        failures.push(format!(
            "expected rule '{}', got '{}'",
            expected_rule,
            decision.matched_rule()
        ));
    }

    // Check reason contains
    if let Some(expected_substr) = &test_case.reason_contains {
        match decision.reason() {
            Some(reason) if reason.contains(expected_substr.as_str()) => {}
            Some(reason) => {
                failures.push(format!(
                    "expected reason to contain '{}', got '{}'",
                    expected_substr, reason
                ));
            }
            None => {
                failures.push(format!(
                    "expected reason containing '{}', but decision has no reason",
                    expected_substr
                ));
            }
        }
    }

    TestResult {
        id: test_case.id.clone(),
        passed: failures.is_empty(),
        actual_decision: actual_type.to_string(),
        actual_rule: decision.matched_rule().to_string(),
        actual_reason: decision.reason().map(|s| s.to_string()),
        failures,
    }
}

/// Compare expected decision string against actual decision type.
/// Accepts common aliases: "approval" and "requireapproval" for "require_approval".
fn expects_match(expected: &str, actual: &str) -> bool {
    match expected.trim().to_lowercase().as_str() {
        "allow" => actual == "allow",
        "deny" => actual == "deny",
        "require_approval" | "requireapproval" | "approval" => actual == "require_approval",
        _ => expected.trim().to_lowercase() == actual,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine() -> Engine {
        let mut engine = Engine::new();
        engine
            .load_policy_yaml(
                r#"
name: test-policy
description: test
version: "1"
rules:
  - id: deny-bash
    description: Deny bash
    match_on:
      resources: ["bash"]
    effect:
      type: deny
      reason: "No bash allowed"
  - id: approve-email
    description: Require approval for email
    match_on:
      resources: ["send_email"]
    effect:
      type: require_approval
      reason: "Email requires approval"
  - id: allow-read
    description: Allow read
    match_on:
      resources: ["read_file"]
    effect:
      type: allow
"#,
            )
            .unwrap();
        engine
    }

    #[test]
    fn test_passing_suite() {
        let engine = test_engine();
        let suite = TestSuite {
            policy: None,
            tests: vec![
                TestCase {
                    id: "test-deny".into(),
                    description: None,
                    action: TestAction {
                        action_type: "tool_call".into(),
                        resource: "bash".into(),
                        agent_id: "test-agent".into(),
                        parameters: HashMap::new(),
                    },
                    expect: "deny".into(),
                    rule: Some("deny-bash".into()),
                    reason_contains: Some("bash".into()),
                },
                TestCase {
                    id: "test-allow".into(),
                    description: None,
                    action: TestAction {
                        action_type: "tool_call".into(),
                        resource: "read_file".into(),
                        agent_id: "test-agent".into(),
                        parameters: HashMap::new(),
                    },
                    expect: "allow".into(),
                    rule: Some("allow-read".into()),
                    reason_contains: None,
                },
            ],
        };
        let result = run_test_suite(&engine, &suite);
        assert_eq!(result.passed, 2);
        assert_eq!(result.failed, 0);
        assert_eq!(result.total, 2);
    }

    #[test]
    fn test_failing_suite() {
        let engine = test_engine();
        let suite = TestSuite {
            policy: None,
            tests: vec![TestCase {
                id: "wrong-expect".into(),
                description: None,
                action: TestAction {
                    action_type: "tool_call".into(),
                    resource: "bash".into(),
                    agent_id: "test-agent".into(),
                    parameters: HashMap::new(),
                },
                expect: "allow".into(), // Wrong — bash is denied
                rule: None,
                reason_contains: None,
            }],
        };
        let result = run_test_suite(&engine, &suite);
        assert_eq!(result.passed, 0);
        assert_eq!(result.failed, 1);
        assert!(result.results[0].failures[0].contains("expected decision 'allow'"));
    }

    #[test]
    fn test_wrong_rule_assertion() {
        let engine = test_engine();
        let suite = TestSuite {
            policy: None,
            tests: vec![TestCase {
                id: "wrong-rule".into(),
                description: None,
                action: TestAction {
                    action_type: "tool_call".into(),
                    resource: "bash".into(),
                    agent_id: "test-agent".into(),
                    parameters: HashMap::new(),
                },
                expect: "deny".into(),
                rule: Some("wrong-rule-id".into()),
                reason_contains: None,
            }],
        };
        let result = run_test_suite(&engine, &suite);
        assert_eq!(result.failed, 1);
        assert!(result.results[0].failures[0].contains("expected rule"));
    }

    #[test]
    fn test_parameters_in_test_action() {
        let mut engine = Engine::new();
        engine
            .load_policy_yaml(
                r#"
name: param-test
description: test
version: "1"
rules:
  - id: deny-sensitive
    description: Deny sensitive paths
    match_on:
      resources: ["read_file"]
      conditions:
        - field: path
          operator: starts_with
          value: "/etc"
    effect:
      type: deny
      reason: "Sensitive path denied"
  - id: allow-all
    description: allow
    match_on: {}
    effect:
      type: allow
"#,
            )
            .unwrap();

        let suite = TestSuite {
            policy: None,
            tests: vec![TestCase {
                id: "deny-etc".into(),
                description: None,
                action: TestAction {
                    action_type: "tool_call".into(),
                    resource: "read_file".into(),
                    agent_id: "test-agent".into(),
                    parameters: {
                        let mut m = HashMap::new();
                        m.insert("path".into(), serde_json::json!("/etc/passwd"));
                        m
                    },
                },
                expect: "deny".into(),
                rule: Some("deny-sensitive".into()),
                reason_contains: Some("Sensitive".into()),
            }],
        };
        let result = run_test_suite(&engine, &suite);
        assert_eq!(result.passed, 1);
        assert_eq!(result.failed, 0);
    }

    #[test]
    fn test_yaml_deserialization() {
        let yaml = r#"
policy: "policy.yaml"
tests:
  - id: test-1
    action:
      resource: bash
    expect: deny
  - id: test-2
    description: "Read a file"
    action:
      resource: read_file
      parameters:
        path: "/tmp/test.txt"
    expect: allow
    rule: allow-read
  - id: test-3
    action:
      resource: send_email
    expect: require_approval
"#;
        let suite: TestSuite = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(suite.tests.len(), 3);
        assert_eq!(suite.policy, Some("policy.yaml".into()));
        assert_eq!(suite.tests[0].action.action_type, "tool_call"); // default
        assert_eq!(suite.tests[0].action.agent_id, "test-agent"); // default
        assert_eq!(suite.tests[1].action.parameters["path"], "/tmp/test.txt");
        assert_eq!(suite.tests[2].expect, "require_approval");
    }
}
