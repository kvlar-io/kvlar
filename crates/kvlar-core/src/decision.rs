//! Decision types — the output of policy evaluation.

use serde::{Deserialize, Serialize};

/// Machine-readable error detail for denied or approval-required decisions.
///
/// Provides structured metadata that programmatic consumers can parse
/// without scraping human-readable text messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorDetail {
    /// Error code identifying the type of policy decision.
    /// Values: `"POLICY_DENY"`, `"POLICY_APPROVAL_REQUIRED"`, `"POLICY_DEFAULT_DENY"`.
    pub code: String,
    /// The decision type: `"deny"` or `"require_approval"`.
    pub decision: String,
    /// The ID of the policy rule that matched.
    pub rule_id: String,
    /// Human-readable reason for the decision.
    pub reason: String,
}

/// The result of evaluating an action against a policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    /// The action is allowed to proceed.
    Allow {
        /// Which policy rule matched to allow this action.
        matched_rule: String,
    },

    /// The action is denied.
    Deny {
        /// The reason for denial.
        reason: String,
        /// Which policy rule matched to deny this action.
        matched_rule: String,
    },

    /// The action requires human approval before proceeding.
    RequireApproval {
        /// Why approval is needed.
        reason: String,
        /// Which policy rule triggered the approval requirement.
        matched_rule: String,
    },
}

impl Decision {
    /// Returns true if this decision allows the action.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allow { .. })
    }

    /// Returns true if this decision denies the action.
    pub fn is_denied(&self) -> bool {
        matches!(self, Decision::Deny { .. })
    }

    /// Returns true if this decision requires human approval.
    pub fn requires_approval(&self) -> bool {
        matches!(self, Decision::RequireApproval { .. })
    }

    /// Returns the ID of the matched policy rule.
    pub fn matched_rule(&self) -> &str {
        match self {
            Decision::Allow { matched_rule }
            | Decision::Deny { matched_rule, .. }
            | Decision::RequireApproval { matched_rule, .. } => matched_rule,
        }
    }

    /// Returns the reason string, if any (Deny and RequireApproval have reasons).
    pub fn reason(&self) -> Option<&str> {
        match self {
            Decision::Allow { .. } => None,
            Decision::Deny { reason, .. } | Decision::RequireApproval { reason, .. } => {
                Some(reason)
            }
        }
    }

    /// Returns the decision type as a string: "allow", "deny", or "require_approval".
    pub fn decision_type(&self) -> &'static str {
        match self {
            Decision::Allow { .. } => "allow",
            Decision::Deny { .. } => "deny",
            Decision::RequireApproval { .. } => "require_approval",
        }
    }

    /// Returns structured error detail for denied or approval-required decisions.
    ///
    /// Returns `None` for allowed decisions (no error to report).
    pub fn error_detail(&self) -> Option<ErrorDetail> {
        match self {
            Decision::Allow { .. } => None,
            Decision::Deny {
                reason,
                matched_rule,
            } => {
                let code = if matched_rule == "_default_deny" {
                    "POLICY_DEFAULT_DENY"
                } else {
                    "POLICY_DENY"
                };
                Some(ErrorDetail {
                    code: code.into(),
                    decision: "deny".into(),
                    rule_id: matched_rule.clone(),
                    reason: reason.clone(),
                })
            }
            Decision::RequireApproval {
                reason,
                matched_rule,
            } => Some(ErrorDetail {
                code: "POLICY_APPROVAL_REQUIRED".into(),
                decision: "require_approval".into(),
                rule_id: matched_rule.clone(),
                reason: reason.clone(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decision_allow() {
        let decision = Decision::Allow {
            matched_rule: "default-allow".into(),
        };
        assert!(decision.is_allowed());
        assert!(!decision.is_denied());
        assert!(!decision.requires_approval());
    }

    #[test]
    fn test_decision_deny() {
        let decision = Decision::Deny {
            reason: "blocked by policy".into(),
            matched_rule: "no-file-delete".into(),
        };
        assert!(!decision.is_allowed());
        assert!(decision.is_denied());
        assert!(!decision.requires_approval());
    }

    #[test]
    fn test_decision_require_approval() {
        let decision = Decision::RequireApproval {
            reason: "sensitive operation".into(),
            matched_rule: "approve-email-send".into(),
        };
        assert!(!decision.is_allowed());
        assert!(!decision.is_denied());
        assert!(decision.requires_approval());
    }

    #[test]
    fn test_decision_accessors() {
        let allow = Decision::Allow {
            matched_rule: "allow-read".into(),
        };
        assert_eq!(allow.matched_rule(), "allow-read");
        assert_eq!(allow.reason(), None);
        assert_eq!(allow.decision_type(), "allow");

        let deny = Decision::Deny {
            reason: "not permitted".into(),
            matched_rule: "deny-shell".into(),
        };
        assert_eq!(deny.matched_rule(), "deny-shell");
        assert_eq!(deny.reason(), Some("not permitted"));
        assert_eq!(deny.decision_type(), "deny");

        let approval = Decision::RequireApproval {
            reason: "needs approval".into(),
            matched_rule: "approve-email".into(),
        };
        assert_eq!(approval.matched_rule(), "approve-email");
        assert_eq!(approval.reason(), Some("needs approval"));
        assert_eq!(approval.decision_type(), "require_approval");
    }

    #[test]
    fn test_error_detail_deny() {
        let decision = Decision::Deny {
            reason: "destructive operation".into(),
            matched_rule: "deny-drop-table".into(),
        };
        let detail = decision.error_detail().unwrap();
        assert_eq!(detail.code, "POLICY_DENY");
        assert_eq!(detail.decision, "deny");
        assert_eq!(detail.rule_id, "deny-drop-table");
        assert_eq!(detail.reason, "destructive operation");
    }

    #[test]
    fn test_error_detail_default_deny() {
        let decision = Decision::Deny {
            reason: "no matching policy rule — denied by default (fail-closed)".into(),
            matched_rule: "_default_deny".into(),
        };
        let detail = decision.error_detail().unwrap();
        assert_eq!(detail.code, "POLICY_DEFAULT_DENY");
        assert_eq!(detail.rule_id, "_default_deny");
    }

    #[test]
    fn test_error_detail_require_approval() {
        let decision = Decision::RequireApproval {
            reason: "email send needs approval".into(),
            matched_rule: "approve-email".into(),
        };
        let detail = decision.error_detail().unwrap();
        assert_eq!(detail.code, "POLICY_APPROVAL_REQUIRED");
        assert_eq!(detail.decision, "require_approval");
        assert_eq!(detail.rule_id, "approve-email");
        assert_eq!(detail.reason, "email send needs approval");
    }

    #[test]
    fn test_error_detail_allow_returns_none() {
        let decision = Decision::Allow {
            matched_rule: "allow-read".into(),
        };
        assert!(decision.error_detail().is_none());
    }

    #[test]
    fn test_error_detail_serialization() {
        let detail = ErrorDetail {
            code: "POLICY_DENY".into(),
            decision: "deny".into(),
            rule_id: "deny-shell".into(),
            reason: "shell not allowed".into(),
        };
        let json = serde_json::to_value(&detail).unwrap();
        assert_eq!(json["code"], "POLICY_DENY");
        assert_eq!(json["decision"], "deny");
        assert_eq!(json["rule_id"], "deny-shell");
        assert_eq!(json["reason"], "shell not allowed");

        // Roundtrip
        let back: ErrorDetail = serde_json::from_value(json).unwrap();
        assert_eq!(back, detail);
    }
}
