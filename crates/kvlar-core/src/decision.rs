//! Decision types — the output of policy evaluation.

use serde::{Deserialize, Serialize};

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
}
