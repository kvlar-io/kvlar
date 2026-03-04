# ADR-001: Fail-Closed Default Decision

## Status
Accepted

## Context
When the policy engine evaluates an action and no rule matches, we need to decide what happens. There are two options:
1. **Fail-open**: Allow the action (optimistic)
2. **Fail-closed**: Deny the action (pessimistic)

## Decision
We use a **fail-closed** model. If no policy rule matches an action, the engine returns `Decision::Deny` with reason "no matching policy rule".

## Rationale
- Security systems should default to the safest option
- It's easier to add allow rules than to discover you forgot to add deny rules
- This is consistent with firewall/IAM best practices (deny by default)
- Agents performing unexpected actions are more dangerous than agents being blocked

## Consequences
- Policy authors must explicitly allow actions they want to permit
- A "catch-all allow" rule can be added at the end of a policy for permissive setups
- Error messages clearly indicate when the default deny is triggered vs. an explicit deny rule
