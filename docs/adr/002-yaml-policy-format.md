# ADR-002: YAML-Based Policy Format

## Status
Accepted

## Context
We need a format for defining security policies. Options considered:
1. Rust code (compile-time)
2. JSON
3. YAML
4. TOML
5. Custom DSL (like OPA/Rego)

## Decision
We use **YAML** for policy definitions, with `serde_yaml` for parsing.

The Effect enum uses internally-tagged representation (`#[serde(tag = "type")]`):
```yaml
effect:
  type: deny
  reason: "Not allowed"
```

## Rationale
- YAML is human-readable and easy to write
- Supports comments (unlike JSON)
- Widely used for configuration (Kubernetes, GitHub Actions, etc.)
- `serde_yaml` integrates seamlessly with Rust's serde ecosystem
- No need to learn a custom DSL — lower barrier to adoption
- Policies can be version-controlled alongside code

## Consequences
- We depend on `serde_yaml` (currently deprecated but functional)
- May need to migrate to a successor YAML library in the future
- Complex logic (conditions, variables) will need extensions to the format
- Internally-tagged enums require `type` field in YAML
