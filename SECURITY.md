# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Kvlar, please report it responsibly.

**Email**: security@kvlar.io

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge your report within 48 hours and aim to provide a fix within 7 days for critical issues.

## Security Model

Kvlar follows a **fail-closed** security model:

1. **Default deny**: If no policy rule matches an action, it is denied
2. **First match wins**: Rules are evaluated in order; the first matching rule determines the outcome
3. **Three outcomes**: Allow, Deny, or RequireApproval
4. **Full audit trail**: Every decision is logged with complete context

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Security Practices

- All dependencies are checked with `cargo audit`
- CI runs `clippy` with `-D warnings`
- No `unsafe` code in the core engine
- Regex patterns are validated before compilation
- YAML input is validated against expected structure
- Error messages are designed to not leak internal state

## Scope

The following are in scope for security reports:
- Policy evaluation bypass
- Audit log tampering or evasion
- Denial of service via crafted policies or actions
- Information disclosure through error messages
- Dependency vulnerabilities

The following are out of scope:
- Issues in upstream dependencies (report to those projects directly)
- Theoretical attacks without a proof of concept
