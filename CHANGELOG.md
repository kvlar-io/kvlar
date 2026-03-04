# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `kvlar-core`: Policy engine with YAML-based policy definitions
- `kvlar-core`: Action, Decision, Policy, Rule, and Engine types
- `kvlar-core`: Fail-closed default (deny when no rule matches)
- `kvlar-core`: Regex-based parameter matching in rules
- `kvlar-audit`: Structured audit event logging
- `kvlar-audit`: JSON and human-readable output formats
- `kvlar-proxy`: MCP proxy configuration and scaffolding
- `kvlar-cli`: `validate`, `evaluate`, and `inspect` commands
- 23 unit tests across all crates
- CI workflow with check, test, clippy, format, and doc jobs
- Apache 2.0 license
