# ADR-005: Python SDK via Subprocess

## Status

Accepted

## Context

Most AI agent developers work in Python (LangChain, CrewAI, AutoGPT, etc.).
A Python SDK for Kvlar would significantly expand adoption. There are three
viable approaches:

1. **PyO3 bindings** — compile kvlar-core to a native Python extension via PyO3.
   Pros: fast, type-safe. Cons: complex build (maturin), platform-specific wheels,
   hard to debug, CI complexity for manylinux/macOS/Windows builds.

2. **Subprocess wrapper** — shell out to the `kvlar` CLI binary.
   Pros: simple, works immediately, no compile step, same binary as CLI users.
   Cons: requires kvlar binary on PATH, subprocess overhead per call.

3. **Pure Python reimplementation** — rewrite the policy engine in Python.
   Pros: no native dependency. Cons: duplicated logic, divergence risk,
   maintenance burden, weaker security guarantees.

## Decision

Use the **subprocess approach** for the initial Python SDK (v0.1.0).

The `kvlar` binary already supports `kvlar evaluate` and `kvlar test` commands
that accept policy files and return structured output. The Python SDK wraps
these commands with a clean API.

## Rationale

- **Ship fast**: Subprocess wrapper can ship in days, not weeks
- **Single source of truth**: Policy evaluation logic stays in Rust
- **No build complexity**: `pip install kvlar` + `cargo install kvlar-cli`
- **Upgrade path**: If performance becomes an issue, we can add PyO3 bindings
  later as an optional accelerated backend (same API, swap implementation)

## Trade-offs

- Requires `kvlar` binary on PATH (documented as prerequisite)
- Subprocess overhead (~10-50ms per evaluation) is acceptable for policy
  checks but not for hot-path evaluation in production
- JSON serialization overhead for action parameters

## Consequences

- Python SDK is a thin wrapper, not a full engine
- `kvlar evaluate` command needs `--json` output mode for machine parsing
- Future PyO3 option remains open via the same Python API surface
