# ADR-003: Pure Core Engine (No I/O, No Async)

## Status
Accepted

## Context
The policy evaluation engine is the most critical component. We need to decide whether it should handle I/O operations (file reading, network calls) or remain a pure logic layer.

## Decision
`kvlar-core` is a **pure logic crate** — no filesystem access, no network calls, no async runtime. It takes an `Action` and a `Policy` as input and returns a `Decision` as output.

## Rationale
- Pure functions are easier to test (no mocks needed)
- Deterministic: same input always produces the same output
- Can be compiled to WebAssembly for browser/edge use
- No runtime dependencies (no tokio in core)
- Enables embedding in any context (CLI, server, library, WASM)
- Security: the engine can't be tricked into making network calls

## Consequences
- File I/O (loading policies from disk) happens in `kvlar-cli` and `kvlar-proxy`
- Async operations (proxy networking) live in `kvlar-proxy`
- The core crate has a minimal dependency footprint
- Testing is straightforward with in-memory data
