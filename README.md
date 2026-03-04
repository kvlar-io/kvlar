# Kvlar

**Bulletproof security for AI agents.**

Kvlar is an open-source policy engine and runtime security layer for AI agents. It evaluates every tool call, data access, and operation against YAML-based security policies before execution — ensuring agents only do what they're allowed to do.

## Why Kvlar?

AI agents are gaining the ability to execute code, send emails, access databases, and interact with production systems. But there's no standardized security layer between the agent and its tools. Kvlar fills that gap.

- **Fail-closed by default** — if no policy rule matches, the action is denied
- **Policy-as-code** — define security rules in human-readable YAML
- **Protocol-native** — built for the Model Context Protocol (MCP, spec 2024-11-05)
- **Deterministic** — same action + same policy = same decision, every time
- **Auditable** — every decision is logged with full context

## Quick Start

### 1. Build & Install

```bash
git clone https://github.com/kvlar-io/kvlar && cd kvlar
cargo build --release
# Binary at: target/release/kvlar-cli
```

### 2. Initialize a Policy

```bash
# Create ~/.kvlar/policy.yaml from a starter template
kvlar init                      # default template
kvlar init --template strict    # strict (deny-heavy)
kvlar init --template filesystem  # filesystem MCP server demo
```

### 3. Wrap Your MCP Servers

```bash
# Automatically inject Kvlar into Claude Desktop's MCP config
kvlar wrap                    # auto-detect client
kvlar wrap --dry-run          # preview changes first
kvlar wrap --client cursor    # target Cursor instead
```

Restart your MCP client after wrapping. Every tool call now flows through Kvlar's policy engine.

### 4. Test Your Policy

Write a test file to verify your policy behaves as expected:

```yaml
# my-policy.test.yaml
policy: "../policy.yaml"
tests:
  - id: deny-bash
    action:
      resource: bash
    expect: deny
    rule: deny-shell

  - id: allow-read
    action:
      resource: read_file
    expect: allow
```

Run it:

```bash
kvlar test -f my-policy.test.yaml           # human output
kvlar test -f my-policy.test.yaml --verbose  # show passing tests too
kvlar test -f my-policy.test.yaml --json     # JSON output for CI
```

### 5. Unwrap (Remove Kvlar)

```bash
kvlar unwrap           # restore original MCP server commands
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `kvlar init` | Create a starter policy file (~/.kvlar/policy.yaml) |
| `kvlar wrap` | Inject Kvlar proxy into MCP client config |
| `kvlar unwrap` | Remove Kvlar wrapping, restore original commands |
| `kvlar test` | Run policy test suites |
| `kvlar validate` | Validate a policy YAML file |
| `kvlar evaluate` | Evaluate a single action against a policy |
| `kvlar inspect` | Show policy summary (rules, effects) |
| `kvlar schema` | Export JSON Schema for policy validation |
| `kvlar proxy` | Start the MCP security proxy (stdio or TCP) |

## Architecture

```
Agent ──stdio/TCP──► kvlar-proxy ──stdio/TCP──► MCP Tool Server
                         │
                    kvlar-core (policy evaluation)
                         │
                    kvlar-audit (structured logging)
```

| Crate | Purpose |
|-------|---------|
| `kvlar-core` | Policy engine — pure logic, no I/O, fully deterministic |
| `kvlar-proxy` | MCP security proxy — intercepts and evaluates tool calls |
| `kvlar-audit` | Structured audit logging — JSONL/human output |
| `kvlar-cli` | CLI tool — 9 commands for policy management and proxy operation |

## MCP Compatibility

- **Spec version**: 2024-11-05
- **Transport**: stdio (primary), TCP
- **Tested with**: Claude Desktop, @modelcontextprotocol/server-filesystem
- **Protocol**: JSON-RPC 2.0 over newline-delimited JSON

## Development

```bash
# Build
cargo build --workspace

# Test (80 tests)
cargo test --workspace

# Lint
cargo clippy --workspace -- -D warnings

# Format
cargo fmt --all
```

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.

## Links

- Website: [kvlar.io](https://kvlar.io)
- GitHub: [github.com/kvlar-io/kvlar](https://github.com/kvlar-io/kvlar)
- X: [@kvlar_io](https://x.com/kvlar_io)
