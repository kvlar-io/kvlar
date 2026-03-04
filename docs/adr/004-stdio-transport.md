# ADR-004: Stdio Transport (MITM Proxy)

## Status
Accepted

## Context
MCP clients (Claude Desktop, Cursor) communicate with tool servers over stdio — newline-delimited JSON on stdin/stdout. To intercept tool calls without modifying either the client or server, Kvlar needs to sit between them transparently.

TCP proxying was already implemented, but stdio is the dominant transport for local MCP servers. We needed a zero-configuration approach that works with any MCP client and any MCP server.

## Decision
Kvlar acts as a **stdio man-in-the-middle proxy**. The MCP client spawns Kvlar as the "server" process. Kvlar in turn spawns the real MCP server as a child process. All JSON-RPC messages flow through Kvlar, which intercepts `tools/call` requests for policy evaluation.

```
Client  ──stdin/stdout──►  Kvlar Proxy  ──stdin/stdout──►  Real MCP Server
                              │
                         Policy Engine
```

## Rationale
- **Zero changes to clients or servers**: The client just spawns a different binary. The server doesn't know Kvlar exists.
- **Works with `kvlar wrap`**: A single command rewrites the client config to insert Kvlar into the chain.
- **All user output goes to stderr**: Since stdin/stdout are the data channel, Kvlar logs exclusively to stderr to avoid corrupting the JSON-RPC stream.
- **Child process lifecycle**: Kvlar spawns the upstream server, pipes stdin/stdout bidirectionally, and exits when either side disconnects.

## Consequences
- Kvlar must handle child process management (spawn, wait, signal forwarding).
- All logging, including from dependencies, must go to stderr.
- The proxy adds minimal latency (< 1ms per message for policy evaluation).
- Non-`tools/call` messages (initialize, notifications, resource reads) are passed through without inspection.
