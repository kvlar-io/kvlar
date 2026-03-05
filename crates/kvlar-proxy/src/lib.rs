//! # kvlar-proxy
//!
//! MCP security proxy — intercepts Model Context Protocol messages and
//! evaluates them against loaded security policies before forwarding.
//!
//! This crate provides the runtime enforcement layer. It sits between an
//! AI agent and its tool servers, ensuring every tool call passes through
//! the Kvlar policy engine before execution.
//!
//! ## Architecture
//!
//! ```text
//! Agent ──► kvlar-proxy ──► MCP Tool Server
//!               │
//!               ├── kvlar-core (policy evaluation)
//!               └── kvlar-audit (structured logging)
//! ```

pub mod approval;
pub mod config;
pub mod handler;
pub mod health;
pub mod mcp;
pub mod proxy;
pub mod shutdown;
pub mod stdio;
pub mod watcher;

pub use approval::{
    ApprovalBackend, ApprovalError, DenyAllApprovalBackend, WebhookApprovalBackend,
};
pub use config::ProxyConfig;
pub use mcp::{McpMessage, McpRequest, McpResponse, ToolCallParams};

/// Library version, pulled from Cargo.toml at compile time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
