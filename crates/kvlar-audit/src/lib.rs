//! # kvlar-audit
//!
//! Structured audit logging for Kvlar. Records every policy decision
//! with full context for compliance, debugging, and observability.
//!
//! ## Output Formats
//!
//! - **JSON** — machine-readable, one event per line (default)
//! - **Human** — developer-friendly colored output for local development

pub mod event;
pub mod export;
pub mod logger;

pub use event::{AuditEvent, EventOutcome};
pub use export::{ExportFilter, ExportFormat, export_events, export_from_file};
pub use logger::AuditLogger;

/// Library version, pulled from Cargo.toml at compile time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
