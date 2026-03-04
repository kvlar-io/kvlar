//! Audit logger implementation.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::event::AuditEvent;

/// Output format for audit logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// JSON, one event per line (JSONL). Default.
    Json,
    /// Human-readable format for local development.
    Human,
}

/// Sink for audit events — where they get written.
#[derive(Debug)]
enum AuditSink {
    /// In-memory only (for testing).
    Memory,
    /// Write to a JSONL file.
    File { path: PathBuf, file: File },
}

/// Audit logger that records policy decisions.
///
/// Supports in-memory storage (for testing) and JSONL file output
/// (for production). Events are always kept in memory for querying,
/// and optionally written to a JSONL file.
#[derive(Debug)]
pub struct AuditLogger {
    /// The output format.
    format: OutputFormat,

    /// In-memory event store.
    events: Vec<AuditEvent>,

    /// Optional file sink.
    sink: AuditSink,
}

impl AuditLogger {
    /// Creates a new audit logger with the given format (in-memory only).
    pub fn new(format: OutputFormat) -> Self {
        Self {
            format,
            events: Vec::new(),
            sink: AuditSink::Memory,
        }
    }

    /// Creates a new audit logger that writes JSONL to a file.
    ///
    /// The file is opened in append mode. Events are written one per line.
    pub fn with_file(path: impl AsRef<Path>) -> Result<Self, std::io::Error> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            format: OutputFormat::Json,
            events: Vec::new(),
            sink: AuditSink::File { path, file },
        })
    }

    /// Returns the file path if this logger writes to a file.
    pub fn file_path(&self) -> Option<&Path> {
        match &self.sink {
            AuditSink::File { path, .. } => Some(path),
            AuditSink::Memory => None,
        }
    }

    /// Records an audit event.
    ///
    /// The event is stored in memory and, if a file sink is configured,
    /// written as a JSONL line to the file.
    pub fn record(&mut self, event: AuditEvent) {
        tracing::info!(
            action_type = %event.action_type,
            resource = %event.resource,
            agent_id = %event.agent_id,
            outcome = ?event.outcome,
            matched_rule = %event.matched_rule,
            "policy decision recorded"
        );

        // Write to file sink if configured
        if let AuditSink::File { file, .. } = &mut self.sink
            && let Ok(json) = serde_json::to_string(&event)
        {
            let _ = writeln!(file, "{}", json);
        }

        self.events.push(event);
    }

    /// Returns all recorded events.
    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }

    /// Returns the number of recorded events.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Returns the output format.
    pub fn format(&self) -> OutputFormat {
        self.format
    }

    /// Clears all in-memory events.
    pub fn clear(&mut self) {
        self.events.clear();
    }

    /// Formats an event for human-readable output.
    pub fn format_human(event: &AuditEvent) -> String {
        let outcome_str = match &event.outcome {
            crate::event::EventOutcome::Allowed => "\x1b[32m✓ ALLOW\x1b[0m",
            crate::event::EventOutcome::Denied => "\x1b[31m✗ DENY\x1b[0m",
            crate::event::EventOutcome::PendingApproval => "\x1b[33m⚠ APPROVE\x1b[0m",
        };

        let reason_part = event
            .reason
            .as_deref()
            .map(|r| format!(" — {}", r))
            .unwrap_or_default();

        format!(
            "{} {} [{}] {}/{} (agent: {}, rule: {}){}",
            event.timestamp.format("%H:%M:%S%.3f"),
            outcome_str,
            event.id.as_simple(),
            event.action_type,
            event.resource,
            event.agent_id,
            event.matched_rule,
            reason_part,
        )
    }
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new(OutputFormat::Json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{AuditEvent, EventOutcome};

    #[test]
    fn test_logger_record_and_retrieve() {
        let mut logger = AuditLogger::default();
        assert_eq!(logger.event_count(), 0);

        let event = AuditEvent::new(
            "tool_call",
            "bash",
            "agent-1",
            EventOutcome::Denied,
            "deny-bash",
        );
        logger.record(event);

        assert_eq!(logger.event_count(), 1);
        assert_eq!(logger.events()[0].resource, "bash");
    }

    #[test]
    fn test_logger_clear() {
        let mut logger = AuditLogger::default();
        let event = AuditEvent::new(
            "tool_call",
            "bash",
            "agent-1",
            EventOutcome::Denied,
            "deny-bash",
        );
        logger.record(event);
        assert_eq!(logger.event_count(), 1);

        logger.clear();
        assert_eq!(logger.event_count(), 0);
    }

    #[test]
    fn test_logger_format() {
        let logger = AuditLogger::new(OutputFormat::Human);
        assert_eq!(logger.format(), OutputFormat::Human);
    }

    #[test]
    fn test_logger_jsonl_file_output() {
        let dir = std::env::temp_dir().join("kvlar-test-audit-jsonl");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");

        {
            let mut logger = AuditLogger::with_file(&path).unwrap();
            assert_eq!(logger.file_path().unwrap(), path);

            logger.record(AuditEvent::new(
                "tool_call",
                "bash",
                "agent-1",
                EventOutcome::Denied,
                "deny-bash",
            ));
            logger.record(AuditEvent::new(
                "tool_call",
                "read_file",
                "agent-2",
                EventOutcome::Allowed,
                "allow-read",
            ));
        }

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.trim().lines().collect();
        assert_eq!(lines.len(), 2);

        // Each line should be valid JSON
        let event1: AuditEvent = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(event1.resource, "bash");
        assert_eq!(event1.outcome, EventOutcome::Denied);

        let event2: AuditEvent = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(event2.resource, "read_file");
        assert_eq!(event2.outcome, EventOutcome::Allowed);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_logger_memory_has_no_file_path() {
        let logger = AuditLogger::default();
        assert!(logger.file_path().is_none());
    }

    #[test]
    fn test_format_human_output() {
        let event = AuditEvent::new(
            "tool_call",
            "bash",
            "agent-1",
            EventOutcome::Denied,
            "deny-bash",
        )
        .with_reason("Shell access not permitted");

        let output = AuditLogger::format_human(&event);
        assert!(output.contains("DENY"));
        assert!(output.contains("tool_call/bash"));
        assert!(output.contains("agent-1"));
        assert!(output.contains("Shell access not permitted"));
    }

    #[test]
    fn test_format_human_allow() {
        let event = AuditEvent::new(
            "tool_call",
            "read_file",
            "agent-1",
            EventOutcome::Allowed,
            "allow-read",
        );

        let output = AuditLogger::format_human(&event);
        assert!(output.contains("ALLOW"));
        assert!(output.contains("read_file"));
    }

    #[test]
    fn test_format_human_approval() {
        let event = AuditEvent::new(
            "tool_call",
            "send_email",
            "agent-1",
            EventOutcome::PendingApproval,
            "approve-email",
        )
        .with_reason("Needs human approval");

        let output = AuditLogger::format_human(&event);
        assert!(output.contains("APPROVE"));
        assert!(output.contains("Needs human approval"));
    }
}
