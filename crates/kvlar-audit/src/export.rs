//! Audit log export — SIEM-compatible formats and filtering.
//!
//! Supports exporting audit events to:
//! - **JSONL** — one JSON object per line (Splunk, Datadog, Elastic)
//! - **CEF** — Common Event Format (ArcSight, QRadar, Splunk)
//! - **CSV** — comma-separated values (spreadsheets, data tools)

use std::io::Write;

use chrono::{DateTime, Utc};

use crate::event::{AuditEvent, EventOutcome};

// ---------------------------------------------------------------------------
// Export formats
// ---------------------------------------------------------------------------

/// Output format for audit log export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// JSON Lines — one JSON object per line.
    Jsonl,
    /// Common Event Format (CEF) — industry standard for SIEMs.
    Cef,
    /// Comma-separated values.
    Csv,
}

impl ExportFormat {
    /// Parse a format string (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "jsonl" | "json" | "ndjson" => Some(Self::Jsonl),
            "cef" => Some(Self::Cef),
            "csv" => Some(Self::Csv),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Filter
// ---------------------------------------------------------------------------

/// Filter criteria for selecting audit events.
#[derive(Debug, Default)]
pub struct ExportFilter {
    /// Only events after this timestamp.
    pub since: Option<DateTime<Utc>>,
    /// Only events before this timestamp.
    pub until: Option<DateTime<Utc>>,
    /// Only events with this outcome.
    pub outcome: Option<EventOutcome>,
    /// Only events targeting this resource (substring match).
    pub resource: Option<String>,
    /// Only events from this agent (substring match).
    pub agent: Option<String>,
}

impl ExportFilter {
    /// Returns true if the event matches all filter criteria.
    pub fn matches(&self, event: &AuditEvent) -> bool {
        if let Some(since) = &self.since
            && event.timestamp < *since
        {
            return false;
        }
        if let Some(until) = &self.until
            && event.timestamp > *until
        {
            return false;
        }
        if let Some(outcome) = &self.outcome
            && event.outcome != *outcome
        {
            return false;
        }
        if let Some(resource) = &self.resource
            && !event.resource.contains(resource.as_str())
        {
            return false;
        }
        if let Some(agent) = &self.agent
            && !event.agent_id.contains(agent.as_str())
        {
            return false;
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Exporters
// ---------------------------------------------------------------------------

/// Export audit events to a writer in the specified format.
///
/// Reads events from the provided slice, applies the filter, and writes
/// matching events to the writer in the requested format.
pub fn export_events<W: Write>(
    events: &[AuditEvent],
    filter: &ExportFilter,
    format: ExportFormat,
    writer: &mut W,
) -> std::io::Result<usize> {
    let mut count = 0;

    // Write CSV header if needed
    if format == ExportFormat::Csv {
        writeln!(
            writer,
            "id,timestamp,action_type,resource,agent_id,outcome,matched_rule,reason"
        )?;
    }

    for event in events {
        if !filter.matches(event) {
            continue;
        }

        match format {
            ExportFormat::Jsonl => write_jsonl(writer, event)?,
            ExportFormat::Cef => write_cef(writer, event)?,
            ExportFormat::Csv => write_csv(writer, event)?,
        }

        count += 1;
    }

    Ok(count)
}

/// Export audit events from a JSONL file on disk.
///
/// Reads line-by-line to handle large files without loading everything
/// into memory.
pub fn export_from_file<W: Write>(
    path: &std::path::Path,
    filter: &ExportFilter,
    format: ExportFormat,
    writer: &mut W,
) -> std::io::Result<usize> {
    use std::io::BufRead;

    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let mut count = 0;

    if format == ExportFormat::Csv {
        writeln!(
            writer,
            "id,timestamp,action_type,resource,agent_id,outcome,matched_rule,reason"
        )?;
    }

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let event: AuditEvent = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(_) => continue, // skip malformed lines
        };

        if !filter.matches(&event) {
            continue;
        }

        match format {
            ExportFormat::Jsonl => write_jsonl(writer, &event)?,
            ExportFormat::Cef => write_cef(writer, &event)?,
            ExportFormat::Csv => write_csv(writer, &event)?,
        }

        count += 1;
    }

    Ok(count)
}

// ---------------------------------------------------------------------------
// Format writers
// ---------------------------------------------------------------------------

fn write_jsonl<W: Write>(writer: &mut W, event: &AuditEvent) -> std::io::Result<()> {
    let json = serde_json::to_string(event).map_err(std::io::Error::other)?;
    writeln!(writer, "{}", json)
}

/// Write a CEF-formatted line.
///
/// CEF format:
/// `CEF:0|Kvlar|PolicyEngine|<version>|<event_id>|<name>|<severity>|<extensions>`
fn write_cef<W: Write>(writer: &mut W, event: &AuditEvent) -> std::io::Result<()> {
    let severity = match event.outcome {
        EventOutcome::Allowed => 1,
        EventOutcome::PendingApproval => 5,
        EventOutcome::Denied => 8,
    };

    let name = format!("{}/{}", event.action_type, event.resource);
    let outcome_str = match event.outcome {
        EventOutcome::Allowed => "allowed",
        EventOutcome::Denied => "denied",
        EventOutcome::PendingApproval => "pending_approval",
    };

    let reason = event.reason.as_deref().unwrap_or("");

    writeln!(
        writer,
        "CEF:0|Kvlar|PolicyEngine|{}|{}|{}|{}|rt={} suser={} outcome={} cs1={} cs1Label=matchedRule msg={}",
        crate::VERSION,
        cef_escape(&event.id.to_string()),
        cef_escape(&name),
        severity,
        event.timestamp.to_rfc3339(),
        cef_escape(&event.agent_id),
        outcome_str,
        cef_escape(&event.matched_rule),
        cef_escape(reason),
    )
}

fn write_csv<W: Write>(writer: &mut W, event: &AuditEvent) -> std::io::Result<()> {
    let outcome_str = match event.outcome {
        EventOutcome::Allowed => "allowed",
        EventOutcome::Denied => "denied",
        EventOutcome::PendingApproval => "pending_approval",
    };

    writeln!(
        writer,
        "{},{},{},{},{},{},{},{}",
        event.id,
        event.timestamp.to_rfc3339(),
        csv_escape(&event.action_type),
        csv_escape(&event.resource),
        csv_escape(&event.agent_id),
        outcome_str,
        csv_escape(&event.matched_rule),
        csv_escape(event.reason.as_deref().unwrap_or("")),
    )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Escape a string for CEF format (pipe and backslash).
fn cef_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('|', "\\|")
}

/// Escape a string for CSV (quote if it contains commas, quotes, or newlines).
fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_events() -> Vec<AuditEvent> {
        vec![
            AuditEvent::new(
                "tool_call",
                "read_file",
                "agent-1",
                EventOutcome::Allowed,
                "allow-read",
            ),
            AuditEvent::new(
                "tool_call",
                "bash",
                "agent-2",
                EventOutcome::Denied,
                "deny-bash",
            )
            .with_reason("Shell access blocked"),
            AuditEvent::new(
                "tool_call",
                "send_email",
                "agent-1",
                EventOutcome::PendingApproval,
                "approve-email",
            )
            .with_reason("Needs human approval"),
        ]
    }

    #[test]
    fn test_export_jsonl() {
        let events = sample_events();
        let mut buf = Vec::new();
        let count = export_events(
            &events,
            &ExportFilter::default(),
            ExportFormat::Jsonl,
            &mut buf,
        )
        .unwrap();
        assert_eq!(count, 3);

        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.trim().lines().collect();
        assert_eq!(lines.len(), 3);

        // Each line should be valid JSON
        for line in &lines {
            let _: AuditEvent = serde_json::from_str(line).unwrap();
        }
    }

    #[test]
    fn test_export_cef() {
        let events = sample_events();
        let mut buf = Vec::new();
        let count = export_events(
            &events,
            &ExportFilter::default(),
            ExportFormat::Cef,
            &mut buf,
        )
        .unwrap();
        assert_eq!(count, 3);

        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.trim().lines().collect();
        assert_eq!(lines.len(), 3);

        // All lines should start with CEF:0
        for line in &lines {
            assert!(line.starts_with("CEF:0|Kvlar|PolicyEngine|"));
        }

        // Check severity mapping
        assert!(lines[0].contains("|1|")); // allowed = 1
        assert!(lines[1].contains("|8|")); // denied = 8
        assert!(lines[2].contains("|5|")); // pending = 5
    }

    #[test]
    fn test_export_csv() {
        let events = sample_events();
        let mut buf = Vec::new();
        let count = export_events(
            &events,
            &ExportFilter::default(),
            ExportFormat::Csv,
            &mut buf,
        )
        .unwrap();
        assert_eq!(count, 3);

        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.trim().lines().collect();
        assert_eq!(lines.len(), 4); // header + 3 rows

        assert!(lines[0].starts_with("id,timestamp,"));
        assert!(lines[2].contains("denied"));
    }

    #[test]
    fn test_filter_by_outcome() {
        let events = sample_events();
        let filter = ExportFilter {
            outcome: Some(EventOutcome::Denied),
            ..Default::default()
        };
        let mut buf = Vec::new();
        let count = export_events(&events, &filter, ExportFormat::Jsonl, &mut buf).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_filter_by_resource() {
        let events = sample_events();
        let filter = ExportFilter {
            resource: Some("bash".to_string()),
            ..Default::default()
        };
        let mut buf = Vec::new();
        let count = export_events(&events, &filter, ExportFormat::Jsonl, &mut buf).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_filter_by_agent() {
        let events = sample_events();
        let filter = ExportFilter {
            agent: Some("agent-1".to_string()),
            ..Default::default()
        };
        let mut buf = Vec::new();
        let count = export_events(&events, &filter, ExportFormat::Jsonl, &mut buf).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_filter_combined() {
        let events = sample_events();
        let filter = ExportFilter {
            agent: Some("agent-1".to_string()),
            outcome: Some(EventOutcome::Allowed),
            ..Default::default()
        };
        let mut buf = Vec::new();
        let count = export_events(&events, &filter, ExportFormat::Jsonl, &mut buf).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_export_from_file() {
        let dir = std::env::temp_dir().join("kvlar-test-export");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");

        // Write sample events as JSONL
        let events = sample_events();
        let mut file = std::fs::File::create(&path).unwrap();
        for event in &events {
            writeln!(file, "{}", serde_json::to_string(event).unwrap()).unwrap();
        }
        drop(file);

        // Export from file as CEF
        let mut buf = Vec::new();
        let count =
            export_from_file(&path, &ExportFilter::default(), ExportFormat::Cef, &mut buf).unwrap();
        assert_eq!(count, 3);

        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("CEF:0|Kvlar|PolicyEngine|"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_cef_escape() {
        assert_eq!(cef_escape("hello|world"), "hello\\|world");
        assert_eq!(cef_escape("back\\slash"), "back\\\\slash");
    }

    #[test]
    fn test_csv_escape() {
        assert_eq!(csv_escape("hello"), "hello");
        assert_eq!(csv_escape("hello,world"), "\"hello,world\"");
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn test_format_from_str() {
        assert_eq!(ExportFormat::parse("jsonl"), Some(ExportFormat::Jsonl));
        assert_eq!(ExportFormat::parse("JSON"), Some(ExportFormat::Jsonl));
        assert_eq!(ExportFormat::parse("cef"), Some(ExportFormat::Cef));
        assert_eq!(ExportFormat::parse("csv"), Some(ExportFormat::Csv));
        assert_eq!(ExportFormat::parse("ndjson"), Some(ExportFormat::Jsonl));
        assert_eq!(ExportFormat::parse("xml"), None);
    }
}
