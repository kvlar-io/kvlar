//! MCP stdio transport implementation.
//!
//! Implements a stdio-based proxy that spawns the upstream MCP server as a
//! child process and communicates via stdin/stdout pipes. This is how
//! Claude Desktop, Cursor, and other MCP clients invoke tool servers.
//!
//! ## Architecture
//!
//! ```text
//! MCP Client (stdin) → Kvlar Proxy → Child Process (stdin) → MCP Server
//! MCP Client (stdout) ← Kvlar Proxy ← Child Process (stdout) ← MCP Server
//! ```

use std::process::Stdio;
use std::sync::Arc;

use kvlar_audit::AuditLogger;
use kvlar_core::Engine;
use tokio::io::BufReader;
use tokio::process::Command;
use tokio::sync::{Mutex, RwLock};

use crate::handler;

/// MCP stdio transport proxy.
///
/// Spawns the upstream MCP server as a child process and proxies
/// MCP messages between the client (our stdin/stdout) and the server
/// (child process stdin/stdout), applying policy evaluation on tool calls.
pub struct StdioTransport {
    engine: Arc<RwLock<Engine>>,
    audit: Arc<Mutex<AuditLogger>>,
    command: String,
    args: Vec<String>,
    fail_open: bool,
}

impl StdioTransport {
    /// Creates a new stdio transport proxy.
    pub fn new(
        engine: Engine,
        audit: AuditLogger,
        command: String,
        args: Vec<String>,
        fail_open: bool,
    ) -> Self {
        Self {
            engine: Arc::new(RwLock::new(engine)),
            audit: Arc::new(Mutex::new(audit)),
            command,
            args,
            fail_open,
        }
    }

    /// Creates a new stdio transport proxy with a shared engine reference.
    ///
    /// Use this when hot-reload is enabled — the caller retains a clone
    /// of the `Arc<RwLock<Engine>>` and can swap the engine atomically
    /// while the proxy is running.
    pub fn with_shared_engine(
        engine: Arc<RwLock<Engine>>,
        audit: AuditLogger,
        command: String,
        args: Vec<String>,
        fail_open: bool,
    ) -> Self {
        Self {
            engine,
            audit: Arc::new(Mutex::new(audit)),
            command,
            args,
            fail_open,
        }
    }

    /// Returns a reference to the shared engine (for hot-reload wiring).
    pub fn engine(&self) -> &Arc<RwLock<Engine>> {
        &self.engine
    }

    /// Runs the stdio proxy.
    ///
    /// Spawns the upstream MCP server as a child process, then proxies
    /// all MCP messages through the policy engine. This function blocks
    /// until the client disconnects (stdin EOF) or the child process exits.
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        tracing::info!(
            command = %self.command,
            args = ?self.args,
            "spawning upstream MCP server"
        );

        // Spawn the upstream MCP server as a child process
        let mut child = Command::new(&self.command)
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit()) // Pass server stderr through to our stderr
            .spawn()
            .map_err(|e| format!("failed to spawn upstream command '{}': {}", self.command, e))?;

        let child_stdin = child.stdin.take().ok_or("failed to capture child stdin")?;
        let child_stdout = child
            .stdout
            .take()
            .ok_or("failed to capture child stdout")?;

        // Our stdin = client reading (MCP client writes to us)
        let client_reader = BufReader::new(tokio::io::stdin());
        // Our stdout = client writing (we write responses to MCP client)
        let client_writer = tokio::io::stdout();
        // Child stdin = upstream writing (we forward messages to the server)
        let upstream_writer = child_stdin;
        // Child stdout = upstream reading (server sends responses to us)
        let upstream_reader = BufReader::new(child_stdout);

        tracing::info!("stdio proxy running");

        // Run the proxy loop — this blocks until client or server disconnects
        let result = handler::run_proxy_loop(
            client_reader,
            Arc::new(Mutex::new(client_writer)),
            upstream_reader,
            Arc::new(Mutex::new(upstream_writer)),
            self.engine.clone(),
            self.audit.clone(),
            self.fail_open,
        )
        .await;

        // Clean up: ensure child process is terminated
        tracing::info!("proxy loop ended, waiting for child process");
        let _ = child.kill().await;
        let _ = child.wait().await;

        result.map_err(|e| -> Box<dyn std::error::Error> { e })
    }
}
