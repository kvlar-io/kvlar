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

use crate::approval::ApprovalBackend;
use crate::handler;
use crate::shutdown;

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
    approval_backend: Option<Arc<dyn ApprovalBackend>>,
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
            approval_backend: None,
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
            approval_backend: None,
        }
    }

    /// Sets the approval backend for handling `RequireApproval` decisions.
    pub fn with_approval_backend(mut self, backend: Arc<dyn ApprovalBackend>) -> Self {
        self.approval_backend = Some(backend);
        self
    }

    /// Returns a reference to the shared engine (for hot-reload wiring).
    pub fn engine(&self) -> &Arc<RwLock<Engine>> {
        &self.engine
    }

    /// Runs the stdio proxy with graceful shutdown.
    ///
    /// Spawns the upstream MCP server as a child process, then proxies
    /// all MCP messages through the policy engine. This function blocks
    /// until the client disconnects (stdin EOF), the child process exits,
    /// or a shutdown signal (SIGTERM/SIGINT) is received.
    ///
    /// On shutdown signal:
    /// 1. Active proxy loop is allowed to drain (up to 30s by default)
    /// 2. Audit log is flushed
    /// 3. Upstream child process is terminated cleanly
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        tracing::info!(
            command = %self.command,
            args = ?self.args,
            "spawning upstream MCP server"
        );

        // Install signal handlers — token is cancelled on SIGTERM/SIGINT
        let shutdown_token = shutdown::signal_shutdown_token();

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

        // Run the proxy loop with signal-aware shutdown
        let proxy_result = tokio::select! {
            result = handler::run_proxy_loop(
                client_reader,
                Arc::new(Mutex::new(client_writer)),
                upstream_reader,
                Arc::new(Mutex::new(upstream_writer)),
                self.engine.clone(),
                self.audit.clone(),
                self.fail_open,
                self.approval_backend.clone(),
            ) => {
                tracing::info!("proxy loop ended normally");
                result
            }
            _ = shutdown_token.cancelled() => {
                tracing::info!("shutdown signal received, draining...");
                // Give in-flight requests a moment to complete
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                Ok(())
            }
        };

        // Flush audit log
        {
            let mut audit = self.audit.lock().await;
            audit.flush();
            tracing::info!("audit log flushed");
        }

        // Clean up: terminate child process gracefully
        tracing::info!("waiting for child process to exit");
        let _ = child.kill().await;
        let exit_status = child.wait().await;
        match exit_status {
            Ok(status) => tracing::info!(status = %status, "child process exited"),
            Err(e) => tracing::warn!(error = %e, "error waiting for child process"),
        }

        proxy_result.map_err(|e| -> Box<dyn std::error::Error> { e })
    }
}
