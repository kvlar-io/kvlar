//! MCP proxy server implementation (TCP transport).
//!
//! Implements a TCP proxy that intercepts MCP JSON-RPC messages,
//! evaluates tool calls against the policy engine, and either
//! forwards allowed requests or blocks denied ones.

use std::sync::Arc;

use kvlar_audit::AuditLogger;
use kvlar_core::Engine;
use tokio::io::BufReader;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, RwLock};

use crate::config::ProxyConfig;
use crate::handler;
use crate::health::ProxyStats;
use crate::shutdown;

/// The MCP security proxy (TCP transport).
///
/// Listens for incoming MCP connections, intercepts tool call requests,
/// runs them through the policy engine, and forwards allowed requests
/// to the upstream MCP server.
pub struct McpProxy {
    /// The policy evaluation engine.
    engine: Arc<RwLock<Engine>>,

    /// Proxy configuration.
    config: ProxyConfig,

    /// Audit logger.
    audit: Arc<Mutex<AuditLogger>>,

    /// Runtime statistics for health endpoint.
    stats: Arc<ProxyStats>,
}

impl McpProxy {
    /// Creates a new proxy with the given engine and configuration.
    pub fn new(engine: Engine, config: ProxyConfig) -> Self {
        let audit = AuditLogger::default();
        Self {
            engine: Arc::new(RwLock::new(engine)),
            config,
            audit: Arc::new(Mutex::new(audit)),
            stats: Arc::new(ProxyStats::new()),
        }
    }

    /// Creates a new proxy with a custom audit logger.
    pub fn with_audit(engine: Engine, config: ProxyConfig, audit: AuditLogger) -> Self {
        Self {
            engine: Arc::new(RwLock::new(engine)),
            config,
            audit: Arc::new(Mutex::new(audit)),
            stats: Arc::new(ProxyStats::new()),
        }
    }

    /// Returns a reference to the shared engine.
    pub fn engine(&self) -> &Arc<RwLock<Engine>> {
        &self.engine
    }

    /// Returns a reference to the proxy configuration.
    pub fn config(&self) -> &ProxyConfig {
        &self.config
    }

    /// Returns a reference to the proxy stats.
    pub fn stats(&self) -> &Arc<ProxyStats> {
        &self.stats
    }

    /// Replaces the engine with a new one (for hot-reload).
    pub async fn replace_engine(&self, new_engine: Engine) {
        let mut engine = self.engine.write().await;
        *engine = new_engine;
    }

    /// Starts the proxy server with graceful shutdown.
    ///
    /// Listens for incoming connections and handles them concurrently.
    /// On SIGTERM/SIGINT, stops accepting new connections and waits
    /// for active connections to drain (up to 30s timeout).
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(&self.config.listen_addr).await?;
        tracing::info!(addr = %self.config.listen_addr, "kvlar proxy listening");

        // Start health check server if configured
        if let Some(ref health_addr) = self.config.health_addr {
            let stats = self.stats.clone();
            let addr = health_addr.clone();
            tokio::spawn(async move {
                if let Err(e) = crate::health::run_health_server(&addr, stats).await {
                    tracing::error!(error = %e, "health server error");
                }
            });
        }

        // Update stats with current policy info
        {
            let eng = self.engine.read().await;
            self.stats
                .set_policy_info(eng.policy_count() > 0, eng.rule_count() as u64);
        }

        // Install signal handlers
        let shutdown_token = shutdown::signal_shutdown_token();

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (client_stream, client_addr) = result?;
                    tracing::info!(client = %client_addr, "new connection");

                    let engine = self.engine.clone();
                    let upstream_addr = self.config.upstream_addr.clone();
                    let audit = self.audit.clone();
                    let fail_open = self.config.fail_open;

                    tokio::spawn(async move {
                        if let Err(e) =
                            Self::handle_connection(client_stream, &upstream_addr, engine, audit, fail_open)
                                .await
                        {
                            tracing::error!(client = %client_addr, error = %e, "connection error");
                        }
                    });
                }
                _ = shutdown_token.cancelled() => {
                    tracing::info!("shutdown signal received, stopping accept loop");
                    break;
                }
            }
        }

        // Flush audit log
        {
            let mut audit = self.audit.lock().await;
            audit.flush();
            tracing::info!("audit log flushed");
        }

        // Give active connections time to drain
        tracing::info!("waiting for active connections to drain...");
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        Ok(())
    }

    /// Handles a single client connection by delegating to the shared handler.
    async fn handle_connection(
        client_stream: TcpStream,
        upstream_addr: &str,
        engine: Arc<RwLock<Engine>>,
        audit: Arc<Mutex<AuditLogger>>,
        fail_open: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let upstream_stream = TcpStream::connect(upstream_addr).await?;

        let (client_read, client_write) = client_stream.into_split();
        let (upstream_read, upstream_write) = upstream_stream.into_split();

        let client_reader = BufReader::new(client_read);
        let upstream_reader = BufReader::new(upstream_read);

        handler::run_proxy_loop(
            client_reader,
            Arc::new(Mutex::new(client_write)),
            upstream_reader,
            Arc::new(Mutex::new(upstream_write)),
            engine,
            audit,
            fail_open,
            None,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_creation() {
        let engine = Engine::new();
        let config = ProxyConfig::default();
        let proxy = McpProxy::new(engine, config);
        assert_eq!(proxy.config().listen_addr, "127.0.0.1:9100");
    }

    #[tokio::test]
    async fn test_proxy_replace_engine() {
        let engine = Engine::new();
        let config = ProxyConfig::default();
        let proxy = McpProxy::new(engine, config);

        {
            let engine = proxy.engine().read().await;
            assert_eq!(engine.policy_count(), 0);
        }

        let mut new_engine = Engine::new();
        new_engine
            .load_policy_yaml(
                r#"
name: test
description: test
version: "1"
rules:
  - id: deny-all
    description: deny everything
    match_on: {}
    effect:
      type: deny
      reason: "denied"
"#,
            )
            .unwrap();

        proxy.replace_engine(new_engine).await;

        {
            let engine = proxy.engine().read().await;
            assert_eq!(engine.policy_count(), 1);
        }
    }
}
