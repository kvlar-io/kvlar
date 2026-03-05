//! Proxy configuration.

use serde::{Deserialize, Serialize};

/// Transport mode for the proxy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    /// TCP socket transport (line-delimited JSON over TCP). Default.
    #[default]
    Tcp,
    /// Stdio transport (newline-delimited JSON over stdin/stdout).
    /// The proxy spawns the upstream server as a subprocess.
    Stdio,
}

/// Configuration for the Kvlar MCP proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Address to listen on (e.g., "127.0.0.1:9100"). TCP mode only.
    pub listen_addr: String,

    /// Upstream MCP server address to forward allowed requests to. TCP mode only.
    pub upstream_addr: String,

    /// Path to the policy YAML file(s).
    pub policy_paths: Vec<String>,

    /// Whether to enable audit logging.
    #[serde(default = "default_true")]
    pub audit_enabled: bool,

    /// Path to the audit log file (JSONL format).
    #[serde(default)]
    pub audit_file: Option<String>,

    /// Whether to fail-open (allow) when the policy engine errors.
    /// Default: false (fail-closed).
    #[serde(default)]
    pub fail_open: bool,

    /// Whether to watch policy files for changes and reload automatically.
    #[serde(default)]
    pub hot_reload: bool,

    /// Transport mode (tcp or stdio). Default: tcp.
    #[serde(default)]
    pub transport: TransportMode,

    /// Command to spawn for stdio transport (e.g., "npx").
    /// Only used when transport = stdio.
    #[serde(default)]
    pub upstream_command: Option<String>,

    /// Arguments for the upstream command.
    /// Only used when transport = stdio.
    #[serde(default)]
    pub upstream_args: Vec<String>,

    /// Health check endpoint address (e.g., "127.0.0.1:9101").
    /// Only used in TCP mode. Set to enable `GET /health` liveness probe.
    #[serde(default)]
    pub health_addr: Option<String>,
}

fn default_true() -> bool {
    true
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:9100".into(),
            upstream_addr: "127.0.0.1:3000".into(),
            policy_paths: vec!["policy.yaml".into()],
            audit_enabled: true,
            audit_file: None,
            fail_open: false,
            hot_reload: false,
            transport: TransportMode::default(),
            upstream_command: None,
            upstream_args: Vec::new(),
            health_addr: None,
        }
    }
}

impl ProxyConfig {
    /// Loads configuration from a YAML file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let yaml = std::fs::read_to_string(path)?;
        let config: ProxyConfig = serde_yaml::from_str(&yaml)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ProxyConfig::default();
        assert_eq!(config.listen_addr, "127.0.0.1:9100");
        assert!(config.audit_enabled);
        assert!(!config.fail_open);
        assert!(!config.hot_reload);
        assert!(config.audit_file.is_none());
    }

    #[test]
    fn test_config_serde_roundtrip() {
        let config = ProxyConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: ProxyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.listen_addr, config.listen_addr);
        assert_eq!(parsed.upstream_addr, config.upstream_addr);
    }

    #[test]
    fn test_config_from_yaml_string() {
        let yaml = r#"
listen_addr: "0.0.0.0:8080"
upstream_addr: "localhost:4000"
policy_paths:
  - "policies/prod.yaml"
  - "policies/custom.yaml"
audit_enabled: true
audit_file: "/var/log/kvlar/audit.jsonl"
fail_open: false
hot_reload: true
"#;
        let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.listen_addr, "0.0.0.0:8080");
        assert_eq!(config.policy_paths.len(), 2);
        assert!(config.hot_reload);
        assert_eq!(
            config.audit_file.as_deref(),
            Some("/var/log/kvlar/audit.jsonl")
        );
    }
}
