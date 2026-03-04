//! MCP client configuration handling.
//!
//! Read, modify, and write MCP client configs (Claude Desktop, Cursor).
//! Used by `kvlar wrap` and `kvlar unwrap` to inject or remove the
//! Kvlar security proxy from existing MCP server entries.

use std::path::{Path, PathBuf};

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// Known MCP client applications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum McpClient {
    /// Claude Desktop (Anthropic).
    ClaudeDesktop,
    /// Cursor IDE.
    Cursor,
}

impl McpClient {
    /// Returns the config file path for this client on the current platform.
    pub fn config_path(&self) -> PathBuf {
        let home = dirs::home_dir().expect("cannot determine home directory");
        match self {
            McpClient::ClaudeDesktop => {
                if cfg!(target_os = "macos") {
                    home.join("Library/Application Support/Claude/claude_desktop_config.json")
                } else if cfg!(target_os = "windows") {
                    home.join("AppData/Roaming/Claude/claude_desktop_config.json")
                } else {
                    home.join(".config/claude/claude_desktop_config.json")
                }
            }
            McpClient::Cursor => home.join(".cursor/mcp.json"),
        }
    }

    /// Human-readable name.
    pub fn display_name(&self) -> &'static str {
        match self {
            McpClient::ClaudeDesktop => "Claude Desktop",
            McpClient::Cursor => "Cursor",
        }
    }
}

/// Auto-detect which MCP client is installed by checking config file existence.
pub fn auto_detect_client() -> Option<McpClient> {
    let clients = [McpClient::ClaudeDesktop, McpClient::Cursor];
    let found: Vec<_> = clients
        .iter()
        .filter(|c| c.config_path().exists())
        .copied()
        .collect();

    match found.len() {
        1 => Some(found[0]),
        _ => {
            // Multiple or none — caller should handle
            if found.len() > 1 {
                eprintln!(
                    "Multiple MCP clients detected: {}",
                    found
                        .iter()
                        .map(|c| c.display_name())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                eprintln!("  Specify --client to choose one.");
            }
            None
        }
    }
}

/// An MCP server entry in the client config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerEntry {
    /// The command to run.
    pub command: String,
    /// Command arguments.
    #[serde(default)]
    pub args: Vec<String>,
    /// Preserve any extra fields (env, disabled, etc.).
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Top-level MCP client config. Preserves unknown fields during roundtrip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpClientConfig {
    /// MCP server definitions.
    #[serde(rename = "mcpServers", default)]
    pub mcp_servers: IndexMap<String, McpServerEntry>,
    /// Preserve any extra top-level fields (preferences, etc.).
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl McpClientConfig {
    /// Parse from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize to pretty-printed JSON.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Returns true if the server entry is already wrapped by Kvlar.
pub fn is_kvlar_wrapped(entry: &McpServerEntry) -> bool {
    // Check if command ends with "kvlar" or "kvlar-cli" (handles full paths too)
    let cmd = Path::new(&entry.command)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(&entry.command);
    cmd == "kvlar" || cmd == "kvlar-cli"
}

/// Wrap an MCP server entry to run through Kvlar.
pub fn wrap_entry(entry: &McpServerEntry, kvlar_bin: &str, policy_path: &Path) -> McpServerEntry {
    let policy_str = policy_path.to_string_lossy().to_string();

    let mut new_args = vec![
        "proxy".to_string(),
        "--stdio".to_string(),
        "--policy".to_string(),
        policy_str,
        "--".to_string(),
        entry.command.clone(),
    ];
    new_args.extend(entry.args.clone());

    McpServerEntry {
        command: kvlar_bin.to_string(),
        args: new_args,
        extra: entry.extra.clone(),
    }
}

/// Unwrap a Kvlar-wrapped entry, restoring the original command.
/// Returns None if the entry doesn't look like a Kvlar wrap.
pub fn unwrap_entry(entry: &McpServerEntry) -> Option<McpServerEntry> {
    if !is_kvlar_wrapped(entry) {
        return None;
    }

    // Find the "--" separator in args
    let separator_idx = entry.args.iter().position(|a| a == "--")?;

    // Everything after "--" is [original_command, ...original_args]
    let after_separator = &entry.args[separator_idx + 1..];
    if after_separator.is_empty() {
        return None;
    }

    Some(McpServerEntry {
        command: after_separator[0].clone(),
        args: after_separator[1..].to_vec(),
        extra: entry.extra.clone(),
    })
}

/// Default Kvlar directory (~/.kvlar/).
pub fn default_kvlar_dir() -> PathBuf {
    dirs::home_dir()
        .expect("cannot determine home directory")
        .join(".kvlar")
}

/// Default policy file path (~/.kvlar/policy.yaml).
pub fn default_policy_path() -> PathBuf {
    default_kvlar_dir().join("policy.yaml")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mcp_config_roundtrip() {
        let json = r#"{
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
                },
                "github": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                    "env": {
                        "GITHUB_TOKEN": "ghp_test123"
                    }
                }
            },
            "preferences": {
                "theme": "dark"
            }
        }"#;

        let config = McpClientConfig::from_json(json).unwrap();
        assert_eq!(config.mcp_servers.len(), 2);

        // Verify server order is preserved
        let keys: Vec<_> = config.mcp_servers.keys().collect();
        assert_eq!(keys, vec!["filesystem", "github"]);

        // Verify extra fields preserved
        assert!(config.extra.contains_key("preferences"));

        // Verify env preserved on github entry
        let github = &config.mcp_servers["github"];
        assert!(github.extra.contains_key("env"));

        // Roundtrip
        let out = config.to_json_pretty().unwrap();
        let reparsed = McpClientConfig::from_json(&out).unwrap();
        assert_eq!(reparsed.mcp_servers.len(), 2);
        assert!(reparsed.extra.contains_key("preferences"));
    }

    #[test]
    fn test_wrap_entry() {
        let entry = McpServerEntry {
            command: "npx".into(),
            args: vec![
                "-y".into(),
                "@modelcontextprotocol/server-filesystem".into(),
                "/tmp".into(),
            ],
            extra: serde_json::Map::new(),
        };

        let wrapped = wrap_entry(
            &entry,
            "/usr/local/bin/kvlar",
            Path::new("/home/user/.kvlar/policy.yaml"),
        );
        assert_eq!(wrapped.command, "/usr/local/bin/kvlar");
        assert_eq!(
            wrapped.args,
            vec![
                "proxy",
                "--stdio",
                "--policy",
                "/home/user/.kvlar/policy.yaml",
                "--",
                "npx",
                "-y",
                "@modelcontextprotocol/server-filesystem",
                "/tmp"
            ]
        );
    }

    #[test]
    fn test_unwrap_entry() {
        let wrapped = McpServerEntry {
            command: "/usr/local/bin/kvlar".into(),
            args: vec![
                "proxy".into(),
                "--stdio".into(),
                "--policy".into(),
                "/home/user/.kvlar/policy.yaml".into(),
                "--".into(),
                "npx".into(),
                "-y".into(),
                "@modelcontextprotocol/server-filesystem".into(),
                "/tmp".into(),
            ],
            extra: serde_json::Map::new(),
        };

        let original = unwrap_entry(&wrapped).unwrap();
        assert_eq!(original.command, "npx");
        assert_eq!(
            original.args,
            vec!["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
        );
    }

    #[test]
    fn test_already_wrapped_detection() {
        let wrapped = McpServerEntry {
            command: "/usr/local/bin/kvlar".into(),
            args: vec!["proxy".into()],
            extra: serde_json::Map::new(),
        };
        assert!(is_kvlar_wrapped(&wrapped));

        let wrapped_cli = McpServerEntry {
            command: "kvlar-cli".into(),
            args: vec!["proxy".into()],
            extra: serde_json::Map::new(),
        };
        assert!(is_kvlar_wrapped(&wrapped_cli));

        let not_wrapped = McpServerEntry {
            command: "npx".into(),
            args: vec!["-y".into(), "some-server".into()],
            extra: serde_json::Map::new(),
        };
        assert!(!is_kvlar_wrapped(&not_wrapped));
    }

    #[test]
    fn test_wrap_preserves_env() {
        let mut extra = serde_json::Map::new();
        extra.insert("env".into(), serde_json::json!({"API_KEY": "secret123"}));

        let entry = McpServerEntry {
            command: "npx".into(),
            args: vec!["server".into()],
            extra,
        };

        let wrapped = wrap_entry(&entry, "kvlar", Path::new("/policy.yaml"));
        assert!(wrapped.extra.contains_key("env"));
        assert_eq!(
            wrapped.extra["env"]["API_KEY"].as_str().unwrap(),
            "secret123"
        );

        // Unwrap also preserves env
        let unwrapped = unwrap_entry(&wrapped).unwrap();
        assert!(unwrapped.extra.contains_key("env"));
    }
}
