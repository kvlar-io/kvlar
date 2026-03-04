//! # kvlar-cli
//!
//! Command-line interface for Kvlar — validate policies, evaluate actions,
//! inspect rules, export schemas, and run the MCP security proxy.

mod client_config;

use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};

use client_config::McpClient;

/// Kvlar — Bulletproof security for AI agents.
#[derive(Parser)]
#[command(name = "kvlar", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate a policy YAML file or directory.
    Validate {
        /// Path to the policy YAML file or directory.
        #[arg(short, long)]
        policy: PathBuf,
    },

    /// Evaluate an action against a policy (for testing).
    Evaluate {
        /// Path to the policy YAML file.
        #[arg(short, long)]
        policy: PathBuf,

        /// Action type (e.g., "tool_call").
        #[arg(long)]
        action_type: String,

        /// Resource (e.g., "bash", "send_email").
        #[arg(long)]
        resource: String,

        /// Agent ID.
        #[arg(long, default_value = "cli-test")]
        agent_id: String,
    },

    /// Show policy summary (rules, effects).
    Inspect {
        /// Path to the policy YAML file.
        #[arg(short, long)]
        policy: PathBuf,
    },

    /// Export the JSON Schema for policy validation.
    Schema {
        /// Output file (default: stdout).
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Start the MCP security proxy.
    Proxy {
        /// Path to the proxy configuration YAML file.
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Listen address (overrides config). TCP mode only.
        #[arg(long)]
        listen: Option<String>,

        /// Upstream MCP server address (overrides config). TCP mode only.
        #[arg(long)]
        upstream: Option<String>,

        /// Policy file path (overrides config, can be repeated).
        #[arg(long)]
        policy: Vec<PathBuf>,

        /// Use stdio transport (newline-delimited JSON over stdin/stdout).
        /// In this mode, Kvlar spawns the upstream MCP server as a child process.
        /// Pass the upstream command after `--`:
        ///   kvlar proxy --stdio --policy policy.yaml -- npx server-name
        #[arg(long)]
        stdio: bool,

        /// Upstream MCP server command and arguments (everything after `--`).
        /// Only used with --stdio.
        #[arg(last = true)]
        upstream_cmd: Vec<String>,
    },

    /// Initialize Kvlar — create a starter policy file.
    Init {
        /// Directory to initialize (default: ~/.kvlar/).
        #[arg(short, long)]
        dir: Option<PathBuf>,

        /// Policy template: default, strict, permissive, filesystem,
        /// postgres, github, slack, shell.
        #[arg(long, default_value = "default")]
        template: String,
    },

    /// Wrap existing MCP servers with Kvlar security proxy.
    ///
    /// Reads your MCP client config, wraps each server so tool calls
    /// go through Kvlar's policy engine, and writes the config back.
    Wrap {
        /// Which MCP client to wrap (auto-detects if omitted).
        #[arg(long, value_enum)]
        client: Option<McpClient>,

        /// Path to the policy file (default: ~/.kvlar/policy.yaml).
        #[arg(long)]
        policy: Option<PathBuf>,

        /// Wrap only these servers (by name).
        #[arg(long)]
        only: Vec<String>,

        /// Skip these servers (by name).
        #[arg(long)]
        skip: Vec<String>,

        /// Show what would change without writing.
        #[arg(long)]
        dry_run: bool,
    },

    /// Unwrap MCP servers — remove Kvlar proxy wrapping.
    Unwrap {
        /// Which MCP client to unwrap (auto-detects if omitted).
        #[arg(long, value_enum)]
        client: Option<McpClient>,

        /// Unwrap only these servers (by name).
        #[arg(long)]
        only: Vec<String>,

        /// Show what would change without writing.
        #[arg(long)]
        dry_run: bool,
    },

    /// Run policy tests from a test file.
    ///
    /// Validates your security policy by running test cases that define
    /// actions and expected outcomes (allow/deny/require_approval).
    Test {
        /// Path to the test file (.test.yaml).
        #[arg(short = 'f', long = "file")]
        file: PathBuf,

        /// Path to the policy file (overrides the `policy` field in test file).
        #[arg(short, long)]
        policy: Option<PathBuf>,

        /// Output results as JSON (for CI integration).
        #[arg(long)]
        json: bool,

        /// Show verbose output (print all tests, not just failures).
        #[arg(short, long)]
        verbose: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Validate { policy } => cmd_validate(&policy),
        Commands::Evaluate {
            policy,
            action_type,
            resource,
            agent_id,
        } => cmd_evaluate(&policy, &action_type, &resource, &agent_id),
        Commands::Inspect { policy } => cmd_inspect(&policy),
        Commands::Schema { output } => cmd_schema(output.as_deref()),
        Commands::Proxy {
            config,
            listen,
            upstream,
            policy,
            stdio,
            upstream_cmd,
        } => cmd_proxy(
            config.as_deref(),
            listen,
            upstream,
            policy,
            stdio,
            upstream_cmd,
        ),
        Commands::Init { dir, template } => cmd_init(dir, &template),
        Commands::Wrap {
            client,
            policy,
            only,
            skip,
            dry_run,
        } => cmd_wrap(client, policy, only, skip, dry_run),
        Commands::Unwrap {
            client,
            only,
            dry_run,
        } => cmd_unwrap(client, only, dry_run),
        Commands::Test {
            file,
            policy,
            json,
            verbose,
        } => cmd_test(&file, policy.as_deref(), json, verbose),
    }
}

fn cmd_validate(policy_path: &std::path::Path) {
    if policy_path.is_dir() {
        match kvlar_core::Policy::from_dir(policy_path) {
            Ok(policies) => {
                if policies.is_empty() {
                    eprintln!(
                        "⚠ No .yaml or .yml files found in {}",
                        policy_path.display()
                    );
                    process::exit(1);
                }
                for policy in &policies {
                    println!(
                        "✓ Policy '{}' is valid ({} rules)",
                        policy.name,
                        policy.rules.len()
                    );
                }
                println!("  {} policies validated", policies.len());
            }
            Err(e) => {
                eprintln!("✗ Validation failed: {}", e);
                process::exit(1);
            }
        }
    } else {
        match kvlar_core::Policy::from_file(policy_path) {
            Ok(mut policy) => {
                resolve_policy_extends(&mut policy);
                println!("✓ Policy '{}' is valid", policy.name);
                println!("  Version: {}", policy.version);
                println!("  Rules: {}", policy.rules.len());
            }
            Err(e) => {
                eprintln!("✗ Invalid policy: {}", e);
                process::exit(1);
            }
        }
    }
}

fn cmd_evaluate(policy_path: &std::path::Path, action_type: &str, resource: &str, agent_id: &str) {
    let mut policy = match kvlar_core::Policy::from_file(policy_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("✗ Failed to load policy: {}", e);
            process::exit(1);
        }
    };
    resolve_policy_extends(&mut policy);

    let mut engine = kvlar_core::Engine::new();
    engine.load_policy(policy);

    let action = kvlar_core::Action::new(action_type, resource, agent_id);
    let decision = engine.evaluate(&action);

    match &decision {
        kvlar_core::Decision::Allow { matched_rule } => {
            println!("✓ ALLOW (rule: {})", matched_rule);
        }
        kvlar_core::Decision::Deny {
            reason,
            matched_rule,
        } => {
            println!("✗ DENY (rule: {})", matched_rule);
            println!("  Reason: {}", reason);
        }
        kvlar_core::Decision::RequireApproval {
            reason,
            matched_rule,
        } => {
            println!("⚠ REQUIRE APPROVAL (rule: {})", matched_rule);
            println!("  Reason: {}", reason);
        }
    }
}

fn cmd_inspect(policy_path: &std::path::Path) {
    let mut policy = match kvlar_core::Policy::from_file(policy_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("✗ Invalid policy: {}", e);
            process::exit(1);
        }
    };
    resolve_policy_extends(&mut policy);

    println!("Policy: {}", policy.name);
    println!("Description: {}", policy.description);
    println!("Version: {}", policy.version);
    println!("Rules ({}):", policy.rules.len());
    for rule in &policy.rules {
        let effect_label = match &rule.effect {
            kvlar_core::policy::Effect::Allow => "ALLOW".to_string(),
            kvlar_core::policy::Effect::Deny { reason } => {
                format!("DENY — {}", reason)
            }
            kvlar_core::policy::Effect::RequireApproval { reason } => {
                format!("APPROVE — {}", reason)
            }
        };
        println!("  [{}] {} → {}", rule.id, rule.description, effect_label);
    }
}

fn cmd_schema(output: Option<&std::path::Path>) {
    let schema = match kvlar_core::Policy::json_schema_string() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("✗ Failed to generate schema: {}", e);
            process::exit(1);
        }
    };

    match output {
        Some(path) => {
            if let Err(e) = std::fs::write(path, &schema) {
                eprintln!("✗ Failed to write schema to {}: {}", path.display(), e);
                process::exit(1);
            }
            println!("✓ JSON Schema written to {}", path.display());
        }
        None => {
            println!("{}", schema);
        }
    }
}

fn cmd_proxy(
    config_path: Option<&std::path::Path>,
    listen: Option<String>,
    upstream: Option<String>,
    policy_paths: Vec<PathBuf>,
    stdio: bool,
    upstream_cmd: Vec<String>,
) {
    // Load config
    let mut config = match config_path {
        Some(path) => match kvlar_proxy::ProxyConfig::from_file(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("✗ Failed to load config from {}: {}", path.display(), e);
                process::exit(1);
            }
        },
        None => kvlar_proxy::ProxyConfig::default(),
    };

    // Apply CLI overrides
    if let Some(addr) = listen {
        config.listen_addr = addr;
    }
    if let Some(addr) = upstream {
        config.upstream_addr = addr;
    }
    if !policy_paths.is_empty() {
        config.policy_paths = policy_paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
    }

    // Apply stdio mode from CLI flag
    if stdio {
        config.transport = kvlar_proxy::config::TransportMode::Stdio;
        if let Some((cmd, args)) = upstream_cmd.split_first() {
            config.upstream_command = Some(cmd.clone());
            config.upstream_args = args.to_vec();
        }
    }

    // Validate stdio mode has a command
    if matches!(config.transport, kvlar_proxy::config::TransportMode::Stdio)
        && config.upstream_command.is_none()
    {
        eprintln!("✗ Stdio mode requires an upstream command.");
        eprintln!("  Usage: kvlar proxy --stdio --policy policy.yaml -- <command> [args...]");
        process::exit(1);
    }

    // In stdio mode, all user-facing output MUST go to stderr.
    // Stdout is reserved exclusively for MCP JSON-RPC messages.
    let use_stderr = matches!(config.transport, kvlar_proxy::config::TransportMode::Stdio);

    // Load policies
    let mut engine = kvlar_core::Engine::new();
    for path_str in &config.policy_paths {
        let path = std::path::Path::new(path_str);
        match kvlar_core::Policy::from_file(path) {
            Ok(mut policy) => {
                resolve_policy_extends(&mut policy);
                eprintln!(
                    "  Loaded policy '{}' ({} rules)",
                    policy.name,
                    policy.rules.len()
                );
                engine.load_policy(policy);
            }
            Err(e) => {
                eprintln!("✗ Failed to load policy {}: {}", path_str, e);
                process::exit(1);
            }
        }
    }

    eprintln!(
        "✓ Loaded {} policies ({} rules total)",
        engine.policy_count(),
        engine.rule_count()
    );

    // Initialize tracing — always to stderr (safe for both modes)
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let rt = tokio::runtime::Runtime::new().unwrap();

    if use_stderr {
        // Stdio mode
        let command = config.upstream_command.clone().unwrap();
        let args = config.upstream_args.clone();
        let fail_open = config.fail_open;

        eprintln!("  Stdio mode: {} {}", command, args.join(" "));

        let transport = kvlar_proxy::stdio::StdioTransport::new(
            engine,
            kvlar_audit::AuditLogger::default(),
            command,
            args,
            fail_open,
        );
        if let Err(e) = rt.block_on(transport.run()) {
            eprintln!("✗ Proxy error: {}", e);
            process::exit(1);
        }
    } else {
        // TCP mode
        eprintln!(
            "  Listening on {} → upstream {}",
            config.listen_addr, config.upstream_addr
        );

        let proxy = kvlar_proxy::proxy::McpProxy::new(engine, config);
        if let Err(e) = rt.block_on(proxy.run()) {
            eprintln!("✗ Proxy error: {}", e);
            process::exit(1);
        }
    }
}

fn policy_template(name: &str) -> Option<&'static str> {
    match name {
        "default" => Some(include_str!("../policies/default.yaml")),
        "strict" => Some(include_str!("../policies/strict.yaml")),
        "permissive" => Some(include_str!("../policies/permissive.yaml")),
        "filesystem" => Some(include_str!("../policies/filesystem-demo.yaml")),
        "postgres" => Some(include_str!("../policies/postgres.yaml")),
        "github" => Some(include_str!("../policies/github.yaml")),
        "slack" => Some(include_str!("../policies/slack.yaml")),
        "shell" => Some(include_str!("../policies/shell.yaml")),
        _ => None,
    }
}

/// Returns all available built-in template names.
pub fn template_names() -> &'static [&'static str] {
    &[
        "default",
        "strict",
        "permissive",
        "filesystem",
        "postgres",
        "github",
        "slack",
        "shell",
    ]
}

/// Resolves `extends` directives in a policy.
/// Looks up built-in templates first, then tries file paths.
fn resolve_policy_extends(policy: &mut kvlar_core::Policy) {
    if let Err(e) = policy.resolve_extends(&|name| {
        // Try built-in template first
        if let Some(yaml) = policy_template(name) {
            return Ok(yaml.to_string());
        }
        // Try as file path
        let path = std::path::Path::new(name);
        if path.exists() {
            return std::fs::read_to_string(path).map_err(|e| {
                kvlar_core::KvlarError::PolicyParse(format!("failed to read {}: {}", name, e))
            });
        }
        Err(kvlar_core::KvlarError::PolicyParse(format!(
            "unknown policy '{}' in extends — not a built-in template ({}) and not a file path",
            name,
            template_names().join(", ")
        )))
    }) {
        eprintln!("✗ Failed to resolve policy extends: {}", e);
        process::exit(1);
    }
}

fn cmd_init(dir: Option<PathBuf>, template: &str) {
    let target_dir = dir.unwrap_or_else(client_config::default_kvlar_dir);
    let policy_path = target_dir.join("policy.yaml");

    // Get template content
    let content = match policy_template(template) {
        Some(c) => c,
        None => {
            eprintln!(
                "✗ Unknown template '{}'. Available: {}",
                template,
                template_names().join(", ")
            );
            process::exit(1);
        }
    };

    // Check if already exists
    if policy_path.exists() {
        eprintln!("✗ Policy file already exists at {}", policy_path.display());
        eprintln!("  Delete it first or use --dir to choose a different location.");
        process::exit(1);
    }

    // Create directory
    if let Err(e) = std::fs::create_dir_all(&target_dir) {
        eprintln!(
            "✗ Failed to create directory {}: {}",
            target_dir.display(),
            e
        );
        process::exit(1);
    }

    // Write policy
    if let Err(e) = std::fs::write(&policy_path, content) {
        eprintln!("✗ Failed to write policy: {}", e);
        process::exit(1);
    }

    // Count rules in the template
    let rule_count = content.matches("  - id:").count();

    println!(
        "✓ Created {} ({} template, {} rules)",
        policy_path.display(),
        template,
        rule_count
    );
    println!();
    println!("Next steps:");
    println!(
        "  1. Review your policy:      vim {}",
        policy_path.display()
    );
    println!("  2. Secure your MCP servers: kvlar wrap");
}

fn cmd_wrap(
    client: Option<McpClient>,
    policy: Option<PathBuf>,
    only: Vec<String>,
    skip: Vec<String>,
    dry_run: bool,
) {
    // Resolve policy path
    let policy_path = policy.unwrap_or_else(client_config::default_policy_path);
    if !policy_path.exists() {
        eprintln!("✗ Policy file not found at {}", policy_path.display());
        eprintln!("  Run `kvlar init` to create a starter policy, or specify --policy <path>.");
        process::exit(1);
    }

    // Get absolute policy path (MCP clients launch from unknown cwd)
    let abs_policy = match policy_path.canonicalize() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("✗ Cannot resolve policy path: {}", e);
            process::exit(1);
        }
    };

    // Get kvlar binary path
    let kvlar_bin = match std::env::current_exe() {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(_) => {
            eprintln!("✗ Cannot determine kvlar binary path.");
            process::exit(1);
        }
    };

    // Determine client
    let client = match client {
        Some(c) => c,
        None => match client_config::auto_detect_client() {
            Some(c) => c,
            None => {
                eprintln!("✗ No MCP client config found.");
                eprintln!("  Specify --client (claude-desktop or cursor).");
                process::exit(1);
            }
        },
    };

    let config_path = client.config_path();
    if !config_path.exists() {
        eprintln!(
            "✗ {} config not found at {}",
            client.display_name(),
            config_path.display()
        );
        process::exit(1);
    }

    println!("Detected {} config", client.display_name());

    // Read config
    let config_str = match std::fs::read_to_string(&config_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("✗ Failed to read config: {}", e);
            process::exit(1);
        }
    };

    let mut config = match client_config::McpClientConfig::from_json(&config_str) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("✗ Failed to parse config: {}", e);
            process::exit(1);
        }
    };

    if config.mcp_servers.is_empty() {
        println!("  No MCP servers found in config. Nothing to wrap.");
        return;
    }

    // Back up config
    if !dry_run {
        let backup_path = config_path.with_extension("pre-kvlar.json");
        if let Err(e) = std::fs::copy(&config_path, &backup_path) {
            eprintln!("✗ Failed to create backup: {}", e);
            process::exit(1);
        }
        println!("Backed up to {}", backup_path.display());
    }

    // Wrap servers
    let mut wrapped_count = 0;
    let total = config.mcp_servers.len();
    let server_names: Vec<String> = config.mcp_servers.keys().cloned().collect();

    for name in &server_names {
        // Filter
        if !only.is_empty() && !only.contains(name) {
            continue;
        }
        if skip.contains(name) {
            continue;
        }

        let entry = &config.mcp_servers[name];

        if client_config::is_kvlar_wrapped(entry) {
            println!("  ~ {}: already wrapped, skipping", name);
            continue;
        }

        let orig_cmd = format!("{} {}", entry.command, entry.args.join(" "));
        let wrapped = client_config::wrap_entry(entry, &kvlar_bin, &abs_policy);

        if dry_run {
            println!("  Would wrap {}: {}", name, orig_cmd);
        } else {
            config.mcp_servers[name] = wrapped;
            println!("  ✓ {}: wrapped ({})", name, orig_cmd);
        }
        wrapped_count += 1;
    }

    if dry_run {
        println!();
        println!("Dry run complete. Run without --dry-run to apply changes.");
        return;
    }

    // Write modified config
    let output = match config.to_json_pretty() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("✗ Failed to serialize config: {}", e);
            process::exit(1);
        }
    };

    if let Err(e) = std::fs::write(&config_path, format!("{}\n", output)) {
        eprintln!("✗ Failed to write config: {}", e);
        process::exit(1);
    }

    println!(
        "✓ Wrapped {}/{} servers. Restart {} to apply.",
        wrapped_count,
        total,
        client.display_name()
    );
}

fn cmd_unwrap(client: Option<McpClient>, only: Vec<String>, dry_run: bool) {
    // Determine client
    let client = match client {
        Some(c) => c,
        None => match client_config::auto_detect_client() {
            Some(c) => c,
            None => {
                eprintln!("✗ No MCP client config found.");
                eprintln!("  Specify --client (claude-desktop or cursor).");
                process::exit(1);
            }
        },
    };

    let config_path = client.config_path();
    if !config_path.exists() {
        eprintln!(
            "✗ {} config not found at {}",
            client.display_name(),
            config_path.display()
        );
        process::exit(1);
    }

    println!("Detected {} config", client.display_name());

    // Read config
    let config_str = match std::fs::read_to_string(&config_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("✗ Failed to read config: {}", e);
            process::exit(1);
        }
    };

    let mut config = match client_config::McpClientConfig::from_json(&config_str) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("✗ Failed to parse config: {}", e);
            process::exit(1);
        }
    };

    // Back up config
    if !dry_run {
        let backup_path = config_path.with_extension("pre-unwrap.json");
        if let Err(e) = std::fs::copy(&config_path, &backup_path) {
            eprintln!("✗ Failed to create backup: {}", e);
            process::exit(1);
        }
        println!("Backed up to {}", backup_path.display());
    }

    // Unwrap servers
    let mut unwrapped_count = 0;
    let total = config.mcp_servers.len();
    let server_names: Vec<String> = config.mcp_servers.keys().cloned().collect();

    for name in &server_names {
        if !only.is_empty() && !only.contains(name) {
            continue;
        }

        let entry = &config.mcp_servers[name];

        if !client_config::is_kvlar_wrapped(entry) {
            println!("  ~ {}: not wrapped, skipping", name);
            continue;
        }

        match client_config::unwrap_entry(entry) {
            Some(original) => {
                let restored_cmd = format!("{} {}", original.command, original.args.join(" "));
                if dry_run {
                    println!("  Would unwrap {}: restore {}", name, restored_cmd);
                } else {
                    config.mcp_servers[name] = original;
                    println!("  ✓ {}: unwrapped (restored {})", name, restored_cmd);
                }
                unwrapped_count += 1;
            }
            None => {
                eprintln!("  ✗ {}: wrapped but cannot extract original command", name);
            }
        }
    }

    if dry_run {
        println!();
        println!("Dry run complete. Run without --dry-run to apply changes.");
        return;
    }

    // Write modified config
    let output = match config.to_json_pretty() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("✗ Failed to serialize config: {}", e);
            process::exit(1);
        }
    };

    if let Err(e) = std::fs::write(&config_path, format!("{}\n", output)) {
        eprintln!("✗ Failed to write config: {}", e);
        process::exit(1);
    }

    println!(
        "✓ Unwrapped {}/{} servers. Restart {} to apply.",
        unwrapped_count,
        total,
        client.display_name()
    );
}

fn cmd_test(
    file: &std::path::Path,
    policy_override: Option<&std::path::Path>,
    json: bool,
    verbose: bool,
) {
    // Read and parse test file
    let test_yaml = match std::fs::read_to_string(file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("✗ Failed to read test file {}: {}", file.display(), e);
            process::exit(1);
        }
    };

    let suite: kvlar_core::testing::TestSuite = match serde_yaml::from_str(&test_yaml) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("✗ Failed to parse test file: {}", e);
            process::exit(1);
        }
    };

    // Resolve policy path: CLI --policy > test file's policy field > error
    let test_dir = file.parent().unwrap_or(std::path::Path::new("."));
    let policy_path = if let Some(p) = policy_override {
        p.to_path_buf()
    } else if let Some(ref p) = suite.policy {
        let candidate = std::path::PathBuf::from(p);
        if candidate.is_absolute() {
            candidate
        } else {
            test_dir.join(candidate)
        }
    } else {
        eprintln!("✗ No policy specified. Use --policy or set `policy:` in the test file.");
        process::exit(1);
    };

    // Load policy
    let mut policy = match kvlar_core::Policy::from_file(&policy_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("✗ Failed to load policy {}: {}", policy_path.display(), e);
            process::exit(1);
        }
    };
    resolve_policy_extends(&mut policy);

    // Build engine and run suite
    let mut engine = kvlar_core::Engine::new();
    engine.load_policy(policy);
    let result = kvlar_core::testing::run_test_suite(&engine, &suite);

    // Output
    if json {
        match serde_json::to_string_pretty(&result) {
            Ok(s) => println!("{}", s),
            Err(e) => {
                eprintln!("✗ Failed to serialize results: {}", e);
                process::exit(1);
            }
        }
    } else {
        println!(
            "Running {} tests from {}...\n",
            result.total,
            file.display()
        );
        for r in &result.results {
            if r.passed {
                if verbose {
                    println!("  ✓ {} ({})", r.id, r.actual_decision);
                }
            } else {
                println!("  ✗ {}", r.id);
                for f in &r.failures {
                    println!("    → {}", f);
                }
            }
        }
        println!();
        if result.failed == 0 {
            println!("✓ {}/{} tests passed.", result.passed, result.total);
        } else {
            println!("✗ {}/{} tests failed.", result.failed, result.total);
        }
    }

    if result.failed > 0 {
        process::exit(1);
    }
}
