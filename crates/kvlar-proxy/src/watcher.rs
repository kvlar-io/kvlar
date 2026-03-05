//! Policy hot-reload via filesystem watcher.
//!
//! Watches policy files for changes and atomically swaps the engine
//! when valid new policies are detected. Uses `notify` for cross-platform
//! filesystem watching with debouncing.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kvlar_core::{Engine, Policy};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::{RwLock, mpsc};
use tokio::time::sleep;

/// Callback type for resolving `extends` directives in policies.
///
/// Takes a template/file name and returns the YAML string content.
/// This keeps kvlar-core pure (no I/O) — the caller provides the resolver.
pub type ExtendsResolver =
    Arc<dyn Fn(&str) -> Result<String, kvlar_core::KvlarError> + Send + Sync>;

/// Spawns a filesystem watcher task that reloads policies on change.
///
/// Returns a `JoinHandle` for the watcher task and the underlying
/// `RecommendedWatcher` (which must be kept alive for watching to continue).
///
/// # Arguments
///
/// * `engine` — Shared engine to swap on successful reload
/// * `policy_paths` — Paths to policy YAML files to watch
/// * `extends_resolver` — Optional callback to resolve `extends` directives
///
/// # Behavior
///
/// - Debounces filesystem events (300ms) to coalesce rapid saves
/// - On change: re-reads all policy files, builds a new engine, swaps atomically
/// - On parse error: logs the error to stderr, keeps the previous valid engine
/// - All output goes to stderr (safe for stdio proxy mode)
pub fn spawn_watcher(
    engine: Arc<RwLock<Engine>>,
    policy_paths: Vec<PathBuf>,
    extends_resolver: Option<ExtendsResolver>,
) -> Result<(tokio::task::JoinHandle<()>, RecommendedWatcher), Box<dyn std::error::Error>> {
    let (tx, mut rx) = mpsc::channel::<()>(16);

    // Set up the filesystem watcher
    let mut watcher = notify::recommended_watcher(move |result: Result<Event, notify::Error>| {
        match result {
            Ok(event) => {
                if matches!(
                    event.kind,
                    EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
                ) {
                    // Signal the reload task (non-blocking, drop if channel full)
                    let _ = tx.try_send(());
                }
            }
            Err(e) => {
                eprintln!("  [kvlar] watch error: {}", e);
            }
        }
    })?;

    // Watch each policy file's parent directory (to catch renames/recreations)
    for path in &policy_paths {
        let watch_path = if path.is_file() {
            path.parent().unwrap_or(Path::new("."))
        } else {
            path.as_path()
        };
        watcher.watch(watch_path, RecursiveMode::NonRecursive)?;
    }

    let paths = policy_paths.clone();
    eprintln!(
        "  [kvlar] watching {} policy file(s) for changes",
        paths.len()
    );

    // Spawn the reload task
    let handle = tokio::spawn(async move {
        loop {
            // Wait for a change signal
            if rx.recv().await.is_none() {
                break; // Channel closed, watcher dropped
            }

            // Debounce: drain any additional signals within 300ms
            sleep(Duration::from_millis(300)).await;
            while rx.try_recv().is_ok() {}

            // Reload all policies
            eprintln!("  [kvlar] policy change detected, reloading...");
            match reload_policies(&paths, extends_resolver.as_ref()) {
                Ok(new_engine) => {
                    let rule_count = new_engine.rule_count();
                    let policy_count = new_engine.policy_count();
                    let mut eng = engine.write().await;
                    *eng = new_engine;
                    drop(eng);
                    eprintln!(
                        "  [kvlar] ✓ reloaded {} policies ({} rules)",
                        policy_count, rule_count
                    );
                }
                Err(e) => {
                    eprintln!("  [kvlar] ✗ reload failed, keeping previous policy: {}", e);
                }
            }
        }
    });

    Ok((handle, watcher))
}

/// Reads all policy files and builds a new engine.
///
/// If any file fails to parse, returns an error — the caller should
/// keep the previous engine (fail-safe).
fn reload_policies(
    paths: &[PathBuf],
    extends_resolver: Option<&ExtendsResolver>,
) -> Result<Engine, String> {
    let mut engine = Engine::new();

    for path in paths {
        let mut policy = Policy::from_file(path)
            .map_err(|e| format!("failed to load {}: {}", path.display(), e))?;

        // Resolve extends if a resolver is provided
        if let Some(resolver) = extends_resolver {
            policy
                .resolve_extends(&|name| resolver(name))
                .map_err(|e| format!("failed to resolve extends in {}: {}", path.display(), e))?;
        }

        engine.load_policy(policy);
    }

    Ok(engine)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Helper: create a policy file with given content.
    fn write_policy(dir: &Path, name: &str, content: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, content).unwrap();
        path
    }

    const POLICY_V1: &str = r#"
name: test-policy
description: Version 1
version: "1"
rules:
  - id: allow-read
    description: Allow reads
    match_on:
      resources: ["read_file"]
    effect:
      type: allow
"#;

    const POLICY_V2: &str = r#"
name: test-policy
description: Version 2
version: "2"
rules:
  - id: allow-read
    description: Allow reads
    match_on:
      resources: ["read_file"]
    effect:
      type: allow
  - id: deny-write
    description: Deny writes
    match_on:
      resources: ["write_file"]
    effect:
      type: deny
      reason: "Write denied"
"#;

    const POLICY_INVALID: &str = r#"
name: broken
this is not valid YAML policy: [[[
"#;

    #[tokio::test]
    async fn test_reload_policies_success() {
        let dir = TempDir::new().unwrap();
        let path = write_policy(dir.path(), "policy.yaml", POLICY_V1);

        let result = reload_policies(&[path], None);
        assert!(result.is_ok());
        let engine = result.unwrap();
        assert_eq!(engine.rule_count(), 1);
    }

    #[tokio::test]
    async fn test_reload_policies_invalid_keeps_error() {
        let dir = TempDir::new().unwrap();
        let path = write_policy(dir.path(), "bad.yaml", POLICY_INVALID);

        let result = reload_policies(&[path], None);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_watcher_detects_change() {
        let dir = TempDir::new().unwrap();
        let path = write_policy(dir.path(), "policy.yaml", POLICY_V1);

        // Create engine with v1
        let mut initial_engine = Engine::new();
        let policy = Policy::from_file(&path).unwrap();
        initial_engine.load_policy(policy);
        assert_eq!(initial_engine.rule_count(), 1);

        let engine = Arc::new(RwLock::new(initial_engine));

        // Start watcher
        let (_handle, _watcher) = spawn_watcher(engine.clone(), vec![path.clone()], None).unwrap();

        // Give watcher time to start
        sleep(Duration::from_millis(100)).await;

        // Write v2 (adds a second rule)
        fs::write(&path, POLICY_V2).unwrap();

        // Wait for debounce + reload (300ms debounce + buffer)
        sleep(Duration::from_millis(800)).await;

        // Engine should now have 2 rules
        let eng = engine.read().await;
        assert_eq!(
            eng.rule_count(),
            2,
            "engine should have reloaded with 2 rules"
        );
    }

    #[tokio::test]
    async fn test_watcher_keeps_old_on_invalid() {
        let dir = TempDir::new().unwrap();
        let path = write_policy(dir.path(), "policy.yaml", POLICY_V1);

        let mut initial_engine = Engine::new();
        let policy = Policy::from_file(&path).unwrap();
        initial_engine.load_policy(policy);

        let engine = Arc::new(RwLock::new(initial_engine));

        let (_handle, _watcher) = spawn_watcher(engine.clone(), vec![path.clone()], None).unwrap();

        sleep(Duration::from_millis(100)).await;

        // Write invalid YAML
        fs::write(&path, POLICY_INVALID).unwrap();

        sleep(Duration::from_millis(800)).await;

        // Engine should still have original 1 rule
        let eng = engine.read().await;
        assert_eq!(
            eng.rule_count(),
            1,
            "engine should keep old policy on parse error"
        );
    }
}
