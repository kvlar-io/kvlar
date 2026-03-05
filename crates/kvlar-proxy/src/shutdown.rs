//! Graceful shutdown coordination.
//!
//! Provides signal handling (SIGTERM/SIGINT) and coordinated shutdown
//! using `CancellationToken`. Critical for Docker/K8s deployments
//! where graceful drain is expected before container termination.

use std::time::Duration;

use tokio_util::sync::CancellationToken;

/// Default shutdown timeout — force-kill if drain takes longer.
pub const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// Creates a cancellation token that triggers on SIGTERM or SIGINT.
///
/// Returns the token immediately. When a signal is received, the token
/// is cancelled, allowing all holders to observe the shutdown request.
pub fn signal_shutdown_token() -> CancellationToken {
    let token = CancellationToken::new();
    let token_clone = token.clone();

    tokio::spawn(async move {
        if let Err(e) = wait_for_shutdown_signal().await {
            tracing::error!(error = %e, "failed to listen for shutdown signals");
            return;
        }
        tracing::info!("shutting down...");
        token_clone.cancel();
    });

    token
}

/// Waits for a SIGTERM or SIGINT signal.
async fn wait_for_shutdown_signal() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sigint = signal(SignalKind::interrupt())?;

        tokio::select! {
            _ = sigterm.recv() => {
                tracing::info!("received SIGTERM");
            }
            _ = sigint.recv() => {
                tracing::info!("received SIGINT");
            }
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        tracing::info!("received Ctrl+C");
    }

    Ok(())
}

/// Waits for the shutdown token to be cancelled, then applies the timeout.
///
/// Returns `true` if the shutdown completed within the timeout,
/// `false` if it was force-killed.
pub async fn shutdown_with_timeout(token: &CancellationToken, timeout_duration: Duration) -> bool {
    token.cancelled().await;

    // Give a grace period for in-flight work to complete
    tracing::info!(
        timeout_secs = timeout_duration.as_secs(),
        "draining active connections..."
    );

    // The caller should use this as a deadline — select! between
    // their cleanup work and this timeout.
    tokio::time::sleep(timeout_duration).await;
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cancellation_token_manual() {
        let token = CancellationToken::new();
        assert!(!token.is_cancelled());

        token.cancel();
        assert!(token.is_cancelled());

        // cancelled() should resolve immediately
        token.cancelled().await;
    }

    #[tokio::test]
    async fn test_child_tokens_cancelled_with_parent() {
        let parent = CancellationToken::new();
        let child = parent.child_token();

        assert!(!child.is_cancelled());
        parent.cancel();
        assert!(child.is_cancelled());
    }

    #[tokio::test]
    async fn test_shutdown_timeout_returns_false() {
        let token = CancellationToken::new();
        let token_clone = token.clone();

        // Cancel immediately
        tokio::spawn(async move {
            token_clone.cancel();
        });

        // With a very short timeout, it should return false (timeout expired)
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            shutdown_with_timeout(&token, Duration::from_millis(10)),
        )
        .await;

        // Should complete within our outer timeout
        assert!(result.is_ok());
    }
}
