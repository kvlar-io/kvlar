//! Approval backend trait and implementations.
//!
//! When a policy evaluates to `RequireApproval`, the proxy uses an
//! `ApprovalBackend` to request human approval and await the decision.

use kvlar_core::{ApprovalRequest, ApprovalResponse};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

/// Errors that can occur during the approval process.
#[derive(Debug, thiserror::Error)]
pub enum ApprovalError {
    /// The approval request timed out.
    #[error("approval request timed out after {0:?}")]
    Timeout(Duration),

    /// The approval backend encountered an error.
    #[error("approval backend error: {0}")]
    Backend(String),
}

/// Trait for backends that handle human approval requests.
///
/// Implementations send approval requests to humans (via webhook, Slack,
/// email, CLI prompt, etc.) and await their decisions.
///
/// Uses boxed futures for object safety (`dyn ApprovalBackend`).
pub trait ApprovalBackend: Send + Sync {
    /// Sends an approval request and waits for the human decision.
    ///
    /// Returns the human's decision, or an error if the request
    /// times out or the backend fails.
    fn request_approval(
        &self,
        request: &ApprovalRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ApprovalResponse, ApprovalError>> + Send + '_>>;
}

/// A simple approval backend that always denies. Used as the default
/// when no approval backend is configured — maintains fail-closed behavior.
pub struct DenyAllApprovalBackend;

impl ApprovalBackend for DenyAllApprovalBackend {
    fn request_approval(
        &self,
        _request: &ApprovalRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ApprovalResponse, ApprovalError>> + Send + '_>> {
        Box::pin(async {
            Ok(ApprovalResponse::Denied {
                reason: Some("No approval backend configured — denied by default".into()),
            })
        })
    }
}

/// HTTP webhook approval backend.
///
/// Sends a POST request with the `ApprovalRequest` JSON body to a configured
/// URL and expects the webhook to respond synchronously with an `ApprovalResponse`.
///
/// For asynchronous workflows (Slack, email), the webhook can hold the connection
/// open until a decision is made, or return a denial with instructions.
pub struct WebhookApprovalBackend {
    url: String,
    client: reqwest::Client,
    timeout: Duration,
}

impl WebhookApprovalBackend {
    /// Creates a new webhook backend with the given URL and timeout.
    pub fn new(url: impl Into<String>, timeout: Duration) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .expect("failed to build HTTP client");
        Self {
            url: url.into(),
            client,
            timeout,
        }
    }
}

impl ApprovalBackend for WebhookApprovalBackend {
    fn request_approval(
        &self,
        request: &ApprovalRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ApprovalResponse, ApprovalError>> + Send + '_>> {
        let url = self.url.clone();
        let client = self.client.clone();
        let timeout = self.timeout;
        let request = request.clone();

        Box::pin(async move {
            let resp = client.post(&url).json(&request).send().await.map_err(|e| {
                if e.is_timeout() {
                    ApprovalError::Timeout(timeout)
                } else {
                    ApprovalError::Backend(format!("webhook request failed: {e}"))
                }
            })?;

            if !resp.status().is_success() {
                return Err(ApprovalError::Backend(format!(
                    "webhook returned status {}",
                    resp.status()
                )));
            }

            let approval_response: ApprovalResponse = resp.json().await.map_err(|e| {
                ApprovalError::Backend(format!("failed to parse webhook response: {e}"))
            })?;

            Ok(approval_response)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_deny_all_backend() {
        let backend = DenyAllApprovalBackend;
        let request = ApprovalRequest::new(
            "delete_file",
            serde_json::json!({"path": "/tmp/test"}),
            "approve-delete",
            "Deletion requires approval",
            "agent-1",
        );
        let response = backend.request_approval(&request).await.unwrap();
        assert!(response.is_denied());
    }

    #[tokio::test]
    async fn test_deny_all_backend_as_dyn() {
        let backend: Box<dyn ApprovalBackend> = Box::new(DenyAllApprovalBackend);
        let request = ApprovalRequest::new(
            "send_email",
            serde_json::json!({"to": "user@example.com"}),
            "approve-email",
            "Email requires approval",
            "agent-1",
        );
        let response = backend.request_approval(&request).await.unwrap();
        assert!(response.is_denied());
        if let ApprovalResponse::Denied { reason } = response {
            assert!(reason.unwrap().contains("No approval backend configured"));
        }
    }
}
