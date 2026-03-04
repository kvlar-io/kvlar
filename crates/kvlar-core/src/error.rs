//! Error types for kvlar-core.

use thiserror::Error;

/// Errors that can occur during policy evaluation.
#[derive(Debug, Error)]
pub enum KvlarError {
    /// A policy file could not be parsed.
    #[error("failed to parse policy: {0}")]
    PolicyParse(String),

    /// A policy rule references an unknown action type.
    #[error("unknown action type: {0}")]
    UnknownActionType(String),

    /// A policy condition is malformed.
    #[error("invalid policy condition: {0}")]
    InvalidCondition(String),

    /// Serialization/deserialization error.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// YAML parsing error.
    #[error("YAML parse error: {0}")]
    YamlParse(#[from] serde_yaml::Error),
}
