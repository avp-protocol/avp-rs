//! AVP Protocol Error Types

use thiserror::Error;

/// Result type for AVP operations
pub type Result<T> = std::result::Result<T, AVPError>;

/// AVP Protocol errors
#[derive(Error, Debug)]
pub enum AVPError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Session error: {0}")]
    SessionError(String),

    #[error("Session expired")]
    SessionExpired,

    #[error("Session terminated")]
    SessionTerminated,

    #[error("Session not found: {0}")]
    SessionNotFound(String),

    #[error("Secret not found: {0}")]
    SecretNotFound(String),

    #[error("Invalid name: {0}")]
    InvalidName(String),

    #[error("Invalid workspace: {0}")]
    InvalidWorkspace(String),

    #[error("Capacity exceeded: {0}")]
    CapacityExceeded(String),

    #[error("Backend error: {0}")]
    BackendError(String),

    #[error("Backend unavailable: {0}")]
    BackendUnavailable(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Value too large: {0}")]
    ValueTooLarge(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Integrity error: {0}")]
    IntegrityError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

impl AVPError {
    /// Get the error code
    pub fn code(&self) -> &'static str {
        match self {
            AVPError::AuthenticationFailed(_) => "AUTHENTICATION_FAILED",
            AVPError::SessionError(_) => "SESSION_ERROR",
            AVPError::SessionExpired => "SESSION_EXPIRED",
            AVPError::SessionTerminated => "SESSION_TERMINATED",
            AVPError::SessionNotFound(_) => "SESSION_NOT_FOUND",
            AVPError::SecretNotFound(_) => "SECRET_NOT_FOUND",
            AVPError::InvalidName(_) => "INVALID_NAME",
            AVPError::InvalidWorkspace(_) => "INVALID_WORKSPACE",
            AVPError::CapacityExceeded(_) => "CAPACITY_EXCEEDED",
            AVPError::BackendError(_) => "BACKEND_ERROR",
            AVPError::BackendUnavailable(_) => "BACKEND_UNAVAILABLE",
            AVPError::RateLimitExceeded => "RATE_LIMIT_EXCEEDED",
            AVPError::ValueTooLarge(_) => "VALUE_TOO_LARGE",
            AVPError::EncryptionError(_) => "ENCRYPTION_ERROR",
            AVPError::IntegrityError(_) => "INTEGRITY_ERROR",
            AVPError::IoError(_) => "IO_ERROR",
            AVPError::JsonError(_) => "JSON_ERROR",
        }
    }
}
