//! AVP Protocol Types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Backend storage types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendType {
    File,
    Keychain,
    Hardware,
    Remote,
    Memory,
}

/// Authentication methods
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    None,
    Pin,
    Token,
    Mtls,
    Os,
    Terminate,
}

impl Default for AuthMethod {
    fn default() -> Self {
        AuthMethod::None
    }
}

/// Protocol conformance levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConformanceLevel {
    Core,
    Full,
    Hardware,
}

/// Secret rotation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationPolicy {
    pub interval_seconds: u64,
    pub strategy: String,
    pub last_rotated_at: Option<DateTime<Utc>>,
}

/// Non-sensitive metadata about a secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub backend: BackendType,
    pub version: u32,
    pub labels: HashMap<String, String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub rotation_policy: Option<RotationPolicy>,
}

/// A credential stored in the vault
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub name: String,
    pub workspace: String,
    pub metadata: SecretMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Vec<u8>>,
}

/// An authenticated context for AVP operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub workspace: String,
    pub backend: String,
    pub agent_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub ttl_seconds: u64,
}

impl Session {
    /// Check if the session has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if the session is still valid
    pub fn is_valid(&self) -> bool {
        !self.is_expired()
    }
}

/// Backend descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Backend {
    #[serde(rename = "type")]
    pub backend_type: BackendType,
    pub id: String,
    pub status: String,
    pub info: HashMap<String, String>,
}

/// Vault capability flags
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capabilities {
    pub attestation: bool,
    pub rotation: bool,
    pub injection: bool,
    pub audit: bool,
    pub migration: bool,
    pub implicit_sessions: bool,
    pub expiration: bool,
    pub versioning: bool,
}

impl Default for Capabilities {
    fn default() -> Self {
        Self {
            attestation: false,
            rotation: false,
            injection: false,
            audit: true,
            migration: false,
            implicit_sessions: false,
            expiration: true,
            versioning: false,
        }
    }
}

/// Operational limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Limits {
    pub max_secret_name_length: usize,
    pub max_secret_value_length: usize,
    pub max_labels_per_secret: usize,
    pub max_secrets_per_workspace: usize,
    pub max_session_ttl_seconds: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_secret_name_length: 255,
            max_secret_value_length: 65536,
            max_labels_per_secret: 64,
            max_secrets_per_workspace: 1000,
            max_session_ttl_seconds: 86400,
        }
    }
}

/// Response from DISCOVER operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoverResponse {
    pub version: String,
    pub conformance: ConformanceLevel,
    pub backends: Vec<Backend>,
    pub active_backend: String,
    pub capabilities: Capabilities,
    pub auth_methods: Vec<AuthMethod>,
    pub limits: Limits,
}

/// Response from STORE operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreResponse {
    pub name: String,
    pub backend: String,
    pub created: bool,
    pub version: u32,
}

/// Response from RETRIEVE operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetrieveResponse {
    pub name: String,
    pub value: Vec<u8>,
    pub encoding: String,
    pub backend: String,
    pub version: u32,
}

/// Response from DELETE operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteResponse {
    pub name: String,
    pub deleted: bool,
}

/// Response from LIST operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListResponse {
    pub secrets: Vec<Secret>,
    pub cursor: Option<String>,
    pub has_more: bool,
}

/// Response from ROTATE operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateResponse {
    pub name: String,
    pub backend: String,
    pub version: u32,
    pub rotated_at: DateTime<Utc>,
}

/// Authentication options
#[derive(Debug, Clone, Default)]
pub struct AuthenticateOptions {
    pub workspace: Option<String>,
    pub agent_id: Option<String>,
    pub auth_method: AuthMethod,
    pub auth_data: Option<HashMap<String, String>>,
    pub requested_ttl: Option<u64>,
}

/// Store options
#[derive(Debug, Clone, Default)]
pub struct StoreOptions {
    pub labels: Option<HashMap<String, String>>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// List options
#[derive(Debug, Clone, Default)]
pub struct ListOptions {
    pub filter_labels: Option<HashMap<String, String>>,
    pub cursor: Option<String>,
    pub limit: Option<usize>,
}

/// Name validation pattern
pub fn validate_secret_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 255 {
        return false;
    }

    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() => {}
        _ => return false,
    }

    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
}

/// Workspace ID validation
pub fn validate_workspace_id(workspace_id: &str) -> bool {
    if workspace_id.is_empty() || workspace_id.len() > 255 {
        return false;
    }

    let mut chars = workspace_id.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }

    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-' || c == '/')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_secret_name() {
        assert!(validate_secret_name("api_key"));
        assert!(validate_secret_name("API_KEY"));
        assert!(validate_secret_name("myKey123"));
        assert!(validate_secret_name("key.name"));
        assert!(validate_secret_name("key-name"));

        assert!(!validate_secret_name(""));
        assert!(!validate_secret_name("123key"));
        assert!(!validate_secret_name("_key"));
        assert!(!validate_secret_name("key with spaces"));
    }

    #[test]
    fn test_validate_workspace_id() {
        assert!(validate_workspace_id("default"));
        assert!(validate_workspace_id("my-project"));
        assert!(validate_workspace_id("project/subproject"));

        assert!(!validate_workspace_id(""));
        assert!(!validate_workspace_id("/leading_slash"));
    }
}
