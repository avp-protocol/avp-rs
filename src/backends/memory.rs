//! In-memory backend for AVP (useful for testing)

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::RwLock;

use crate::backends::base::{BackendBase, ListResult, RetrieveResult, StoreResult};
use crate::errors::{AVPError, Result};
use crate::types::{BackendType, Capabilities, Limits, Secret, SecretMetadata};

struct StoredSecret {
    value: Vec<u8>,
    metadata: SecretMetadata,
}

/// In-memory backend for testing and development.
///
/// WARNING: Secrets are stored in plaintext in memory.
/// Do not use in production.
pub struct MemoryBackend {
    backend_id: String,
    secrets: RwLock<HashMap<String, HashMap<String, StoredSecret>>>,
}

impl MemoryBackend {
    /// Create a new memory backend
    pub fn new() -> Self {
        Self::with_id("memory-0")
    }

    /// Create a new memory backend with a custom ID
    pub fn with_id(id: &str) -> Self {
        Self {
            backend_id: id.to_string(),
            secrets: RwLock::new(HashMap::new()),
        }
    }

    /// Clear all secrets (for testing)
    pub fn clear(&self) {
        let mut secrets = self.secrets.write().unwrap();
        secrets.clear();
    }
}

impl Default for MemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl BackendBase for MemoryBackend {
    fn backend_type(&self) -> BackendType {
        BackendType::Memory
    }

    fn backend_id(&self) -> &str {
        &self.backend_id
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            attestation: false,
            rotation: true,
            injection: false,
            audit: true,
            migration: false,
            implicit_sessions: true,
            expiration: true,
            versioning: true,
        }
    }

    fn limits(&self) -> Limits {
        Limits {
            max_secret_name_length: 255,
            max_secret_value_length: 65536,
            max_labels_per_secret: 64,
            max_secrets_per_workspace: 10000,
            max_session_ttl_seconds: 86400,
        }
    }

    fn get_info(&self) -> HashMap<String, String> {
        let mut info = HashMap::new();
        info.insert("type".to_string(), "memory".to_string());
        info.insert(
            "warning".to_string(),
            "In-memory storage - data lost on restart".to_string(),
        );
        info
    }

    fn store(
        &mut self,
        workspace: &str,
        name: &str,
        value: &[u8],
        labels: Option<HashMap<String, String>>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<StoreResult> {
        let mut secrets = self.secrets.write().unwrap();
        let ws = secrets.entry(workspace.to_string()).or_default();

        let now = Utc::now();
        let existing = ws.get(name);
        let created = existing.is_none();

        let (version, created_at) = if created {
            (1, now)
        } else {
            let ex = existing.unwrap();
            (ex.metadata.version + 1, ex.metadata.created_at)
        };

        let metadata = SecretMetadata {
            created_at,
            updated_at: now,
            backend: BackendType::Memory,
            version,
            labels: labels.unwrap_or_default(),
            expires_at,
            rotation_policy: None,
        };

        ws.insert(
            name.to_string(),
            StoredSecret {
                value: value.to_vec(),
                metadata,
            },
        );

        Ok(StoreResult { created, version })
    }

    fn retrieve(
        &self,
        workspace: &str,
        name: &str,
        version: Option<u32>,
    ) -> Result<RetrieveResult> {
        let secrets = self.secrets.read().unwrap();
        let ws = secrets.get(workspace).ok_or_else(|| {
            AVPError::SecretNotFound(format!("Secret '{}' not found", name))
        })?;

        let secret = ws.get(name).ok_or_else(|| {
            AVPError::SecretNotFound(format!("Secret '{}' not found", name))
        })?;

        // Check expiration
        if let Some(exp) = secret.metadata.expires_at {
            if Utc::now() > exp {
                return Err(AVPError::SecretNotFound(format!(
                    "Secret '{}' not found",
                    name
                )));
            }
        }

        // Version check
        if let Some(v) = version {
            if v != secret.metadata.version {
                return Err(AVPError::SecretNotFound(format!(
                    "Secret '{}' version {} not found",
                    name, v
                )));
            }
        }

        Ok(RetrieveResult {
            value: secret.value.clone(),
            version: secret.metadata.version,
        })
    }

    fn delete(&mut self, workspace: &str, name: &str) -> Result<bool> {
        let mut secrets = self.secrets.write().unwrap();
        let ws = match secrets.get_mut(workspace) {
            Some(ws) => ws,
            None => return Ok(false),
        };

        if let Some(mut secret) = ws.remove(name) {
            // Zero out the value before dropping
            for byte in &mut secret.value {
                *byte = 0;
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn list_secrets(
        &self,
        workspace: &str,
        filter_labels: Option<&HashMap<String, String>>,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<ListResult> {
        let secrets = self.secrets.read().unwrap();
        let ws = match secrets.get(workspace) {
            Some(ws) => ws,
            None => return Ok(ListResult { secrets: vec![], cursor: None }),
        };

        let now = Utc::now();
        let mut result: Vec<Secret> = vec![];

        for (name, stored) in ws.iter() {
            // Skip expired secrets
            if let Some(exp) = stored.metadata.expires_at {
                if now > exp {
                    continue;
                }
            }

            // Apply label filter
            if let Some(filter) = filter_labels {
                let matches = filter
                    .iter()
                    .all(|(k, v)| stored.metadata.labels.get(k) == Some(v));
                if !matches {
                    continue;
                }
            }

            result.push(Secret {
                name: name.clone(),
                workspace: workspace.to_string(),
                metadata: stored.metadata.clone(),
                value: None,
            });
        }

        // Sort by name
        result.sort_by(|a, b| a.name.cmp(&b.name));

        // Handle pagination
        let start: usize = cursor.and_then(|c| c.parse().ok()).unwrap_or(0);
        let end = (start + limit).min(result.len());
        let page = result[start..end].to_vec();
        let next_cursor = if end < result.len() {
            Some(end.to_string())
        } else {
            None
        };

        Ok(ListResult {
            secrets: page,
            cursor: next_cursor,
        })
    }

    fn get_metadata(&self, workspace: &str, name: &str) -> Result<SecretMetadata> {
        let secrets = self.secrets.read().unwrap();
        let ws = secrets.get(workspace).ok_or_else(|| {
            AVPError::SecretNotFound(format!("Secret '{}' not found", name))
        })?;

        let secret = ws.get(name).ok_or_else(|| {
            AVPError::SecretNotFound(format!("Secret '{}' not found", name))
        })?;

        // Check expiration
        if let Some(exp) = secret.metadata.expires_at {
            if Utc::now() > exp {
                return Err(AVPError::SecretNotFound(format!(
                    "Secret '{}' not found",
                    name
                )));
            }
        }

        Ok(secret.metadata.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_and_retrieve() {
        let mut backend = MemoryBackend::new();

        let result = backend.store("default", "key1", b"value1", None, None).unwrap();
        assert!(result.created);
        assert_eq!(result.version, 1);

        let retrieved = backend.retrieve("default", "key1", None).unwrap();
        assert_eq!(retrieved.value, b"value1");
        assert_eq!(retrieved.version, 1);
    }

    #[test]
    fn test_update_increments_version() {
        let mut backend = MemoryBackend::new();

        backend.store("default", "key1", b"v1", None, None).unwrap();
        let result = backend.store("default", "key1", b"v2", None, None).unwrap();

        assert!(!result.created);
        assert_eq!(result.version, 2);
    }

    #[test]
    fn test_delete() {
        let mut backend = MemoryBackend::new();

        backend.store("default", "key1", b"value", None, None).unwrap();
        let deleted = backend.delete("default", "key1").unwrap();
        assert!(deleted);

        let result = backend.retrieve("default", "key1", None);
        assert!(result.is_err());
    }
}
