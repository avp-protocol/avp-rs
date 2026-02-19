//! Encrypted file backend for AVP

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;

use crate::backends::base::{BackendBase, ListResult, RetrieveResult, StoreResult};
use crate::errors::{AVPError, Result};
use crate::types::{BackendType, Capabilities, Limits, Secret, SecretMetadata};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct StoredData {
    version: u32,
    workspaces: HashMap<String, HashMap<String, StoredSecret>>,
}

#[derive(Serialize, Deserialize, Clone)]
struct StoredSecret {
    value: String, // base64
    metadata: StoredMetadata,
}

#[derive(Serialize, Deserialize, Clone)]
struct StoredMetadata {
    created_at: String,
    updated_at: String,
    backend: String,
    version: u32,
    labels: HashMap<String, String>,
    expires_at: Option<String>,
}

/// Encrypted file-based backend.
///
/// Secrets are encrypted using AES-256-GCM.
/// The encryption key is derived from a password using PBKDF2.
pub struct FileBackend {
    path: PathBuf,
    backend_id: String,
    key: [u8; 32],
    data: StoredData,
}

impl FileBackend {
    /// Create a new file backend
    pub fn new(path: &str, password: &str) -> Result<Self> {
        Self::with_id(path, password, "file-0")
    }

    /// Create a new file backend with a custom ID
    pub fn with_id(path: &str, password: &str, id: &str) -> Result<Self> {
        let path = PathBuf::from(path);

        // Derive encryption key from password
        let salt = b"avp_file_backend_v1";
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 480_000, &mut key);

        // Load or create the data
        let data = Self::load_data(&path, &key)?;

        Ok(Self {
            path,
            backend_id: id.to_string(),
            key,
            data,
        })
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| AVPError::EncryptionError(e.to_string()))?;

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| AVPError::EncryptionError(e.to_string()))?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 12 {
            return Err(AVPError::EncryptionError("Data too short".to_string()));
        }

        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| AVPError::EncryptionError(e.to_string()))?;

        let nonce = Nonce::from_slice(&data[..12]);
        let ciphertext = &data[12..];

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| AVPError::EncryptionError(e.to_string()))
    }

    fn load_data(path: &PathBuf, key: &[u8; 32]) -> Result<StoredData> {
        if !path.exists() {
            return Ok(StoredData {
                version: 1,
                workspaces: HashMap::new(),
            });
        }

        let metadata = fs::metadata(path)?;
        if metadata.len() == 0 {
            return Ok(StoredData {
                version: 1,
                workspaces: HashMap::new(),
            });
        }

        let mut file = File::open(path)?;
        let mut encrypted = Vec::new();
        file.read_to_end(&mut encrypted)?;

        // Decrypt
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| AVPError::EncryptionError(e.to_string()))?;

        if encrypted.len() < 12 {
            return Err(AVPError::EncryptionError("File too short".to_string()));
        }

        let nonce = Nonce::from_slice(&encrypted[..12]);
        let ciphertext = &encrypted[12..];

        let decrypted = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| AVPError::EncryptionError(e.to_string()))?;

        let data: StoredData = serde_json::from_slice(&decrypted)?;
        Ok(data)
    }

    fn save(&self) -> Result<()> {
        let json = serde_json::to_vec(&self.data)?;
        let encrypted = self.encrypt(&json)?;

        // Write atomically
        let temp_path = self.path.with_extension("tmp");
        {
            let mut file = File::create(&temp_path)?;
            file.write_all(&encrypted)?;
            file.sync_all()?;
        }

        fs::rename(&temp_path, &self.path)?;

        // Set restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&self.path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&self.path, perms)?;
        }

        Ok(())
    }

    fn parse_datetime(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now())
    }
}

impl BackendBase for FileBackend {
    fn backend_type(&self) -> BackendType {
        BackendType::File
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
            migration: true,
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
        info.insert("path".to_string(), self.path.display().to_string());
        info.insert("encryption".to_string(), "AES-256-GCM".to_string());
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
        let ws = self
            .data
            .workspaces
            .entry(workspace.to_string())
            .or_default();

        let now = Utc::now();
        let existing = ws.get(name);
        let created = existing.is_none();

        let (version, created_at) = if created {
            (1, now.to_rfc3339())
        } else {
            let ex = existing.unwrap();
            (ex.metadata.version + 1, ex.metadata.created_at.clone())
        };

        let metadata = StoredMetadata {
            created_at,
            updated_at: now.to_rfc3339(),
            backend: "file".to_string(),
            version,
            labels: labels.unwrap_or_default(),
            expires_at: expires_at.map(|d| d.to_rfc3339()),
        };

        ws.insert(
            name.to_string(),
            StoredSecret {
                value: BASE64.encode(value),
                metadata,
            },
        );

        self.save()?;
        Ok(StoreResult { created, version })
    }

    fn retrieve(
        &self,
        workspace: &str,
        name: &str,
        version: Option<u32>,
    ) -> Result<RetrieveResult> {
        let ws = self.data.workspaces.get(workspace).ok_or_else(|| {
            AVPError::SecretNotFound(format!("Secret '{}' not found", name))
        })?;

        let secret = ws.get(name).ok_or_else(|| {
            AVPError::SecretNotFound(format!("Secret '{}' not found", name))
        })?;

        // Check expiration
        if let Some(ref exp) = secret.metadata.expires_at {
            let exp_dt = Self::parse_datetime(exp);
            if Utc::now() > exp_dt {
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

        let value = BASE64
            .decode(&secret.value)
            .map_err(|e| AVPError::EncryptionError(e.to_string()))?;

        Ok(RetrieveResult {
            value,
            version: secret.metadata.version,
        })
    }

    fn delete(&mut self, workspace: &str, name: &str) -> Result<bool> {
        let ws = match self.data.workspaces.get_mut(workspace) {
            Some(ws) => ws,
            None => return Ok(false),
        };

        if ws.remove(name).is_some() {
            self.save()?;
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
        let ws = match self.data.workspaces.get(workspace) {
            Some(ws) => ws,
            None => return Ok(ListResult { secrets: vec![], cursor: None }),
        };

        let now = Utc::now();
        let mut result: Vec<Secret> = vec![];

        for (name, stored) in ws.iter() {
            // Skip expired secrets
            if let Some(ref exp) = stored.metadata.expires_at {
                let exp_dt = Self::parse_datetime(exp);
                if now > exp_dt {
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

            let metadata = SecretMetadata {
                created_at: Self::parse_datetime(&stored.metadata.created_at),
                updated_at: Self::parse_datetime(&stored.metadata.updated_at),
                backend: BackendType::File,
                version: stored.metadata.version,
                labels: stored.metadata.labels.clone(),
                expires_at: stored.metadata.expires_at.as_ref().map(|s| Self::parse_datetime(s)),
                rotation_policy: None,
            };

            result.push(Secret {
                name: name.clone(),
                workspace: workspace.to_string(),
                metadata,
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
        let ws = self.data.workspaces.get(workspace).ok_or_else(|| {
            AVPError::SecretNotFound(format!("Secret '{}' not found", name))
        })?;

        let stored = ws.get(name).ok_or_else(|| {
            AVPError::SecretNotFound(format!("Secret '{}' not found", name))
        })?;

        // Check expiration
        if let Some(ref exp) = stored.metadata.expires_at {
            let exp_dt = Self::parse_datetime(exp);
            if Utc::now() > exp_dt {
                return Err(AVPError::SecretNotFound(format!(
                    "Secret '{}' not found",
                    name
                )));
            }
        }

        Ok(SecretMetadata {
            created_at: Self::parse_datetime(&stored.metadata.created_at),
            updated_at: Self::parse_datetime(&stored.metadata.updated_at),
            backend: BackendType::File,
            version: stored.metadata.version,
            labels: stored.metadata.labels.clone(),
            expires_at: stored.metadata.expires_at.as_ref().map(|s| Self::parse_datetime(s)),
            rotation_policy: None,
        })
    }

    fn close(&mut self) -> Result<()> {
        self.save()
    }
}
