//! AVP Client - Main entry point for the protocol

use chrono::{Duration, Utc};
use rand::Rng;
use std::collections::HashMap;

use crate::backends::base::BackendBase;
use crate::errors::{AVPError, Result};
use crate::types::{
    validate_secret_name, validate_workspace_id, AuthMethod, AuthenticateOptions,
    ConformanceLevel, DeleteResponse, DiscoverResponse, ListOptions, ListResponse,
    RetrieveResponse, RotateResponse, Session, StoreOptions, StoreResponse,
};

/// AVP Protocol Client
///
/// This is the main entry point for interacting with the AVP protocol.
/// It manages sessions and delegates operations to the configured backend.
pub struct AVPClient {
    backend: Box<dyn BackendBase>,
    sessions: HashMap<String, Session>,
}

impl AVPClient {
    /// Protocol version
    pub const VERSION: &'static str = "0.1.0";
    /// Default session TTL in seconds
    pub const DEFAULT_TTL: u64 = 3600;

    /// Create a new AVP client with the given backend
    pub fn new(backend: Box<dyn BackendBase>) -> Self {
        Self {
            backend,
            sessions: HashMap::new(),
        }
    }

    /// Query vault capabilities (DISCOVER operation)
    pub fn discover(&self) -> DiscoverResponse {
        DiscoverResponse {
            version: Self::VERSION.to_string(),
            conformance: ConformanceLevel::Full,
            backends: vec![self.backend.get_descriptor()],
            active_backend: self.backend.backend_id().to_string(),
            capabilities: self.backend.capabilities(),
            auth_methods: vec![AuthMethod::None, AuthMethod::Token],
            limits: self.backend.limits(),
        }
    }

    /// Establish a session (AUTHENTICATE operation)
    pub fn authenticate(&mut self, options: AuthenticateOptions) -> Result<Session> {
        let workspace = options.workspace.unwrap_or_else(|| "default".to_string());
        let agent_id = options.agent_id.unwrap_or_else(|| "avp-rs".to_string());

        // Validate workspace
        if !validate_workspace_id(&workspace) {
            return Err(AVPError::InvalidWorkspace(workspace));
        }

        // Handle termination
        if options.auth_method == AuthMethod::Terminate {
            if let Some(auth_data) = &options.auth_data {
                if let Some(session_id) = auth_data.get("session_id") {
                    self.sessions.remove(session_id);
                    return Ok(Session {
                        session_id: session_id.clone(),
                        workspace,
                        backend: self.backend.backend_id().to_string(),
                        agent_id,
                        created_at: Utc::now(),
                        expires_at: Utc::now(),
                        ttl_seconds: 0,
                    });
                }
            }
            return Err(AVPError::AuthenticationFailed(
                "session_id required for termination".to_string(),
            ));
        }

        // For other methods, create a new session
        let ttl = options
            .requested_ttl
            .unwrap_or(Self::DEFAULT_TTL)
            .min(self.backend.limits().max_session_ttl_seconds);

        let now = Utc::now();
        let session_id = format!("avp_sess_{}", generate_token(24));

        let session = Session {
            session_id: session_id.clone(),
            workspace,
            backend: self.backend.backend_id().to_string(),
            agent_id,
            created_at: now,
            expires_at: now + Duration::seconds(ttl as i64),
            ttl_seconds: ttl,
        };

        self.sessions.insert(session_id, session.clone());
        Ok(session)
    }

    fn validate_session(&self, session_id: &str) -> Result<&Session> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| AVPError::SessionNotFound(session_id.to_string()))?;

        if session.is_expired() {
            return Err(AVPError::SessionExpired);
        }

        Ok(session)
    }

    /// Store a secret (STORE operation)
    pub fn store(
        &mut self,
        session_id: &str,
        name: &str,
        value: &[u8],
        labels: Option<HashMap<String, String>>,
        expires_at: Option<chrono::DateTime<Utc>>,
    ) -> Result<StoreResponse> {
        let session = self.validate_session(session_id)?.clone();

        // Validate name
        if !validate_secret_name(name) {
            return Err(AVPError::InvalidName(name.to_string()));
        }

        // Validate value size
        if value.len() > self.backend.limits().max_secret_value_length {
            return Err(AVPError::ValueTooLarge(format!(
                "Value exceeds maximum size of {} bytes",
                self.backend.limits().max_secret_value_length
            )));
        }

        let result = self
            .backend
            .store(&session.workspace, name, value, labels, expires_at)?;

        Ok(StoreResponse {
            name: name.to_string(),
            backend: self.backend.backend_id().to_string(),
            created: result.created,
            version: result.version,
        })
    }

    /// Retrieve a secret (RETRIEVE operation)
    pub fn retrieve(
        &self,
        session_id: &str,
        name: &str,
        version: Option<u32>,
    ) -> Result<RetrieveResponse> {
        let session = self.validate_session(session_id)?;

        let result = self.backend.retrieve(&session.workspace, name, version)?;

        Ok(RetrieveResponse {
            name: name.to_string(),
            value: result.value,
            encoding: "utf8".to_string(),
            backend: self.backend.backend_id().to_string(),
            version: result.version,
        })
    }

    /// Delete a secret (DELETE operation)
    pub fn delete(&mut self, session_id: &str, name: &str) -> Result<DeleteResponse> {
        let session = self.validate_session(session_id)?.clone();

        let deleted = self.backend.delete(&session.workspace, name)?;

        Ok(DeleteResponse {
            name: name.to_string(),
            deleted,
        })
    }

    /// List secrets (LIST operation)
    pub fn list_secrets(&self, session_id: &str, options: ListOptions) -> Result<ListResponse> {
        let session = self.validate_session(session_id)?;

        let result = self.backend.list_secrets(
            &session.workspace,
            options.filter_labels.as_ref(),
            options.cursor.as_deref(),
            options.limit.unwrap_or(100),
        )?;

        Ok(ListResponse {
            secrets: result.secrets,
            cursor: result.cursor.clone(),
            has_more: result.cursor.is_some(),
        })
    }

    /// Rotate a secret (ROTATE operation)
    pub fn rotate(
        &mut self,
        session_id: &str,
        name: &str,
        new_value: &[u8],
    ) -> Result<RotateResponse> {
        let session = self.validate_session(session_id)?.clone();

        let version = self.backend.rotate(&session.workspace, name, new_value)?;

        Ok(RotateResponse {
            name: name.to_string(),
            backend: self.backend.backend_id().to_string(),
            version,
            rotated_at: Utc::now(),
        })
    }

    /// Close the client and release resources
    pub fn close(&mut self) -> Result<()> {
        self.backend.close()?;
        self.sessions.clear();
        Ok(())
    }
}

fn generate_token(len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();

    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryBackend;

    #[test]
    fn test_discover() {
        let backend = MemoryBackend::new();
        let client = AVPClient::new(Box::new(backend));

        let response = client.discover();
        assert_eq!(response.version, "0.1.0");
        assert_eq!(response.conformance, ConformanceLevel::Full);
    }

    #[test]
    fn test_authenticate() {
        let backend = MemoryBackend::new();
        let mut client = AVPClient::new(Box::new(backend));

        let session = client.authenticate(Default::default()).unwrap();
        assert!(session.session_id.starts_with("avp_sess_"));
        assert_eq!(session.workspace, "default");
    }

    #[test]
    fn test_store_and_retrieve() {
        let backend = MemoryBackend::new();
        let mut client = AVPClient::new(Box::new(backend));

        let session = client.authenticate(Default::default()).unwrap();

        let store_result = client
            .store(&session.session_id, "api_key", b"secret123", None, None)
            .unwrap();
        assert!(store_result.created);
        assert_eq!(store_result.version, 1);

        let retrieve_result = client
            .retrieve(&session.session_id, "api_key", None)
            .unwrap();
        assert_eq!(retrieve_result.value, b"secret123");
    }

    #[test]
    fn test_delete() {
        let backend = MemoryBackend::new();
        let mut client = AVPClient::new(Box::new(backend));

        let session = client.authenticate(Default::default()).unwrap();
        client
            .store(&session.session_id, "api_key", b"secret", None, None)
            .unwrap();

        let delete_result = client.delete(&session.session_id, "api_key").unwrap();
        assert!(delete_result.deleted);

        let retrieve_result = client.retrieve(&session.session_id, "api_key", None);
        assert!(retrieve_result.is_err());
    }

    #[test]
    fn test_list_secrets() {
        let backend = MemoryBackend::new();
        let mut client = AVPClient::new(Box::new(backend));

        let session = client.authenticate(Default::default()).unwrap();
        client
            .store(&session.session_id, "key1", b"v1", None, None)
            .unwrap();
        client
            .store(&session.session_id, "key2", b"v2", None, None)
            .unwrap();

        let list_result = client
            .list_secrets(&session.session_id, Default::default())
            .unwrap();
        assert_eq!(list_result.secrets.len(), 2);
    }

    #[test]
    fn test_rotate() {
        let backend = MemoryBackend::new();
        let mut client = AVPClient::new(Box::new(backend));

        let session = client.authenticate(Default::default()).unwrap();
        client
            .store(&session.session_id, "api_key", b"old_value", None, None)
            .unwrap();

        let rotate_result = client
            .rotate(&session.session_id, "api_key", b"new_value")
            .unwrap();
        assert_eq!(rotate_result.version, 2);

        let retrieve_result = client
            .retrieve(&session.session_id, "api_key", None)
            .unwrap();
        assert_eq!(retrieve_result.value, b"new_value");
    }

    #[test]
    fn test_workspace_isolation() {
        let backend = MemoryBackend::new();
        let mut client = AVPClient::new(Box::new(backend));

        let session1 = client
            .authenticate(AuthenticateOptions {
                workspace: Some("workspace1".to_string()),
                ..Default::default()
            })
            .unwrap();

        let session2 = client
            .authenticate(AuthenticateOptions {
                workspace: Some("workspace2".to_string()),
                ..Default::default()
            })
            .unwrap();

        client
            .store(&session1.session_id, "shared_name", b"value1", None, None)
            .unwrap();
        client
            .store(&session2.session_id, "shared_name", b"value2", None, None)
            .unwrap();

        let result1 = client
            .retrieve(&session1.session_id, "shared_name", None)
            .unwrap();
        let result2 = client
            .retrieve(&session2.session_id, "shared_name", None)
            .unwrap();

        assert_eq!(result1.value, b"value1");
        assert_eq!(result2.value, b"value2");
    }
}
