//! Base backend trait for AVP

use chrono::{DateTime, Utc};
use std::collections::HashMap;

use crate::errors::Result;
use crate::types::{Backend, BackendType, Capabilities, Limits, Secret, SecretMetadata};

/// Store operation result
pub struct StoreResult {
    pub created: bool,
    pub version: u32,
}

/// Retrieve operation result
pub struct RetrieveResult {
    pub value: Vec<u8>,
    pub version: u32,
}

/// List operation result
pub struct ListResult {
    pub secrets: Vec<Secret>,
    pub cursor: Option<String>,
}

/// Abstract trait for AVP backends
pub trait BackendBase: Send + Sync {
    /// Return the backend type
    fn backend_type(&self) -> BackendType;

    /// Return a unique backend identifier
    fn backend_id(&self) -> &str;

    /// Return backend capabilities
    fn capabilities(&self) -> Capabilities {
        Capabilities::default()
    }

    /// Return backend limits
    fn limits(&self) -> Limits {
        Limits::default()
    }

    /// Get the backend descriptor
    fn get_descriptor(&self) -> Backend {
        Backend {
            backend_type: self.backend_type(),
            id: self.backend_id().to_string(),
            status: "available".to_string(),
            info: self.get_info(),
        }
    }

    /// Get backend-specific information
    fn get_info(&self) -> HashMap<String, String> {
        HashMap::new()
    }

    /// Store a secret
    fn store(
        &mut self,
        workspace: &str,
        name: &str,
        value: &[u8],
        labels: Option<HashMap<String, String>>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<StoreResult>;

    /// Retrieve a secret value
    fn retrieve(
        &self,
        workspace: &str,
        name: &str,
        version: Option<u32>,
    ) -> Result<RetrieveResult>;

    /// Delete a secret
    fn delete(&mut self, workspace: &str, name: &str) -> Result<bool>;

    /// List secrets in a workspace
    fn list_secrets(
        &self,
        workspace: &str,
        filter_labels: Option<&HashMap<String, String>>,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<ListResult>;

    /// Get secret metadata without the value
    fn get_metadata(&self, workspace: &str, name: &str) -> Result<SecretMetadata>;

    /// Rotate a secret value
    fn rotate(&mut self, workspace: &str, name: &str, new_value: &[u8]) -> Result<u32> {
        // Default implementation: verify exists, then store
        self.get_metadata(workspace, name)?;
        let result = self.store(workspace, name, new_value, None, None)?;
        Ok(result.version)
    }

    /// Close the backend and release resources
    fn close(&mut self) -> Result<()> {
        Ok(())
    }
}
