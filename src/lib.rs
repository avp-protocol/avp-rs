//! Agent Vault Protocol (AVP) - Rust SDK
//!
//! A secure credential management protocol for AI agents.
//!
//! # Example
//!
//! ```
//! use avp::{AVPClient, MemoryBackend};
//!
//! let backend = MemoryBackend::new();
//! let mut client = AVPClient::new(Box::new(backend));
//!
//! // Authenticate
//! let session = client.authenticate(Default::default()).unwrap();
//!
//! // Store a secret
//! client.store(&session.session_id, "api_key", b"secret123", None, None).unwrap();
//!
//! // Retrieve the secret
//! let response = client.retrieve(&session.session_id, "api_key", None).unwrap();
//! assert_eq!(response.value, b"secret123");
//! ```

pub mod types;
pub mod errors;
pub mod backends;
pub mod client;

pub use types::*;
pub use errors::*;
pub use backends::{BackendBase, MemoryBackend, FileBackend};
pub use client::AVPClient;
