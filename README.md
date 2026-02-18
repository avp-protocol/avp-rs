<p align="center">
  <img src="https://raw.githubusercontent.com/avp-protocol/spec/main/assets/avp-shield.svg" alt="AVP Shield" width="80" />
</p>

<h1 align="center">avp-rs</h1>

<p align="center">
  <strong>Rust reference implementation of Agent Vault Protocol</strong><br>
  Full + Hardware conformance · Production ready · Zero unsafe code
</p>

<p align="center">
  <a href="https://crates.io/crates/avp"><img src="https://img.shields.io/crates/v/avp?style=flat-square&color=00D4AA" alt="Crates.io" /></a>
  <a href="https://docs.rs/avp"><img src="https://img.shields.io/docsrs/avp?style=flat-square" alt="docs.rs" /></a>
  <a href="https://github.com/avp-protocol/avp-rs/actions"><img src="https://img.shields.io/github/actions/workflow/status/avp-protocol/avp-rs/ci.yml?style=flat-square" alt="CI" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache_2.0-blue?style=flat-square" alt="License" /></a>
</p>

---

## Overview

`avp-rs` is the official Rust reference implementation of the [Agent Vault Protocol (AVP)](https://github.com/avp-protocol/spec). It provides a complete, production-ready library for secure credential management in AI agent systems.

## Features

- **Full AVP Conformance** — All 7 core operations (DISCOVER, AUTHENTICATE, STORE, RETRIEVE, DELETE, LIST, ROTATE)
- **Hardware Support** — HW_CHALLENGE, HW_SIGN, HW_ATTEST for secure elements
- **All Backends** — File, Keychain (macOS/Windows/Linux), Hardware, Remote
- **All Transports** — In-process, USB serial, Unix socket, HTTP/HTTPS, MCP
- **Zero Unsafe** — 100% safe Rust, audited dependencies
- **Async/Await** — Tokio-based async runtime
- **WASM Ready** — Compile to WebAssembly for browser/edge use

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
avp = "0.1"
```

## Quick Start

```rust
use avp::{Vault, Config};

#[tokio::main]
async fn main() -> avp::Result<()> {
    // Load configuration
    let config = Config::from_file("avp.toml")?;

    // Create vault instance
    let vault = Vault::new(config).await?;

    // Authenticate
    vault.authenticate().await?;

    // Store a secret
    vault.store("anthropic_api_key", "sk-ant-...").await?;

    // Retrieve a secret
    let api_key = vault.retrieve("anthropic_api_key").await?;

    Ok(())
}
```

## Backend Selection

```rust
use avp::{Vault, Backend};

// File backend (encrypted, for development)
let vault = Vault::with_backend(Backend::File {
    path: "~/.avp/secrets.enc".into(),
    cipher: avp::Cipher::ChaCha20Poly1305,
}).await?;

// OS Keychain (recommended for most use cases)
let vault = Vault::with_backend(Backend::Keychain).await?;

// Hardware secure element (maximum security)
let vault = Vault::with_backend(Backend::Hardware {
    device: "/dev/ttyUSB0".into(),
}).await?;

// Remote vault (team/enterprise)
let vault = Vault::with_backend(Backend::Remote {
    url: "https://vault.company.com".into(),
    auth: avp::RemoteAuth::Token("hvs.xxx".into()),
}).await?;
```

## Hardware Attestation

```rust
// Verify hardware device authenticity
let challenge = vault.hw_challenge().await?;
assert!(challenge.verified);

// Sign data without exposing the key
let signature = vault.hw_sign("anthropic_api_key", payload).await?;

// Generate compliance attestation
let attestation = vault.hw_attest("anthropic_api_key").await?;
println!("Attestation: {}", attestation.proof);
```

## Migration

```rust
use avp::migration;

// Migrate from file to keychain
migration::migrate(
    Backend::File { path: "~/.avp/secrets.enc".into(), .. },
    Backend::Keychain,
).await?;

// Migrate from keychain to hardware
migration::migrate(
    Backend::Keychain,
    Backend::Hardware { device: "/dev/ttyUSB0".into() },
).await?;
```

## Project Structure

```
avp-rs/
├── avp/                 # Core library
│   ├── src/
│   │   ├── lib.rs       # Public API
│   │   ├── vault.rs     # Vault implementation
│   │   ├── session.rs   # Session management
│   │   ├── backend/     # Backend implementations
│   │   │   ├── file.rs
│   │   │   ├── keychain.rs
│   │   │   ├── hardware.rs
│   │   │   └── remote.rs
│   │   ├── transport/   # Transport bindings
│   │   │   ├── library.rs
│   │   │   ├── usb.rs
│   │   │   ├── socket.rs
│   │   │   ├── http.rs
│   │   │   └── mcp.rs
│   │   └── crypto/      # Cryptographic primitives
│   └── Cargo.toml
├── avp-cli/             # CLI binary (re-exported from avp-protocol/avp-cli)
├── avp-mcp/             # MCP server binary
└── examples/            # Usage examples
```

## Conformance

| Level | Status |
|-------|--------|
| AVP Core | ✅ Complete |
| AVP Full | ✅ Complete |
| AVP Hardware | ✅ Complete |

## Security

- All cryptographic operations use audited libraries (ring, rustcrypto)
- Memory is zeroed after use (zeroize crate)
- No unsafe code in the main library
- Fuzz tested with cargo-fuzz
- Regular dependency audits with cargo-audit

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

<p align="center">
  <a href="https://github.com/avp-protocol/spec">Specification</a> ·
  <a href="https://docs.rs/avp">Documentation</a> ·
  <a href="https://github.com/avp-protocol/avp-rs/issues">Issues</a>
</p>
