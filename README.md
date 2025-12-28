# securebit_core

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Security Audit](https://img.shields.io/badge/security-audited-green.svg)](SECURITY_MODEL.md)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Code Quality](https://img.shields.io/badge/code%20quality-excellent-brightgreen.svg)]()

**Platform-agnostic cryptographic kernel for secure peer-to-peer communication.**

`securebit_core` is a pure Rust crate that provides cryptographic primitives and protocol implementation for secure WebRTC-based peer-to-peer communication. It is designed to be the **single source of truth** for all security-critical operations, reusable across desktop, mobile, and headless deployments.

---

##  Now Available: Desktop Applications!

**SecureBit Chat desktop applications are now available for Windows, macOS, and Linux!**

Download native desktop apps built on this secure core:

[![Download Desktop Apps](https://img.shields.io/badge/Download-Desktop%20Apps-blue?style=for-the-badge&logo=github)](https://github.com/SecureBitChat/securebit-desktop)

### Desktop Releases
- **Windows 10/11** - NSIS Installer
- **macOS 11+** - Universal App (Intel + Apple Silicon)
- **Linux** - AppImage (Universal)

**[Get Desktop Apps →](https://github.com/SecureBitChat/securebit-desktop)**

---

## Features

### Cryptographic Security

- **ECDH Key Exchange (P-384)**: Ephemeral key exchange with perfect forward secrecy
- **ECDSA Signatures (P-384)**: Cryptographic authentication of protocol messages
- **HKDF Key Derivation (SHA-256)**: Deterministic key derivation from shared secrets
- **AES-256-GCM Encryption**: Authenticated encryption for message confidentiality and integrity
- **HMAC-SHA-256**: Message authentication codes for integrity verification
- **SAS (Short Authentication String)**: MITM detection via DTLS fingerprint verification

### Protocol Security

- **Protocol Version Enforcement**: Strict validation of protocol version (v4.0)
- **Message Structure Validation**: All protocol messages are validated before processing
- **State Machine Integrity**: Connection state transitions are enforced
- **Replay Protection**: Sequence numbers prevent message replay attacks
- **Metadata Protection**: Message metadata (timestamps, IDs) are encrypted separately

### Platform Independence

- **Zero Platform Dependencies**: No Tauri, no UI frameworks, no OS-specific APIs
- **Cross-Platform**: Works on Windows, macOS, Linux, Android, iOS
- **Headless Support**: Can be used in CLI tools, daemons, and background services
- **Thread-Safe**: Uses `Arc<Mutex<>>` for thread-safe state management

### Security Transparency

- **Public Core**: All security-critical code is in this public repository
- **Auditable**: Designed for independent security review
- **No Backdoors**: Zero external network calls, zero file system access
- **Deterministic**: Same inputs produce the same security-relevant outputs

---

## Official Applications

SecureBit Core powers multiple official applications:

### Desktop Applications
**Native desktop apps for Windows, macOS, and Linux**
- Repository: [securebit-desktop](https://github.com/SecureBitChat/securebit-desktop)
- Platforms: Windows 10/11, macOS 11+, Linux (AppImage)
- Status: Public Beta v0.1.0 Available
- License: Proprietary (free for personal & commercial use)

### Web Application
**Browser-based secure chat (fully open source)**
- Repository: [securebit-chat](https://github.com/SecureBitChat/securebit-chat)
- Platforms: All modern browsers
- Status: Production Ready
- License: MIT

### Coming Soon
- **Mobile Apps** (iOS/Android) - Q2 2026
- **Store Distribution** (Windows Store, Mac App Store, Snap Store) - Q1 2026

---

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
securebit_core = { path = "../core" }  # Local path
# Or from crates.io (when published):
# securebit_core = "0.1.0"
```

---

## Quick Start

### Basic Usage

```rust
use securebit_core::Core;

// Create a new Core instance
let core = Core::new();

// Create a secure offer (for initiator)
let offer = core.create_secure_offer(Some(web_rtc_sdp))?;
println!("Offer: {}", offer);

// Join a connection (for responder)
let answer = core.join_secure_connection(offer_data, Some(web_rtc_answer_sdp))?;
println!("Answer: {}", answer);

// Handle answer (for initiator)
let result = core.handle_secure_answer(answer_data)?;

// Encrypt a message
let encrypted = core.encrypt_enhanced_message(
    "Hello, world!".to_string(),
    "msg-123".to_string(),
    1
)?;

// Decrypt a message
let decrypted = core.decrypt_enhanced_message(encrypted)?;
```

### Integration with Tauri (Desktop Apps)

```rust
use securebit_core::Core;
use std::sync::Arc;
use tauri::{State, Manager};

#[tauri::command]
fn create_secure_offer(
    core: State<Arc<Core>>,
    offer_sdp: Option<String>
) -> Result<String, String> {
    core.create_secure_offer(offer_sdp)
}
```

### Integration with Mobile (FFI)

```rust
use securebit_core::Core;

#[no_mangle]
pub extern "C" fn create_secure_offer_ffi(
    offer_sdp: *const c_char,
    output: *mut c_char,
    output_len: usize,
) -> i32 {
    // FFI wrapper implementation
}
```

---

## Architecture

### Core Structure

```
securebit_core/
├── src/
│   ├── core.rs          # Main Core struct and public API
│   ├── crypto.rs        # Cryptographic utilities
│   ├── session.rs       # Session management (encryption/decryption)
│   ├── webrtc.rs        # WebRTC protocol (offer/answer/join)
│   ├── error.rs         # Error types
│   ├── logger.rs        # Optional logging trait
│   └── lib.rs           # Public API exports
├── SECURITY_MODEL.md    # Security guarantees and boundaries
├── THREAT_MODEL.md      # Threats mitigated and not mitigated
└── README.md            # This file
```

### State Management

The core manages three types of state:

1. **Crypto State**: Key pairs, encryption keys
2. **Offer State**: ECDH secrets, session salts, DTLS fingerprints
3. **Session Keys**: Encryption keys, MAC keys, metadata keys

All state is thread-safe via `Arc<Mutex<>>` and is never persisted to disk.

---

## Security Model

### What the Core Guarantees

- **Cryptographic Security**: ECDH, ECDSA, HKDF, AES-GCM, HMAC
- **Protocol Security**: Version enforcement, message validation, state machine
- **Key Management**: Ephemeral keys, secure derivation, key isolation
- **SAS Security**: Deterministic SAS computation for MITM detection
- **Input Validation**: Strict validation of all inputs

### What the Core Does NOT Guarantee

- ❌ **Platform Security**: Protection against compromised OS/hardware
- ❌ **Network Security**: Protection against network-level attacks
- ❌ **UI Security**: Protection against malicious UI code
- ❌ **Application Logic**: Protection against application-level vulnerabilities
- ❌ **Side-Channel Attacks**: Protection against timing/power/cache attacks

See [SECURITY_MODEL.md](SECURITY_MODEL.md) for detailed security guarantees.

---

## Threat Model

### Threats Mitigated

- **MITM Attacks**: ECDH key exchange, ECDSA signatures, SAS verification
- **Eavesdropping**: AES-256-GCM encryption with ephemeral keys
- **Message Tampering**: HMAC-SHA-256, AES-GCM authentication
- **Replay Attacks**: Sequence numbers, timestamp validation
- **Perfect Forward Secrecy**: Ephemeral ECDH keys
- **Protocol Attacks**: Version enforcement, message validation

### Threats NOT Mitigated

- ❌ **Compromised OS/Hardware**: Platform-level attacks
- ❌ **Malicious UI**: UI-level attacks (XSS, spoofing, phishing)
- ❌ **Side-Channel Attacks**: Timing, power, cache attacks
- ❌ **Memory Dump Attacks**: Process memory extraction
- ❌ **Denial of Service**: Resource exhaustion, crashes

See [THREAT_MODEL.md](THREAT_MODEL.md) for detailed threat analysis.

---

## API Reference

### Core Methods

#### WebRTC Protocol

- `create_secure_offer(offer_sdp: Option<String>) -> Result<String, String>`
  - Creates a secure offer for peer-to-peer connection initiation
  - Returns: Encrypted offer in `SB1:gz:` format

- `join_secure_connection(offer_data: String, answer_sdp: Option<String>) -> Result<String, String>`
  - Joins a connection by processing an offer and creating an answer
  - Returns: Encrypted answer in `SB1:gz:` format

- `handle_secure_answer(answer_data: String) -> Result<String, String>`
  - Handles an answer from the responder (for initiator)
  - Returns: Connection result with session keys established

- `parse_secure_offer(offer_data: String) -> Result<String, String>`
  - Parses an offer to extract SDP and metadata
  - Returns: JSON string with parsed offer data

#### Message Encryption/Decryption

- `encrypt_enhanced_message(message: String, message_id: String, sequence_number: u64) -> Result<String, String>`
  - Encrypts a message with AES-256-GCM and HMAC-SHA-256
  - Returns: JSON string with encrypted message data

- `decrypt_enhanced_message(encrypted_message: String) -> Result<String, String>`
  - Decrypts a message and verifies integrity
  - Returns: JSON string with decrypted message data

#### Cryptographic Utilities

- `generate_key_pair() -> Result<String, String>`
  - Generates a new cryptographic key pair
  - Returns: Key ID

- `encrypt_data(data: &str, key_id: &str) -> Result<String, String>`
  - Encrypts data using a key pair
  - Returns: JSON string with encrypted data

- `decrypt_data(encrypted_data: &str) -> Result<String, String>`
  - Decrypts data using a key pair
  - Returns: Decrypted data string

- `generate_secure_password(length: usize) -> Result<String, String>`
  - Generates a cryptographically secure random password
  - Returns: Random password string

---

## Dependencies

### Cryptographic Libraries

- `p384`: P-384 elliptic curve (ECDH, ECDSA)
- `aes-gcm`: AES-256-GCM authenticated encryption
- `hkdf`: HKDF key derivation (SHA-256)
- `hmac`: HMAC-SHA-256 message authentication
- `sha2`: SHA-256, SHA-384 hashing

### Utility Libraries

- `serde`, `serde_json`: Serialization
- `rand`: Cryptographically secure random number generation
- `base64`: Base64 encoding/decoding
- `hex`: Hexadecimal encoding/decoding
- `chrono`: Timestamp handling
- `uuid`: UUID generation
- `flate2`: Compression (zlib)
- `serde_cbor`: CBOR serialization
- `regex`: Regular expressions

**No platform-specific dependencies** (no Tauri, no UI frameworks, no OS APIs).

---

## Use Cases

### Production Applications

This core is used in production by:

1. **[SecureBit Desktop](https://github.com/SecureBitChat/securebit-desktop)** - Native desktop applications
2. **[SecureBit Web](https://github.com/SecureBitChat/securebit-chat)** - Browser-based chat application

### Your Own Applications

You can integrate this core into:
-  **Desktop Applications** (Tauri, Electron, Qt)
-  **Mobile Applications** (React Native, Flutter, native iOS/Android)
-  **Web Applications** (WASM, JavaScript bindings)
-  **CLI Tools** (Headless bots, automation)
-  **Backend Services** (Message relays, bridge services)

---

## Security Audit

This crate has been audited for public security review. See:

- [SECURITY_MODEL.md](SECURITY_MODEL.md) - Security guarantees and boundaries
- [THREAT_MODEL.md](THREAT_MODEL.md) - Threat analysis

**License**: Apache-2.0

---

## Contributing

This is a security-critical crate. All contributions must:

1. Maintain platform independence (no platform-specific code)
2. Preserve security guarantees (no weakening of security)
3. Follow Rust security best practices (no `unsafe`, proper error handling)
4. Include tests for new functionality
5. Update documentation (README, SECURITY_MODEL, THREAT_MODEL)

### How to Contribute

1. **Report Security Issues**: Email security@securebit.chat (PGP key available)
2. **Submit Bug Reports**: Open an issue on GitHub
3. **Propose Features**: Open a discussion on GitHub
4. **Submit Pull Requests**: Follow our contribution guidelines
5. **Improve Documentation**: Help make docs clearer

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

---

## License

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](LICENSE) file for details.

**SPDX-License-Identifier**: Apache-2.0

### Why Apache 2.0?

We chose Apache License 2.0 because it:
-  Provides explicit patent protection
-  Allows commercial use without restrictions
-  Protects contributors from patent claims
-  Is compatible with most other licenses
-  Is trusted by enterprise users

---

## Roadmap

### Current Version (v0.1.0)
-  Core cryptographic primitives
-  P2P protocol implementation
-  Desktop application support
-  Web application support

### Q1 2026
-  Mobile FFI bindings (iOS/Android)
-  WASM support for web
-  Performance optimizations
-  Additional test coverage

### Q2 2026
-  Post-quantum cryptography (CRYSTALS-Kyber)
-  Multi-device sync protocol
-  Group chat cryptography
-  Hardware security module support

### Q3 2026
-  Formal verification (selected modules)
-  Side-channel resistance improvements
-  Memory-hard key derivation
-  Advanced metadata protection

---

## Acknowledgments

- Built with Rust's excellent cryptographic ecosystem
- Designed for independent security review and white-label distribution
- Inspired by Signal Protocol and OTR (Off-the-Record) messaging
- Thanks to all contributors and security researchers

### Special Thanks

- **Rust Crypto Team**: For excellent cryptographic primitives
- **Tauri Team**: For the desktop application framework
- **WebRTC Community**: For peer-to-peer technology
- **Security Researchers**: For audits and feedback

---

## Related Projects

### Official SecureBit Applications
- **[Desktop Apps](https://github.com/SecureBitChat/securebit-desktop)** - Windows, macOS, Linux
- **[Web App](https://github.com/SecureBitChat/securebit-chat)** - Browser-based chat

### Cryptographic Libraries
- [RustCrypto](https://github.com/RustCrypto) - Cryptographic algorithms in Rust
- [ring](https://github.com/briansmith/ring) - Safe, fast crypto using Rust & BoringSSL
- [sodiumoxide](https://github.com/sodiumoxide/sodiumoxide) - Rust bindings to libsodium

---

## FAQs

### Why is the core open source but desktop apps proprietary?

The **security-critical code** (all cryptography, protocol implementation) is 100% open source in this repository. The desktop applications are proprietary wrappers around this core, containing only UI code and platform integrations. This means:
- You can audit all security-critical operations
- No cryptographic operations happen in closed-source code
- Business sustainability through proprietary UI
- Open core enables trust and transparency

### Can I use this core in my own application?

Yes! This core is licensed under Apache 2.0, which allows:
- Commercial use
- Modification and distribution
- Private use
- Patent grant

Just make sure to include the license and copyright notice.

### Is this production-ready?

Yes! This core is used in production by:
- SecureBit Desktop (public beta)
- SecureBit Web (production)

However, we recommend:
- Independent security audit for critical applications
- Thorough testing in your specific use case
- Performance testing under expected load

### How do I report security vulnerabilities?

**Please DO NOT open public issues for security vulnerabilities.**

Instead:
1. Email: security@securebit.chat
2. Include: Detailed description, reproduction steps, impact assessment
3. Expect: Response within 24 hours
4. We follow: Responsible disclosure (90-day window)

---

**Version**: 0.1.0  
**License**: Apache-2.0  
**Last Updated**: December 28, 2025

---

<div align="center">

**Built for Security, Designed for Transparency**

[Desktop Apps](https://github.com/SecureBitChat/securebit-desktop) • [Web App](https://github.com/SecureBitChat/securebit-chat) • [Security Model](SECURITY_MODEL.md) • [Threat Model](THREAT_MODEL.md)

**Made with 🦀 by the SecureBit Team**

</div>
