# Security Model

## Overview

`securebit_core` is a platform-agnostic cryptographic kernel that provides secure peer-to-peer communication primitives. This document clearly defines what security guarantees the core provides, what it does not guarantee, and why closed-source adapters cannot weaken these guarantees.

---

## What the Core Guarantees

### 1. Cryptographic Security

The core guarantees:

- **ECDH Key Exchange (P-384)**: Secure ephemeral key exchange with perfect forward secrecy
- **ECDSA Signatures (P-384)**: Cryptographic authentication of protocol messages
- **HKDF Key Derivation (SHA-256)**: Deterministic key derivation from shared secrets using industry-standard HKDF
- **AES-256-GCM Encryption**: Authenticated encryption for message confidentiality and integrity
- **HMAC-SHA-256**: Message authentication codes for integrity verification
- **Session Key Isolation**: Separate keys for encryption, MAC, and metadata protection

**Implementation**: All cryptographic operations use well-vetted Rust crates (`p384`, `aes-gcm`, `hkdf`, `hmac`) with no custom cryptographic primitives.

### 2. Protocol Security

The core guarantees:

- **Protocol Version Enforcement**: Strict validation of protocol version (v4.0)
- **Message Structure Validation**: All protocol messages are validated before processing
- **State Machine Integrity**: Connection state transitions are enforced (offer → answer → join)
- **Replay Protection**: Sequence numbers prevent message replay attacks
- **Metadata Protection**: Message metadata (timestamps, IDs) are encrypted separately

**Implementation**: All protocol logic is in `core/src/webrtc.rs` and `core/src/session.rs` with no bypass mechanisms.

### 3. Key Management Security

The core guarantees:

- **Ephemeral Keys**: ECDH keys are generated fresh for each connection
- **Secure Key Derivation**: Session keys are derived using HKDF with specific info labels
- **Key Isolation**: Keys are stored in memory only, never persisted
- **Secure Cleanup**: Keys are zeroed before deallocation (when possible in Rust)

**Implementation**: All key generation and derivation is in the core, with no external dependencies.

### 4. SAS (Short Authentication String) Security

The core guarantees:

- **Deterministic SAS Computation**: SAS codes are computed from DTLS fingerprints using SHA-384
- **MITM Detection**: SAS codes allow users to detect man-in-the-middle attacks
- **Verification Code Generation**: Cryptographically secure 6-digit verification codes

**Implementation**: SAS computation is in `core/src/webrtc.rs` with deterministic algorithms.

### 5. Input Validation

The core guarantees:

- **Strict Input Validation**: All inputs are validated before processing
- **Type Safety**: Rust's type system prevents many classes of errors
- **Error Handling**: All operations return `Result<T, CoreError>` with no panics in security paths

**Implementation**: Input validation is performed at API boundaries in all core functions.

---

## What is NOT the Core's Responsibility

### 1. Platform Security

The core does **NOT** guarantee:

- **OS Security**: Protection against compromised operating systems
- **Hardware Security**: Protection against compromised hardware (TPM, secure enclaves)
- **System-Level Attacks**: Protection against rootkits, kernel exploits, etc.

**Why**: The core is a cryptographic library, not a platform security framework. Platform security is the responsibility of the operating system and hardware.

### 2. Network Security

The core does **NOT** guarantee:

- **Network Transport Security**: Protection against network-level attacks (DDoS, packet injection)
- **WebRTC Signaling Security**: Protection of the signaling channel (offer/answer exchange)
- **NAT/Firewall Traversal**: Network connectivity establishment

**Why**: The core provides cryptographic primitives for application-layer security. Network transport security is the responsibility of the WebRTC stack and network infrastructure.

### 3. UI/UX Security

The core does **NOT** guarantee:

- **User Interface Security**: Protection against malicious UI code
- **User Input Validation**: Validation of user-provided data (message content, display)
- **Visual Security**: Protection against UI spoofing, phishing, etc.

**Why**: The core is a headless library with no UI dependencies. UI security is the responsibility of the application layer.

### 4. Application Logic Security

The core does **NOT** guarantee:

- **Business Logic Security**: Protection against application-level vulnerabilities
- **Access Control**: User authentication, authorization, permissions
- **Rate Limiting**: Protection against abuse, spam, DoS

**Why**: The core provides cryptographic primitives. Application logic security is the responsibility of the application layer.

### 5. Side-Channel Attacks

The core does **NOT** guarantee:

- **Timing Attack Protection**: Protection against timing-based side-channel attacks
- **Power Analysis Protection**: Protection against power analysis attacks
- **Cache Attack Protection**: Protection against cache-based side-channel attacks

**Why**: Side-channel attack protection requires platform-specific mitigations (constant-time operations, secure hardware). The core uses standard cryptographic libraries that may not implement all side-channel mitigations.

### 6. Key Storage Security

The core does **NOT** guarantee:

- **Persistent Key Storage**: Secure storage of keys on disk
- **Key Backup Security**: Secure backup and recovery of keys
- **Key Escrow**: Key escrow or recovery mechanisms

**Why**: The core stores keys in memory only. Persistent key storage is the responsibility of the application layer.

---

## Why Closed Adapters Cannot Weaken Security

### 1. Architectural Isolation

**Principle**: All security-critical logic is in the public core. Adapters are thin wrappers.

**Evidence**:
- Adapters only call core methods: `core.create_secure_offer()`, `core.join_secure_connection()`, etc.
- Adapters have **zero** access to internal core state (private fields)
- Adapters cannot modify cryptographic algorithms
- Adapters cannot bypass protocol validation

**Example**:
```rust
// Adapter (closed-source)
#[tauri::command]
fn create_secure_offer(core: State<Arc<Core>>, offer_sdp: Option<String>) -> Result<String, String> {
    core.create_secure_offer(offer_sdp)  // Direct pass-through, no logic
}
```

### 2. No Cryptographic Bypass

**Principle**: Adapters cannot bypass cryptographic operations because all crypto is in the core.

**Evidence**:
- All ECDH key exchange is in `core/src/webrtc.rs`
- All key derivation is in `core/src/webrtc.rs`
- All encryption/decryption is in `core/src/session.rs`
- Adapters cannot access keys directly (they are private fields)

**Verification**: Security researchers can audit the core and verify that adapters cannot bypass security.

### 3. Protocol Enforcement

**Principle**: Protocol validation is enforced in the core, not in adapters.

**Evidence**:
- Protocol version checking is in `core/src/webrtc.rs`
- Message structure validation is in `core/src/webrtc.rs`
- State machine enforcement is in `core/src/webrtc.rs`
- Adapters cannot skip validation (it's inside core methods)

**Verification**: Security researchers can verify that protocol validation cannot be bypassed.

### 4. Input Validation

**Principle**: All input validation happens in the core before processing.

**Evidence**:
- Input validation is at the API boundary in core methods
- Adapters cannot inject invalid data (core validates it)
- Adapters cannot skip validation (it's inside core methods)

**Verification**: Security researchers can verify that input validation cannot be bypassed.

### 5. State Isolation

**Principle**: Core state (keys, secrets, session data) is private and inaccessible to adapters.

**Evidence**:
- Core state fields are private: `crypto: Arc<Mutex<CryptoUtils>>`
- Adapters only have access to public API methods
- Adapters cannot read or modify internal state directly

**Verification**: Security researchers can verify that state is properly isolated.

### 6. Deterministic Behavior

**Principle**: The core's behavior is deterministic (same inputs → same outputs) regardless of adapter.

**Evidence**:
- Core uses deterministic algorithms (HKDF, HMAC, AES-GCM with fixed IVs)
- Core has no platform-specific code paths
- Adapters cannot change core behavior (they only call methods)

**Verification**: Security researchers can verify deterministic behavior independently.

---

## Security Guarantee Summary

| Guarantee | Core Responsibility | Adapter Responsibility |
|-----------|---------------------|----------------------|
| **Cryptographic Operations** | ✅ Full | ❌ None |
| **Protocol Validation** | ✅ Full | ❌ None |
| **Key Management** | ✅ Full | ❌ None |
| **Input Validation** | ✅ Full | ❌ None |
| **Platform Security** | ❌ None | ⚠️ Partial |
| **Network Security** | ❌ None | ⚠️ Partial |
| **UI Security** | ❌ None | ✅ Full |
| **Application Logic** | ❌ None | ✅ Full |

---

## Conclusion

The `securebit_core` provides **strong cryptographic and protocol security guarantees** that cannot be weakened by closed-source adapters. This is because:

1. **All security-critical logic is in the public core**
2. **Adapters are thin wrappers with no security logic**
3. **Core state is private and inaccessible to adapters**
4. **Protocol validation is enforced in the core**
5. **Input validation happens in the core**

Security researchers can audit the core independently and verify that adapters cannot weaken security guarantees. The closed-source nature of adapters does not affect the security model because adapters have no access to security-critical code paths.

---

**Last Updated**: 2025-12-23  
**Version**: 1.0

