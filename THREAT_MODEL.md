# Threat Model

## Overview

This document describes the threats that `securebit_core` mitigates and the threats it does not mitigate. This helps security researchers and auditors understand the security boundaries and limitations of the core.

---

## Threats Mitigated by the Core

### 1. Man-in-the-Middle (MITM) Attacks

**Threat**: An attacker intercepts and modifies communication between two parties.

**Mitigation**:
- **ECDH Key Exchange**: Ephemeral key exchange prevents passive MITM attacks
- **ECDSA Signatures**: Protocol messages are cryptographically signed to prevent tampering
- **SAS (Short Authentication String)**: Users can verify connection authenticity using SAS codes
- **DTLS Fingerprint Verification**: DTLS fingerprints are included in protocol messages for verification

**Implementation**: All MITM protections are in `core/src/webrtc.rs`.

**Limitation**: SAS verification requires user interaction. If users skip verification, MITM attacks are possible.

---

### 2. Eavesdropping

**Threat**: An attacker intercepts and reads encrypted messages.

**Mitigation**:
- **AES-256-GCM Encryption**: All messages are encrypted with authenticated encryption
- **Ephemeral Keys**: Each connection uses fresh keys (perfect forward secrecy)
- **Key Derivation**: Session keys are derived using HKDF from ephemeral shared secrets

**Implementation**: Encryption is in `core/src/session.rs`, key derivation is in `core/src/webrtc.rs`.

**Limitation**: If an attacker compromises the session keys (e.g., via memory dump), they can decrypt messages.

---

### 3. Message Tampering

**Threat**: An attacker modifies messages in transit.

**Mitigation**:
- **HMAC-SHA-256**: All messages include MACs for integrity verification
- **AES-GCM Authentication**: AES-GCM provides authenticated encryption
- **ECDSA Signatures**: Protocol messages are signed to prevent tampering

**Implementation**: MAC computation is in `core/src/session.rs`, signature verification is in `core/src/webrtc.rs`.

**Limitation**: If an attacker compromises the MAC key, they can forge messages.

---

### 4. Replay Attacks

**Threat**: An attacker replays old messages to cause unauthorized actions.

**Mitigation**:
- **Sequence Numbers**: Messages include sequence numbers to detect replay
- **Timestamp Validation**: Messages include timestamps (application layer should validate)

**Implementation**: Sequence numbers are in `core/src/session.rs`.

**Limitation**: Replay protection requires application-layer timestamp validation. The core provides sequence numbers but does not enforce timestamp validation.

---

### 5. Key Compromise (Perfect Forward Secrecy)

**Threat**: If long-term keys are compromised, past communications should remain secure.

**Mitigation**:
- **Ephemeral ECDH Keys**: Each connection uses fresh ephemeral keys
- **No Long-Term Keys**: The core does not use long-term keys for encryption
- **Key Derivation**: Session keys are derived from ephemeral shared secrets

**Implementation**: Ephemeral key generation is in `core/src/webrtc.rs`.

**Limitation**: If an attacker compromises the session keys during an active session, they can decrypt messages in that session.

---

### 6. Protocol Attacks

**Threat**: An attacker exploits protocol vulnerabilities (version downgrade, message injection, etc.).

**Mitigation**:
- **Protocol Version Enforcement**: Strict validation of protocol version (v4.0)
- **Message Structure Validation**: All protocol messages are validated before processing
- **State Machine Enforcement**: Connection state transitions are enforced

**Implementation**: Protocol validation is in `core/src/webrtc.rs`.

**Limitation**: If the protocol itself has design flaws, the core cannot mitigate them.

---

## Threats NOT Mitigated by the Core

### 1. Compromised Operating System

**Threat**: An attacker compromises the operating system (rootkit, kernel exploit, etc.).

**Not Mitigated**: The core cannot protect against OS-level attacks because:
- The core runs with the same privileges as the application
- The core cannot detect OS-level compromise
- The core relies on the OS for memory protection, process isolation, etc.

**Mitigation Responsibility**: Operating system security, hardware security (TPM, secure enclaves).

---

### 2. Compromised Hardware

**Threat**: An attacker compromises hardware (malicious firmware, hardware backdoors, etc.).

**Not Mitigated**: The core cannot protect against hardware-level attacks because:
- The core cannot detect hardware compromise
- The core relies on hardware for cryptographic operations
- The core cannot verify hardware integrity

**Mitigation Responsibility**: Hardware security, secure boot, hardware attestation.

---

### 3. Malicious UI Code

**Threat**: Malicious code in the user interface (XSS, UI spoofing, phishing, etc.).

**Not Mitigated**: The core cannot protect against UI-level attacks because:
- The core has no UI dependencies
- The core cannot verify UI authenticity
- The core cannot prevent UI from displaying incorrect information

**Mitigation Responsibility**: Application layer, UI security best practices.

---

### 4. Side-Channel Attacks

**Threat**: An attacker exploits side channels (timing, power, cache, etc.) to extract secrets.

**Not Mitigated**: The core does not implement side-channel attack mitigations because:
- Side-channel protection requires platform-specific mitigations
- The core uses standard cryptographic libraries that may not implement all mitigations
- Constant-time operations are not guaranteed

**Mitigation Responsibility**: Platform security, cryptographic library implementations, hardware security.

---

### 5. Memory Dump Attacks

**Threat**: An attacker dumps process memory to extract keys and secrets.

**Not Mitigated**: The core cannot protect against memory dump attacks because:
- The core stores keys in memory (required for operation)
- The core cannot prevent memory dumps (OS-level protection required)
- The core cannot detect memory dumps

**Mitigation Responsibility**: Operating system security, process isolation, secure memory, hardware security.

---

### 6. Compromised Random Number Generator

**Threat**: An attacker compromises the random number generator (weak RNG, predictable randomness, etc.).

**Not Mitigated**: The core relies on the platform's RNG (`rand::thread_rng()`). If the RNG is compromised:
- Key generation becomes predictable
- Nonces become predictable
- Security guarantees are weakened

**Mitigation Responsibility**: Platform security, hardware RNG, OS RNG security.

---

### 7. Denial of Service (DoS)

**Threat**: An attacker causes denial of service (resource exhaustion, crash, etc.).

**Not Mitigated**: The core does not implement DoS protection because:
- The core is a cryptographic library, not a network service
- DoS protection requires application-layer logic
- The core cannot prevent resource exhaustion

**Mitigation Responsibility**: Application layer, network infrastructure, rate limiting.

---

### 8. Social Engineering

**Threat**: An attacker tricks users into revealing secrets or bypassing security.

**Not Mitigated**: The core cannot protect against social engineering because:
- The core has no user interaction
- The core cannot verify user intent
- The core cannot prevent users from skipping security checks

**Mitigation Responsibility**: User education, UI security, application design.

---

### 9. Key Storage Attacks

**Threat**: An attacker steals keys from persistent storage (disk, database, etc.).

**Not Mitigated**: The core does not store keys persistently. However, if the application stores keys:
- The core cannot protect keys on disk
- The core cannot verify key storage security
- The core cannot prevent key theft

**Mitigation Responsibility**: Application layer, secure key storage, hardware security modules (HSM).

---

### 10. Compromised Dependencies

**Threat**: An attacker compromises cryptographic dependencies (malicious updates, supply chain attacks, etc.).

**Not Mitigated**: The core relies on external cryptographic libraries. If dependencies are compromised:
- Security guarantees are weakened
- The core cannot detect dependency compromise
- The core cannot verify dependency integrity

**Mitigation Responsibility**: Dependency management, supply chain security, dependency auditing.

---

## Threat Summary Table

| Threat | Core Mitigates | Core Does NOT Mitigate | Mitigation Responsibility |
|--------|---------------|----------------------|--------------------------|
| **MITM Attacks** | ✅ Yes (ECDH, ECDSA, SAS) | ⚠️ Partial (requires user verification) | Core + User |
| **Eavesdropping** | ✅ Yes (AES-256-GCM) | ⚠️ Partial (if keys compromised) | Core |
| **Message Tampering** | ✅ Yes (HMAC, AES-GCM, ECDSA) | ❌ No (if keys compromised) | Core |
| **Replay Attacks** | ✅ Yes (sequence numbers) | ⚠️ Partial (requires app validation) | Core + Application |
| **Perfect Forward Secrecy** | ✅ Yes (ephemeral keys) | ⚠️ Partial (if session keys compromised) | Core |
| **Protocol Attacks** | ✅ Yes (validation, state machine) | ❌ No (if protocol flawed) | Core |
| **Compromised OS** | ❌ No | ❌ No | OS + Hardware |
| **Compromised Hardware** | ❌ No | ❌ No | Hardware |
| **Malicious UI** | ❌ No | ❌ No | Application |
| **Side-Channel Attacks** | ❌ No | ❌ No | Platform + Libraries |
| **Memory Dump Attacks** | ❌ No | ❌ No | OS + Hardware |
| **Compromised RNG** | ❌ No | ❌ No | Platform |
| **Denial of Service** | ❌ No | ❌ No | Application + Network |
| **Social Engineering** | ❌ No | ❌ No | User + Application |
| **Key Storage Attacks** | ❌ No | ❌ No | Application |
| **Compromised Dependencies** | ❌ No | ❌ No | Dependency Management |

---

## Security Boundaries

### Core Security Boundary

The core provides security guarantees **within its execution environment**:

- ✅ Cryptographic operations are secure (assuming secure RNG, secure dependencies)
- ✅ Protocol validation is enforced
- ✅ Key derivation is secure
- ✅ Message encryption/decryption is secure

### Application Security Boundary

The application (including adapters) is responsible for:

- ✅ Platform security (OS, hardware)
- ✅ Network security (WebRTC signaling, transport)
- ✅ UI security (user interaction, display)
- ✅ Application logic security (access control, rate limiting)
- ✅ Key storage security (persistent storage)

### Platform Security Boundary

The platform (OS, hardware) is responsible for:

- ✅ Process isolation
- ✅ Memory protection
- ✅ Secure RNG
- ✅ Hardware security (TPM, secure enclaves)

---

## Conclusion

`securebit_core` mitigates **application-layer cryptographic and protocol threats** but does **not** mitigate **platform-level, hardware-level, or application-level threats**. This is by design:

- The core is a **cryptographic library**, not a platform security framework
- The core provides **cryptographic primitives**, not complete security solutions
- The core focuses on **what it can guarantee** (cryptography, protocol) rather than what it cannot (platform, hardware, UI)

Security researchers should understand these boundaries when auditing the core. The core's security guarantees are **strong within its scope** but **do not extend beyond** its execution environment.

---

**Last Updated**: 2025-12-23  
**Version**: 1.0

