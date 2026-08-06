# securebit_core

Platform-agnostic cryptographic kernel for secure peer-to-peer communication.

`securebit_core` holds every security-critical operation behind SecureBit.chat:
the authenticated key exchange, message and file encryption, and the short
authentication string used to detect a man in the middle. It carries no UI, no
transport and no platform dependency, so the same audited code runs on desktop,
mobile and headless deployments — and so this repository is the only place a
reviewer needs to look.

**License:** Apache-2.0 · **Minimum Rust:** 1.70 · **Security model:** [SECURITY_MODEL.md](SECURITY_MODEL.md) · **Threat model:** [THREAT_MODEL.md](THREAT_MODEL.md)

---

## Contents

- [Scope](#scope)
- [Where to look when auditing](#where-to-look-when-auditing)
- [Cryptographic primitives](#cryptographic-primitives)
- [Web client compatibility](#web-client-compatibility)
- [Installation](#installation)
- [Usage](#usage)
- [Verifying compatibility](#verifying-compatibility)
- [Security model](#security-model)
- [Reporting a vulnerability](#reporting-a-vulnerability)
- [Applications built on this core](#applications-built-on-this-core)
- [License](#license)

---

## Scope

Being precise about the boundary matters more than a long feature list: it tells
a reviewer where to look, and where there is nothing to find.

### In this crate

| Area | What it covers |
|---|---|
| Key exchange | Ephemeral ECDH P-384, ECDSA P-384 signatures over the key packages, HKDF-SHA-256 key schedule |
| Session keys | Separate message, MAC, metadata and fingerprint keys derived from one shared secret |
| Message ratchet | Double Ratchet in the Signal design, giving every message its own key; agreed during the handshake and used only when both peers support it |
| Messages | AES-256-GCM payload, separately encrypted metadata, HMAC-SHA-256 over the canonical payload |
| Verification | Short authentication string derived from the shared secret and both DTLS fingerprints |
| Files and voice notes | Per-file key derivation, per-chunk AES-256-GCM, SHA-256 integrity over the whole file |
| Sessions | Several independent, fully isolated sessions in one process |

### Deliberately not in this crate

- **Transport.** The crate produces and consumes JSON and `SB1:` messages;
  moving them over a WebRTC data channel is the platform layer's job.
- **Audio and video calls.** Call media rides DTLS-SRTP on the same peer
  connection whose fingerprints this crate authenticates during the handshake,
  and call signalling travels as ordinary encrypted messages. There is no media
  code here — do not expect to find any.
- **Storage and I/O.** Nothing is written to disk, and no network call is ever
  made from this crate.
- **UI.** No rendering, no input handling, no platform APIs.

---

## Where to look when auditing

| File | Size | What to review |
|---|---:|---|
| [`src/webrtc.rs`](src/webrtc.rs) | ~1620 lines | Offer/answer construction, signature verification, ECDH, SAS derivation, ratchet negotiation |
| [`src/file_transfer.rs`](src/file_transfer.rs) | ~610 lines | Transfer state machine, consent, chunk validation, integrity check |
| [`src/ratchet.rs`](src/ratchet.rs) | ~570 lines | Double Ratchet: chain and root key derivation, out of order handling, frame authentication |
| [`src/session.rs`](src/session.rs) | ~490 lines | Message encryption and decryption, metadata protection, MAC, chat frame selection |
| [`src/core.rs`](src/core.rs) | ~440 lines | Public API surface and session isolation |
| [`src/crypto.rs`](src/crypto.rs) | ~330 lines | Key-pair generation, generic encrypt/decrypt helpers, measured security level |
| [`src/file_crypto.rs`](src/file_crypto.rs) | ~110 lines | Key fingerprint and per-file key derivation, chunk encryption |

State lives in three places, all behind `Arc<Mutex<_>>` and none of it persisted:
crypto state (key pairs), offer state (ECDH secret, session salt, DTLS
fingerprint) and session keys (message, MAC, metadata keys, key fingerprint,
verification code, and the ratchet state when a session runs one).

---

## Cryptographic primitives

| Purpose | Primitive |
|---|---|
| Key agreement | ECDH, NIST P-384, ephemeral per session |
| Authentication of key packages | ECDSA P-384 with SHA-384 |
| Key derivation | HKDF-SHA-256, 64-byte session salt, distinct `info` label per derived key |
| Message confidentiality | AES-256-GCM, fresh 12-byte nonce per message |
| Message integrity | HMAC-SHA-256 over the canonicalized payload, plus the GCM tag |
| Per-message keys | Double Ratchet (Signal design): HKDF-SHA-256 root steps, HMAC-SHA-256 chain steps, a fresh AES-256-GCM key and nonce for every message |
| File chunks | AES-256-GCM, fresh nonce per chunk, SHA-256 over the whole file |
| MITM detection | 7-digit SAS from HKDF over the shared secret and both DTLS fingerprints |

Forward secrecy works on two levels. The ephemeral ECDH key pair exists only
for the lifetime of a session and is never persisted, so compromising the
device later does not decrypt traffic captured earlier. On top of that, when
both peers support it, the Double Ratchet gives every message its own key,
derived through a one way function and destroyed after use, so even state
captured during a live session does not reach back to earlier messages. With a
peer that lacks ratchet support the session simply stays on the per-session
keys it always had.

All primitives come from the RustCrypto ecosystem (`p384`, `aes-gcm`, `hkdf`,
`hmac`, `sha2`), with `rand` for randomness. There is no `unsafe` code and no
platform-specific dependency.

---

## Web client compatibility

The crate implements the same wire protocol as the SecureBit.chat web client,
so a desktop peer built on it interoperates with a browser peer in either
direction. The compatibility surface is byte-exact:

- **Offer and answer packages** — identical compact field layout and `SB1:gz:` /
  `SB1:bin:` encoding.
- **Signed key exchange** — ECDH P-384 public keys packaged and ECDSA-signed
  (SHA-384) over the same canonical, insertion-ordered JSON the web verifier
  reconstructs.
- **Key schedule** — HKDF-SHA-256 with the same `info` labels and 64-byte salt,
  truncating the P-384 shared secret to 32 bytes exactly as the Web Crypto API
  does.
- **Verification code** — derived from the dedicated fingerprint key and the
  peers' real DTLS fingerprints (colon-separated, lowercased), so both
  implementations reach the same code.
- **Messages** — AES-256-GCM payloads with separately encrypted metadata and an
  HMAC-SHA-256 over the canonicalized payload.
- **Double Ratchet** — the same key derivation tree, header format and frame
  encoding as the web implementation, with support agreed through the same
  handshake field. A web peer and a peer built on this crate ratchet together;
  a peer without support keeps working on the session keys.
- **Files and voice notes** — the same per-file key derivation, chunk framing
  and `file_transfer_*` message shapes.

Voice notes are ordinary file transfers: the recording is encrypted and chunked
through the pipeline above, so it inherits exactly the same guarantees as any
other file.

---

## Installation

```toml
[dependencies]
securebit_core = { git = "https://github.com/SecureBitChat/securebit-core" }
```

---

## Usage

Every call takes an optional session id. Pass `None` for the default session,
or `Some("id")` to run several conversations at once — sessions share no key
material.

### Establishing a session

```rust
use securebit_core::Core;

let core = Core::new();

// Initiator: create an invitation. Passing the real WebRTC SDP binds the
// verification code to the actual DTLS fingerprints, which is what makes it
// meaningful.
let offer = core.create_secure_offer(None, Some(local_offer_sdp))?;

// Responder: derive the session keys and produce an answer.
let answer = core.join_secure_connection(None, offer, Some(local_answer_sdp))?;

// Initiator: verify the answer's signature and complete the key schedule.
let confirmation = core.handle_secure_answer(None, answer)?;
```

### Verifying the peer

Both sides derive the verification code independently. Show it to the user and
have them compare it with the other party over a channel an attacker cannot
control — in person, or a call where they recognise the voice. Only then treat
the session as authenticated.

```rust
let crypto = core.get_session_crypto(None);
let code = crypto["verificationCode"].as_str().unwrap_or("");
```

A code taken from the wire is not a verification. It must be the one this peer
computed for itself, or an attacker in the middle can simply show both sides
the same number.

### Messages

```rust
let encrypted = core.encrypt_enhanced_message(
    None,
    "Hello".to_string(),
    "msg-1".to_string(),
    sequence_number,
)?;

let decrypted = core.decrypt_enhanced_message(None, encrypted)?;
```

Sequence numbers must increase; the receiving side uses them to reject replays.

### Files and voice notes

The crate owns the cryptography and the state machine. Reading the file and
moving the resulting messages over the data channel is the caller's job.

```rust
// Sender
let start = core.file_prepare_outgoing(None, file_id.clone(), name, mime, data_base64)?;
while let Ok(chunk) = core.file_next_chunk(None, file_id.clone()) {
    // send `chunk` over the data channel
}

// Receiver
let event = core.file_handle_incoming(None, message_json)?;
core.file_accept(None, file_id)?;   // or file_reject(..)
```

Nothing is buffered before the receiving side accepts, so an unwanted transfer
costs no memory.

---

## Verifying compatibility

```bash
cargo test
```

The suite pins the properties an audit should care about:

| Test | What it proves |
|---|---|
| `offer_e_signature_is_web_verifiable` | Key packages verify under the web client's exact reconstruction |
| `answer_e_signature_is_web_verifiable` | The same, for the answering side |
| `offer_join_handle_roundtrip` | Full handshake; both sides reach the same keys |
| `both_peers_derive_the_same_sas_independently` | Neither peer takes the verification code from the wire |
| `sas_matches_web_reference_vector` | The code equals the web implementation's output for a fixed input |
| `sas_is_orientation_independent` | Fingerprint order cannot change the code |
| `key_fingerprint_matches_web_reference` | File-key derivation matches the web client byte for byte |
| `chunk_aes_gcm_matches_web` | Chunk encryption is interoperable |
| `full_round_trip` | A file survives the whole pipeline intact |
| `duplicate_chunk_is_idempotent` | A replayed chunk cannot corrupt the result |
| `corrupted_chunk_fails_decryption` | Tampering is detected rather than silently accepted |
| `rejection_stops_transfer` | Refusal leaves no state behind |
| `handshake_brings_up_an_interoperating_ratchet` | A full handshake leaves both sides ratcheting together |
| `offer_and_answer_advertise_ratchet_support` | Ratchet support is announced where the web client expects it |
| `full_conversation_with_direction_changes` | The ratchet survives replies, gaps and both directions |
| `tampered_frame_leaves_no_trace` | A forged ratchet frame fails without desynchronising the session |
| `replay_is_rejected` | A ratchet frame cannot be delivered twice |

The desktop repository additionally runs the real web `DoubleRatchet.js`
against this crate over live frames in both directions, as part of its
interoperability suite.

---

## Security model

**Guaranteed here:** confidentiality and integrity of messages and files under
the derived session keys; authentication of the key exchange; forward secrecy
from ephemeral keys, and per message when both peers run the Double Ratchet; a
deterministic verification code for MITM detection; strict validation of every
input parsed from the wire.

**Not guaranteed here**, and out of scope by design:

- Compromised operating system, hardware, or a malicious peer device
- Malicious or compromised UI in the embedding application
- Side channels: timing, power, cache
- Memory disclosure of the host process
- Denial of service and resource exhaustion
- Network-level attacks beyond what the protocol itself detects

[SECURITY_MODEL.md](SECURITY_MODEL.md) and [THREAT_MODEL.md](THREAT_MODEL.md)
cover both lists in detail.

---

## Reporting a vulnerability

Please report privately rather than opening a public issue.

- Email: security@securebit.chat
- Include a description, the affected commit, and a reproduction if you have one
- Responsible disclosure, 90-day window

---

## Applications built on this core

| Application | Repository | Notes |
|---|---|---|
| Web client | [securebit-chat](https://github.com/SecureBitChat/securebit-chat) | Fully open source, MIT |
| Desktop apps | [securebit-desktop](https://github.com/SecureBitChat/securebit-desktop) | Windows, macOS, Linux |

The desktop applications are proprietary wrappers — UI and platform
integration only. Every cryptographic operation they perform comes from this
repository, which is what makes an audit of this crate meaningful for them too.

Mobile applications and store distribution are planned; their cryptography will
come from here as well.

---

## License

Apache-2.0. See [LICENSE](LICENSE).
