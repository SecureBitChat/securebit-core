// Double Ratchet (Signal specification), byte-compatible with the SecureBit.chat
// web reference implementation (src/crypto/DoubleRatchet.js, web release 5.7.1).
//
// WIRE COMPATIBILITY — every constant and encoding here is dictated by the web
// peer and must not change independently:
//
//   - Root/chain KDFs: HKDF-SHA-256 with info strings 'SecureBit-DR-Init-v1',
//     'SecureBit-DR-Root-v1', 'SecureBit-DR-Message-v1'.
//   - Chain advance (KDF_CK): message key = HMAC-SHA-256(ck, 0x01),
//     next chain key = HMAC-SHA-256(ck, 0x02).
//   - Per-message cipher: HKDF(mk, salt = 32 zero bytes, info
//     'SecureBit-DR-Message-v1', 44 bytes) → AES-256-GCM key (32) + IV (12).
//   - DH: ECDH P-384, shared secret truncated to the first 32 bytes — WebCrypto's
//     deriveBits(256) does exactly this, and the handshake already relies on it.
//   - Ratchet public keys travel as base64(SPKI DER).
//   - The header is the exact JSON string `{"dh":"…","pn":N,"n":N}` and doubles
//     as the AES-GCM AAD. It must be transmitted and consumed VERBATIM: web
//     peers feed the received string straight back as AAD, so re-serialising it
//     (key order, whitespace) breaks authentication for no reason.
//
// The staging discipline mirrors the web class: the header is attacker-reachable
// plaintext, so no ratchet state is committed until the frame authenticates.
// A forged frame must leave no trace, or one bad frame desynchronises a live
// session permanently.

use aes_gcm::{aead::{Aead, Payload}, Aes256Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose, Engine};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p384::pkcs8::{DecodePublicKey, EncodePublicKey};
use sha2::Sha256;
use zeroize::Zeroize;

const ROOT_INFO: &[u8] = b"SecureBit-DR-Root-v1";
const MESSAGE_INFO: &[u8] = b"SecureBit-DR-Message-v1";
const INIT_INFO: &[u8] = b"SecureBit-DR-Init-v1";

const MK_SEED: [u8; 1] = [0x01];
const CK_SEED: [u8; 1] = [0x02];

/// Bounds on out-of-order tolerance. A DoS control, not a tuning knob: every
/// skipped message forces us to derive and RETAIN a key, so a peer who can pick
/// message numbers could otherwise allocate without limit. Values are the web
/// client's RATCHET_LIMITS and both sides must agree on the behaviour they imply.
pub const MAX_SKIP_PER_CHAIN: u64 = 512;
pub const MAX_SKIPPED_KEYS: usize = 1024;
pub const SKIPPED_KEY_TTL_MS: i64 = 5 * 60 * 1000;

/// Advertised in the offer/answer as `dr`. Peers compare it and fall back to
/// static session keys when it is absent or unknown (web RATCHET_VERSION).
pub const RATCHET_VERSION: u64 = 1;

type HmacSha256 = Hmac<Sha256>;

fn hkdf_expand(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), String> {
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, out)
        .map_err(|e| format!("HKDF expand failed: {:?}", e))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// KDF_CK — advance a chain and emit this message's key. One-way by construction.
fn advance_chain(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    (hmac_sha256(chain_key, &MK_SEED), hmac_sha256(chain_key, &CK_SEED))
}

/// KDF_RK — mix a fresh DH secret into the root key, yielding the next chain.
fn advance_root(root_key: &[u8; 32], dh_output: &[u8]) -> Result<([u8; 32], [u8; 32]), String> {
    let mut derived = [0u8; 64];
    hkdf_expand(dh_output, root_key, ROOT_INFO, &mut derived)?;
    let mut next_root = [0u8; 32];
    let mut chain_key = [0u8; 32];
    next_root.copy_from_slice(&derived[..32]);
    chain_key.copy_from_slice(&derived[32..]);
    derived.zeroize();
    Ok((next_root, chain_key))
}

/// ECDH with the WebCrypto convention the whole protocol uses: P-384 shared
/// secret truncated to its first 32 bytes (deriveBits(256)).
fn dh(private: &p384::SecretKey, public: &p384::PublicKey) -> [u8; 32] {
    let shared = p384::ecdh::diffie_hellman(private.to_nonzero_scalar(), public.as_affine());
    let full = shared.raw_secret_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&full[..32]);
    out
}

fn export_spki_b64(public: &p384::PublicKey) -> Result<String, String> {
    let der = public
        .to_public_key_der()
        .map_err(|e| format!("SPKI export failed: {}", e))?;
    Ok(general_purpose::STANDARD.encode(der.as_bytes()))
}

fn import_spki_b64(spki_b64: &str) -> Result<p384::PublicKey, String> {
    let der = general_purpose::STANDARD
        .decode(spki_b64)
        .map_err(|e| format!("ratchet key base64 decode failed: {}", e))?;
    p384::PublicKey::from_public_key_der(&der)
        .map_err(|e| format!("ratchet key import failed: {}", e))
}

/// Derive the AES-GCM key and IV for one message. The message key is consumed
/// exactly once; callers zeroize it immediately after.
fn message_cipher(message_key: &[u8; 32]) -> Result<(Aes256Gcm, [u8; 12]), String> {
    let mut material = [0u8; 44];
    hkdf_expand(message_key, &[0u8; 32], MESSAGE_INFO, &mut material)?;
    let cipher = Aes256Gcm::new_from_slice(&material[..32])
        .map_err(|e| format!("AES key setup failed: {}", e))?;
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&material[32..44]);
    material.zeroize();
    Ok((cipher, iv))
}

fn open_with(message_key: &[u8; 32], header: &str, ciphertext_b64: &str) -> Result<String, String> {
    let (cipher, iv) = message_cipher(message_key)?;
    let body = general_purpose::STANDARD
        .decode(ciphertext_b64)
        .map_err(|_| "DoubleRatchet: malformed ciphertext".to_string())?;
    let opened = cipher
        .decrypt(&Nonce::from(iv), Payload { msg: &body, aad: header.as_bytes() })
        // Wrong key, tampered body, or a tampered header — AES-GCM cannot tell
        // us which, and neither should we: the answer is the same.
        .map_err(|_| "DoubleRatchet: authentication failed".to_string())?;
    String::from_utf8(opened).map_err(|_| "DoubleRatchet: invalid UTF-8 plaintext".to_string())
}

struct SkippedKey {
    id: String,
    key: [u8; 32],
    stored_at: i64,
}

impl Drop for SkippedKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

pub struct DoubleRatchet {
    root_key: [u8; 32],
    sending_chain_key: Option<[u8; 32]>,
    receiving_chain_key: Option<[u8; 32]>,
    self_private: p384::SecretKey,
    self_public_b64: Option<String>,
    remote_public_b64: Option<String>,
    send_count: u64,          // Ns
    receive_count: u64,       // Nr
    previous_send_count: u64, // PN
    // Insertion-ordered so eviction drops the oldest first, like the web Map.
    skipped: Vec<SkippedKey>,
}

impl DoubleRatchet {
    /// The side that created the offer. Adopts a fresh ratchet key immediately
    /// and steps the root once, so its very first message already leaves the
    /// handshake key behind. `remote_public_b64` deliberately starts as None:
    /// the peer's first message carries their own fresh ratchet key and must
    /// read as a new chain (web keeps it null for the same reason).
    pub fn init_initiator(
        shared_secret: &[u8],
        session_salt: &[u8],
        remote_handshake_public: &p384::PublicKey,
    ) -> Result<Self, String> {
        let mut init_root = [0u8; 32];
        hkdf_expand(shared_secret, session_salt, INIT_INFO, &mut init_root)?;

        let fresh = p384::SecretKey::random(&mut rand::thread_rng());
        let self_public_b64 = export_spki_b64(&fresh.public_key())?;

        let mut dh_out = dh(&fresh, remote_handshake_public);
        let (root_key, sending_chain_key) = advance_root(&init_root, &dh_out)?;
        dh_out.zeroize();
        init_root.zeroize();

        Ok(Self {
            root_key,
            sending_chain_key: Some(sending_chain_key),
            receiving_chain_key: None,
            self_private: fresh,
            self_public_b64: Some(self_public_b64),
            remote_public_b64: None,
            send_count: 0,
            receive_count: 0,
            previous_send_count: 0,
            skipped: Vec::new(),
        })
    }

    /// The side that joined. Keeps the handshake key pair as the current ratchet
    /// pair so the initiator's first DH lands on a key we hold, and takes no
    /// sending chain until that message arrives — `can_encrypt` is false until
    /// then, which is inherent to the ratchet, not an implementation gap.
    pub fn init_responder(
        shared_secret: &[u8],
        session_salt: &[u8],
        self_handshake_private: p384::SecretKey,
    ) -> Result<Self, String> {
        let mut root_key = [0u8; 32];
        hkdf_expand(shared_secret, session_salt, INIT_INFO, &mut root_key)?;

        Ok(Self {
            root_key,
            sending_chain_key: None,
            receiving_chain_key: None,
            self_private: self_handshake_private,
            self_public_b64: None,
            remote_public_b64: None,
            send_count: 0,
            receive_count: 0,
            previous_send_count: 0,
            skipped: Vec::new(),
        })
    }

    /// False on the responder until the initiator's first message arrives.
    /// Callers must check this and fall back to the static session keys for
    /// those few frames, exactly as the web client does.
    pub fn can_encrypt(&self) -> bool {
        self.sending_chain_key.is_some()
    }

    /// Diagnostics only — deliberately exposes no key material.
    pub fn state_json(&self) -> serde_json::Value {
        serde_json::json!({
            "initialised": true,
            "sending": self.sending_chain_key.is_some(),
            "receiving": self.receiving_chain_key.is_some(),
            "sendCount": self.send_count,
            "receiveCount": self.receive_count,
            "previousSendCount": self.previous_send_count,
            "skippedKeys": self.skipped.len(),
        })
    }

    /// Returns (header, ciphertext_b64). The header is the exact string that
    /// must go on the wire: it is the AAD.
    pub fn encrypt(&mut self, plaintext: &str) -> Result<(String, String), String> {
        let chain = self
            .sending_chain_key
            .as_mut()
            .ok_or_else(|| "DoubleRatchet: no sending chain — awaiting the peer's first message".to_string())?;
        let self_public = self
            .self_public_b64
            .clone()
            .ok_or_else(|| "DoubleRatchet: no ratchet public key to announce".to_string())?;

        let (mut message_key, next_chain) = advance_chain(chain);
        chain.zeroize();
        *chain = next_chain;

        // Field order and formatting must match JSON.stringify({dh, pn, n}).
        let header = format!(
            r#"{{"dh":"{}","pn":{},"n":{}}}"#,
            self_public, self.previous_send_count, self.send_count
        );
        self.send_count += 1;

        let (cipher, iv) = message_cipher(&message_key)?;
        message_key.zeroize();

        let ciphertext = cipher
            .encrypt(&Nonce::from(iv), Payload { msg: plaintext.as_bytes(), aad: header.as_bytes() })
            .map_err(|e| format!("DoubleRatchet: encryption failed: {}", e))?;

        Ok((header, general_purpose::STANDARD.encode(ciphertext)))
    }

    /// `header` must be exactly the string the peer produced — it is the AAD.
    /// No state is committed unless the frame authenticates.
    pub fn decrypt(&mut self, header: &str, ciphertext_b64: &str) -> Result<String, String> {
        let parsed: serde_json::Value =
            serde_json::from_str(header).map_err(|_| "DoubleRatchet: malformed header".to_string())?;
        let dh_b64 = parsed
            .get("dh")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "DoubleRatchet: invalid header fields".to_string())?
            .to_string();
        let pn = parsed
            .get("pn")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| "DoubleRatchet: invalid header fields".to_string())?;
        let n = parsed
            .get("n")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| "DoubleRatchet: invalid header fields".to_string())?;

        self.prune_skipped();

        // A key retained for a message that arrived late. Only drop it once the
        // message actually opens: a forged frame quoting a real header must not
        // consume the key that the genuine message still needs.
        let skipped_id = format!("{}|{}", dh_b64, n);
        if let Some(pos) = self.skipped.iter().position(|s| s.id == skipped_id) {
            let plaintext = open_with(&self.skipped[pos].key, header, ciphertext_b64)?;
            self.skipped.remove(pos); // Drop zeroizes the key.
            return Ok(plaintext);
        }

        // Everything below is computed on locals and only assigned to `self`
        // once the message authenticates (the commit block at the end).
        let is_new_chain = Some(dh_b64.as_str()) != self.remote_public_b64.as_deref();

        let mut pending: Vec<SkippedKey> = Vec::new();
        // Staged DH-ratchet result, applied only on commit.
        let mut staged_ratchet: Option<(p384::SecretKey, String, [u8; 32], [u8; 32])> = None;

        let (chain_key, receive_from, remote_b64) = if is_new_chain {
            // Keys for messages still missing from the OLD chain, before it is
            // replaced. `pn` says how long that chain was.
            if let Some(old_chain) = self.receiving_chain_key {
                let old_remote = self.remote_public_b64.clone().unwrap_or_else(|| "null".to_string());
                let (keys, mut final_ck) =
                    collect_skipped(&old_chain, self.receive_count, pn, &old_remote)?;
                pending.extend(keys);
                final_ck.zeroize();
            }

            // The DH-ratchet step, computed without touching `self`.
            let remote_public = import_spki_b64(&dh_b64)?;

            // Receiving chain: our CURRENT key pair against their new key. For
            // the responder's first ratchet this is still the handshake key
            // pair, which is exactly what the initiator derived against at init.
            let mut receive_dh = dh(&self.self_private, &remote_public);
            let (mut received_root, receiving_chain) = advance_root(&self.root_key, &receive_dh)?;
            receive_dh.zeroize();

            // Sending chain: a fresh key pair, so our next message moves the
            // ratchet on again — the step that locks out an attacker who
            // captured the previous state.
            let next_private = p384::SecretKey::random(&mut rand::thread_rng());
            let next_public_b64 = export_spki_b64(&next_private.public_key())?;
            let mut send_dh = dh(&next_private, &remote_public);
            let (next_root, sending_chain) = advance_root(&received_root, &send_dh)?;
            send_dh.zeroize();
            received_root.zeroize();

            staged_ratchet = Some((next_private, next_public_b64, next_root, sending_chain));
            (receiving_chain, 0u64, dh_b64.clone())
        } else {
            let chain = self
                .receiving_chain_key
                .ok_or_else(|| "DoubleRatchet: no receiving chain for this message".to_string())?;
            let remote = self.remote_public_b64.clone().unwrap_or_else(|| "null".to_string());
            (chain, self.receive_count, remote)
        };

        let (gap_keys, final_chain) = collect_skipped(&chain_key, receive_from, n, &remote_b64)?;
        pending.extend(gap_keys);

        let (mut message_key, next_chain) = advance_chain(&final_chain);

        let plaintext = match open_with(&message_key, header, ciphertext_b64) {
            Ok(p) => p,
            Err(e) => {
                // Discard: locals (and `pending` via Drop) are zeroized; `self`
                // was never touched, so a forged frame leaves no trace.
                message_key.zeroize();
                drop(pending);
                return Err(e);
            }
        };

        // Commit.
        message_key.zeroize();
        if let Some((next_private, next_public_b64, next_root, sending_chain)) = staged_ratchet {
            self.root_key.zeroize();
            self.root_key = next_root;
            if let Some(ref mut sck) = self.sending_chain_key {
                sck.zeroize();
            }
            self.sending_chain_key = Some(sending_chain);
            self.self_private = next_private;
            self.self_public_b64 = Some(next_public_b64);
            self.previous_send_count = self.send_count;
            self.send_count = 0;
        }
        if let Some(ref mut rck) = self.receiving_chain_key {
            rck.zeroize();
        }
        self.receiving_chain_key = Some(next_chain);
        self.receive_count = n + 1;
        self.remote_public_b64 = Some(remote_b64);
        for key in pending {
            self.remember_skipped(key);
        }

        Ok(plaintext)
    }

    fn remember_skipped(&mut self, key: SkippedKey) {
        // Oldest-first eviction keeps the cache bounded even if every gap is
        // legitimate; losing the oldest gap is preferable to unbounded growth.
        while self.skipped.len() >= MAX_SKIPPED_KEYS {
            self.skipped.remove(0); // Drop zeroizes.
        }
        self.skipped.push(key);
    }

    fn prune_skipped(&mut self) {
        let cutoff = chrono::Utc::now().timestamp_millis() - SKIPPED_KEY_TTL_MS;
        self.skipped.retain(|s| s.stored_at >= cutoff); // Drop zeroizes removed keys.
    }
}

/// Derive the keys for messages `from`..`until-1` without mutating any state.
/// `until` comes off the wire, so the jump is bounded here rather than trusted.
fn collect_skipped(
    chain_key: &[u8; 32],
    from: u64,
    until: u64,
    remote_b64: &str,
) -> Result<(Vec<SkippedKey>, [u8; 32]), String> {
    if until < from {
        // An older number on a chain we have already advanced past: either a
        // replay or a duplicate. Its key is gone, so it cannot be opened.
        return Err("DoubleRatchet: message number is behind the current chain".to_string());
    }
    if until - from > MAX_SKIP_PER_CHAIN {
        return Err(format!(
            "DoubleRatchet: refusing to skip {} messages (limit {})",
            until - from,
            MAX_SKIP_PER_CHAIN
        ));
    }

    let now = chrono::Utc::now().timestamp_millis();
    let mut keys = Vec::new();
    let mut current = *chain_key;
    for i in from..until {
        let (message_key, next_chain) = advance_chain(&current);
        current.zeroize();
        current = next_chain;
        keys.push(SkippedKey {
            id: format!("{}|{}", remote_b64, i),
            key: message_key,
            stored_at: now,
        });
    }
    Ok((keys, current))
}

impl Drop for DoubleRatchet {
    fn drop(&mut self) {
        self.root_key.zeroize();
        if let Some(ref mut k) = self.sending_chain_key {
            k.zeroize();
        }
        if let Some(ref mut k) = self.receiving_chain_key {
            k.zeroize();
        }
        // self_private: p384::SecretKey zeroizes on drop (elliptic-curve crate);
        // skipped keys zeroize in SkippedKey::drop.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (DoubleRatchet, DoubleRatchet) {
        let root = [7u8; 32];
        let salt = [9u8; 64];
        let responder_handshake = p384::SecretKey::random(&mut rand::thread_rng());
        let initiator =
            DoubleRatchet::init_initiator(&root, &salt, &responder_handshake.public_key()).unwrap();
        let responder = DoubleRatchet::init_responder(&root, &salt, responder_handshake).unwrap();
        (initiator, responder)
    }

    #[test]
    fn initiator_can_send_immediately_responder_cannot() {
        let (a, b) = pair();
        assert!(a.can_encrypt());
        assert!(!b.can_encrypt());
    }

    #[test]
    fn full_conversation_with_direction_changes() {
        let (mut a, mut b) = pair();

        let (h, c) = a.encrypt("hello from A").unwrap();
        assert_eq!(b.decrypt(&h, &c).unwrap(), "hello from A");
        assert!(b.can_encrypt(), "responder gains a sending chain after the first inbound");

        let (h, c) = b.encrypt("hello from B").unwrap();
        assert_eq!(a.decrypt(&h, &c).unwrap(), "hello from B");

        // Several messages one way, then back — exercises PN bookkeeping.
        for i in 0..5 {
            let (h, c) = a.encrypt(&format!("a{}", i)).unwrap();
            assert_eq!(b.decrypt(&h, &c).unwrap(), format!("a{}", i));
        }
        let (h, c) = b.encrypt("reply").unwrap();
        assert_eq!(a.decrypt(&h, &c).unwrap(), "reply");
    }

    #[test]
    fn out_of_order_within_a_chain() {
        let (mut a, mut b) = pair();
        let m0 = a.encrypt("m0").unwrap();
        let m1 = a.encrypt("m1").unwrap();
        let m2 = a.encrypt("m2").unwrap();

        assert_eq!(b.decrypt(&m2.0, &m2.1).unwrap(), "m2");
        // Late arrivals open from retained keys.
        assert_eq!(b.decrypt(&m0.0, &m0.1).unwrap(), "m0");
        assert_eq!(b.decrypt(&m1.0, &m1.1).unwrap(), "m1");
    }

    #[test]
    fn replay_is_rejected() {
        let (mut a, mut b) = pair();
        let (h, c) = a.encrypt("once").unwrap();
        assert_eq!(b.decrypt(&h, &c).unwrap(), "once");
        assert!(b.decrypt(&h, &c).is_err(), "second delivery of the same frame must fail");
    }

    #[test]
    fn tampered_frame_leaves_no_trace() {
        let (mut a, mut b) = pair();
        let (h, c) = a.encrypt("first").unwrap();

        // Tamper with the header (AAD) — authentication must fail…
        let bad_header = h.replace("\"n\":0", "\"n\":1");
        assert!(b.decrypt(&bad_header, &c).is_err());

        // …and the genuine frame must still open afterwards: no state was burned.
        assert_eq!(b.decrypt(&h, &c).unwrap(), "first");
    }

    #[test]
    fn excessive_skip_is_refused() {
        let (mut a, mut b) = pair();
        let (h, c) = a.encrypt("seed").unwrap();
        b.decrypt(&h, &c).unwrap();

        // Forge a header far ahead; bound must trip before any allocation.
        let dh = serde_json::from_str::<serde_json::Value>(&h).unwrap()["dh"]
            .as_str()
            .unwrap()
            .to_string();
        let forged = format!(r#"{{"dh":"{}","pn":0,"n":{}}}"#, dh, 2 + MAX_SKIP_PER_CHAIN);
        let err = b.decrypt(&forged, &c).unwrap_err();
        assert!(err.contains("refusing to skip"), "got: {}", err);
    }

    #[test]
    fn header_format_matches_web_json_stringify() {
        let (mut a, _b) = pair();
        let (h, _c) = a.encrypt("x").unwrap();
        let v: serde_json::Value = serde_json::from_str(&h).unwrap();
        // Exact re-serialisation equality proves compact formatting and field order.
        assert_eq!(serde_json::to_string(&v).unwrap(), h);
        assert!(h.starts_with(r#"{"dh":""#));
        assert!(h.ends_with(r#","n":0}"#));
    }
}
