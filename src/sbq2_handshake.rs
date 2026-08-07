//! The SBQ2 handshake, as the desktop performs it.
//!
//! Kept separate from `webrtc.rs` on purpose. That module's job is the SB1
//! packages, where the peer's keys arrive inside the offer and the session can
//! be derived on the spot. Here there are no peer keys at the point the answer
//! is produced — only a fingerprint and a commitment — so folding the two
//! together would mean threading "do we have keys yet?" through every phase of a
//! function that already runs to hundreds of lines.
//!
//! Division of labour with the UI: the webview owns the RTCPeerConnection and
//! the data channel, this owns the descriptor and the key schedule. The two
//! in-band frames (`key_blob`, `key_proof`) are relayed by the webview; every
//! decision about them is made here.

use crate::descriptor::{self, DescriptorType, EncodeParams};
use crate::error::CoreError;
use crate::keyexchange::{self, Role};
use crate::session::{OfferContext, Sbq2State, SessionKeys};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use hkdf::Hkdf;
use p384::ecdsa::{Signature, SigningKey, VerifyingKey};
use p384::pkcs8::{DecodePublicKey, EncodePublicKey};
use p384::PublicKey as P384Pub;
use sha2::{Digest, Sha256, Sha384};
use std::sync::{Arc, Mutex};

/// ── SBQ2 ROLLBACK SWITCH ────────────────────────────────────────────────
/// Flip this ONE value to `false` and rebuild to put every new invitation back
/// on the SB1 format. It governs only what we EMIT: reception of both formats is
/// unconditional and never consults it, so a build with this off still reads
/// SBQ2 invitations from a peer that has it on.
pub const SBQ2_SEND_ENABLED: bool = true;

/// How long an invitation stays valid.
const LIFETIME_MS: i64 = 10 * 60 * 1000;

fn now_ms() -> i64 { chrono::Utc::now().timestamp_millis() }
fn bad(m: impl Into<String>) -> CoreError { CoreError::invalid_input(m.into()) }
fn lock_err() -> CoreError { CoreError::state_error("Failed to acquire offer_state lock") }

/// True when a payload is an SBQ2 descriptor rather than an SB1 package.
pub fn is_sbq2(payload: &str) -> bool { descriptor::looks_like_sbq2(payload) }

fn spki_of_ecdh(sk: &p384::SecretKey) -> Result<Vec<u8>, CoreError> {
    sk.public_key().to_public_key_der()
        .map_err(|e| CoreError::crypto_failure(format!("ECDH SPKI export failed: {}", e)))
        .map(|d| d.as_bytes().to_vec())
}
fn spki_of_ecdsa(vk: &VerifyingKey) -> Result<Vec<u8>, CoreError> {
    vk.to_public_key_der()
        .map_err(|e| CoreError::crypto_failure(format!("ECDSA SPKI export failed: {}", e)))
        .map(|d| d.as_bytes().to_vec())
}

/// Build our key blob and the commitment that goes into the descriptor. Called
/// while the descriptor is being made, so the commitment is fixed before
/// anything is shown to the user.
fn build_local_blob(
    role: Role, ecdh: &p384::SecretKey, ecdsa: &SigningKey,
) -> Result<(Vec<u8>, [u8; descriptor::COMMITMENT_BYTES]), CoreError> {
    let blob = keyexchange::encode_key_blob(
        role, &spki_of_ecdh(ecdh)?, &spki_of_ecdsa(ecdsa.verifying_key())?)?;
    let commitment = descriptor::commit_blob(&blob);
    Ok((blob, commitment))
}

/// Create an SBQ2 invitation from the SDP the webview gathered.
pub fn create_offer(
    offer_state: Arc<Mutex<OfferContext>>, offer_sdp: String,
) -> Result<String, CoreError> {
    let ecdh = p384::SecretKey::random(&mut rand::thread_rng());
    let ecdsa = SigningKey::random(&mut rand::thread_rng());
    let (blob, commitment) = build_local_blob(Role::Offer, &ecdh, &ecdsa)?;

    let raw = descriptor::parse_sdp(&offer_sdp)?;
    let fields = descriptor::SdpFields {
        candidates: descriptor::prune_candidates(&raw.candidates), ..raw
    };
    let bytes = descriptor::encode_descriptor(&EncodeParams {
        dtype: DescriptorType::Offer,
        binding_tag: None,
        expires_at_ms: now_ms() + LIFETIME_MS,
        fields: &fields,
        commitment: Some(commitment),
    })?;

    let mut st = offer_state.lock().map_err(|_| lock_err())?;
    let mut s = Sbq2State::new(Role::Offer);
    s.local_descriptor = Some(bytes.clone());
    s.local_blob = Some(blob);
    s.ecdsa_signing = Some(ecdsa);
    st.sbq2 = Some(s);
    st.ecdh_secret = Some(ecdh);
    st.local_dtls_fingerprint = Some(hex::encode(fields.fingerprint));

    Ok(descriptor::encode_text(&bytes))
}

/// Decode an invitation without committing to it — the UI shows the peer's SDP
/// and its own state before the user accepts.
pub fn parse_offer(offer_data: &str) -> Result<serde_json::Value, CoreError> {
    let bytes = descriptor::decode_text(offer_data)?;
    let d = descriptor::decode_descriptor(&bytes, now_ms())?;
    if d.dtype != DescriptorType::Offer {
        return Err(bad("that code is a response, not an invitation"));
    }
    Ok(serde_json::json!({
        "format": "sbq2",
        "type": "offer",
        "sdp": descriptor::serialize_sdp(&d),
        "fingerprint": d.fingerprint.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(":"),
        "candidates": d.candidates.len(),
        "expiresAtMs": d.expires_at_ms,
        "hasCommitment": d.commitment.is_some(),
        "bytes": bytes.len(),
    }))
}

/// Answer an SBQ2 invitation. No key is imported and no secret derived here —
/// none has been sent yet.
pub fn join(
    offer_state: Arc<Mutex<OfferContext>>, offer_data: &str, answer_sdp: String,
) -> Result<String, CoreError> {
    let offer_bytes = descriptor::decode_text(offer_data)?;
    let od = descriptor::decode_descriptor(&offer_bytes, now_ms())?;
    if od.dtype != DescriptorType::Offer {
        return Err(bad("that code is a response, not an invitation"));
    }
    // Without a commitment nothing binds the in-band key material to the code the
    // user scanned, which is the entire basis for moving it in band.
    let commitment = od.commitment.ok_or_else(|| bad("the invitation carries no key commitment"))?;

    let ecdh = p384::SecretKey::random(&mut rand::thread_rng());
    let ecdsa = SigningKey::random(&mut rand::thread_rng());
    let (blob, our_commitment) = build_local_blob(Role::Answer, &ecdh, &ecdsa)?;

    let raw = descriptor::parse_sdp(&answer_sdp)?;
    let fields = descriptor::SdpFields {
        candidates: descriptor::prune_candidates(&raw.candidates), ..raw
    };
    let bytes = descriptor::encode_descriptor(&EncodeParams {
        dtype: DescriptorType::Answer,
        binding_tag: Some(descriptor::binding_tag(&offer_bytes)),
        expires_at_ms: now_ms() + LIFETIME_MS,
        fields: &fields,
        commitment: Some(our_commitment),
    })?;

    let mut st = offer_state.lock().map_err(|_| lock_err())?;
    let mut s = Sbq2State::new(Role::Answer);
    s.local_descriptor = Some(bytes.clone());
    s.remote_descriptor = Some(offer_bytes);
    s.remote_commitment = Some(commitment);
    s.local_blob = Some(blob);
    s.ecdsa_signing = Some(ecdsa);
    st.sbq2 = Some(s);
    st.ecdh_secret = Some(ecdh);
    st.local_dtls_fingerprint = Some(hex::encode(fields.fingerprint));

    Ok(descriptor::encode_text(&bytes))
}

/// Accept the response on the inviting side. Verifies that it answers THIS
/// invitation and nothing else, which is what makes each invitation one-shot.
pub fn handle_answer(
    offer_state: Arc<Mutex<OfferContext>>, answer_data: &str,
) -> Result<serde_json::Value, CoreError> {
    let answer_bytes = descriptor::decode_text(answer_data)?;
    let ad = descriptor::decode_descriptor(&answer_bytes, now_ms())?;
    if ad.dtype != DescriptorType::Answer {
        return Err(bad("that code is an invitation, not a response to one"));
    }
    let commitment = ad.commitment.ok_or_else(|| bad("the response carries no key commitment"))?;
    let tag = ad.binding_tag.ok_or_else(|| bad("the response carries no binding tag"))?;

    let mut st = offer_state.lock().map_err(|_| lock_err())?;
    let s = st.sbq2.as_mut().ok_or_else(|| {
        // We advertised SB1 and got SBQ2 back. Refuse rather than switch: an
        // established session's format is latched, and this is the shape a
        // format-confusion attack would take.
        bad("received a new-format response to an old-format invitation; start a new invitation")
    })?;
    let local = s.local_descriptor.clone().ok_or_else(|| bad("no invitation is currently open"))?;

    let expected = descriptor::binding_tag(&local);
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(tag.iter()) { diff |= a ^ b; }
    if diff != 0 {
        return Err(bad("this response belongs to a different invitation; ask for a response \
                        to the code you are showing now"));
    }

    s.remote_descriptor = Some(answer_bytes);
    s.remote_commitment = Some(commitment);

    Ok(serde_json::json!({
        "format": "sbq2",
        "sdp": descriptor::serialize_sdp(&ad),
        "fingerprint": ad.fingerprint.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(":"),
    }))
}

/// Our key blob, base64, for the webview to send as the first data-channel frame.
pub fn local_key_blob(offer_state: Arc<Mutex<OfferContext>>) -> Result<String, CoreError> {
    let st = offer_state.lock().map_err(|_| lock_err())?;
    let s = st.sbq2.as_ref().ok_or_else(|| bad("this session is not an SBQ2 session"))?;
    let blob = s.local_blob.as_ref().ok_or_else(|| bad("no key blob has been built"))?;
    Ok(B64.encode(blob))
}

/// Accept the peer's key blob and close the handshake.
///
/// The commitment is checked FIRST, against raw bytes, so a substituted blob
/// never reaches `decode_key_blob` or any key import. Only then is the transcript
/// defined, the salt derived from it, the session keys installed, and the proof
/// signed.
pub fn accept_peer_blob(
    offer_state: Arc<Mutex<OfferContext>>,
    session_keys: Arc<Mutex<SessionKeys>>,
    peer_blob_b64: &str,
) -> Result<serde_json::Value, CoreError> {
    let peer_bytes = B64.decode(peer_blob_b64.trim())
        .map_err(|e| bad(format!("key blob is not valid base64: {}", e)))?;

    let mut st = offer_state.lock().map_err(|_| lock_err())?;
    let ecdh = st.ecdh_secret.clone().ok_or_else(|| bad("no ECDH key for this session"))?;
    let s = st.sbq2.as_mut().ok_or_else(|| bad("this session is not an SBQ2 session"))?;
    if s.remote_blob.is_some() {
        // A second blob means a confused peer or an attempt to replace key
        // material after it was accepted.
        return Err(bad("the key material was sent twice"));
    }
    let expected = s.remote_commitment.ok_or_else(|| bad("no commitment to check the key material against"))?;

    // ── the gate ──
    keyexchange::verify_blob_commitment(&peer_bytes, &expected)?;

    let blob = keyexchange::decode_key_blob(&peer_bytes)?;
    if blob.role != s.role.peer() {
        return Err(bad("the other side sent the wrong kind of handshake"));
    }

    let peer_ecdh = P384Pub::from_public_key_der(&blob.ecdh_spki)
        .map_err(|e| bad(format!("peer ECDH key is not a valid P-384 SPKI: {}", e)))?;
    let peer_ecdsa = VerifyingKey::from_public_key_der(&blob.ecdsa_spki)
        .map_err(|e| bad(format!("peer identity key is not a valid P-384 SPKI: {}", e)))?;

    let (local_desc, remote_desc, local_blob) = (
        s.local_descriptor.clone().ok_or_else(|| bad("missing local descriptor"))?,
        s.remote_descriptor.clone().ok_or_else(|| bad("missing peer descriptor"))?,
        s.local_blob.clone().ok_or_else(|| bad("missing local key blob"))?,
    );
    let is_offer = s.role == Role::Offer;
    let transcript = keyexchange::build_transcript(
        if is_offer { &local_desc } else { &remote_desc },
        if is_offer { &remote_desc } else { &local_desc },
        if is_offer { &local_blob } else { &peer_bytes },
        if is_offer { &peer_bytes } else { &local_blob },
    )?;

    // The salt is derived, never sent: every session key is bound to both DTLS
    // fingerprints and every candidate in both descriptors.
    let salt = keyexchange::derive_transcript_salt(&transcript);

    let shared = p384::ecdh::diffie_hellman(ecdh.to_nonzero_scalar(), peer_ecdh.as_affine());
    let full = shared.raw_secret_bytes();
    // Web Crypto's deriveBits(256) returns the leftmost 256 bits of the shared X
    // coordinate; matching that is what keeps the two implementations agreeing.
    let shared_bytes: &[u8] = if full.len() >= 32 { &full[..32] } else { &full };

    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_bytes);
    let mut enc = [0u8; 32];
    let mut mac = [0u8; 64];
    let mut meta = [0u8; 32];
    let mut dr_root = [0u8; 32];
    for (label, buf) in [
        (&b"message-encryption-v4"[..], &mut enc[..]),
        (&b"message-authentication-v4"[..], &mut mac[..]),
        (&b"metadata-protection-v4"[..], &mut meta[..]),
        (&b"double-ratchet-root-v1"[..], &mut dr_root[..]),
    ] {
        hk.expand(label, buf)
            .map_err(|e| CoreError::crypto_failure(format!("HKDF expand failed: {:?}", e)))?;
    }
    // Colon-separated hex, via the shared helper. This value is mixed into every
    // per-file key (see file_crypto::derive_file_key), so computing it a second
    // way here — even correctly — would give file and voice transfers a different
    // key on each side.
    let key_fingerprint = crate::file_crypto::compute_key_fingerprint(shared_bytes, &salt);

    // Start the Double Ratchet.
    //
    // Support is IMPLIED by the format rather than advertised in it: SB1 carries
    // a `dr` field because a peer might predate the ratchet, and SBQ2 postdates it
    // entirely. Leaving peer_supports_ratchet false — which is what the absence of
    // `dr` would otherwise mean — silently downgrades the session to static keys
    // and takes cover traffic down with it, since cover traffic rides the ratchet.
    let ratchet = if is_offer {
        crate::ratchet::DoubleRatchet::init_initiator(&dr_root, &salt, &peer_ecdh).ok()
    } else {
        crate::ratchet::DoubleRatchet::init_responder(&dr_root, &salt, ecdh.clone()).ok()
    };
    if ratchet.is_none() {
        // On SB1 this is a tolerated downgrade for old peers. Here there are no
        // old peers by construction, so it can only be a real failure.
        return Err(CoreError::crypto_failure("Double Ratchet initialisation failed"));
    }
    {
        use zeroize::Zeroize;
        dr_root.zeroize();   // folded into the ratchet; must not linger
    }

    // SAS over the transcript: everything that travelled out of band, in both
    // directions, plus both blobs, is inside these digits.
    let sas = keyexchange::compute_transcript_sas(shared_bytes, &transcript)?;

    // Identity proof — one signature over the whole transcript, replacing the
    // challenge/response that used to echo a nonce back across seven fields.
    let signing = s.ecdsa_signing.as_ref().ok_or_else(|| bad("no identity key for this session"))?;
    let digest = Sha384::digest(keyexchange::proof_payload(&transcript));
    let sig: Signature = signing.sign_prehash(&digest)
        .map_err(|e| CoreError::crypto_failure(format!("transcript signing failed: {}", e)))?;

    s.remote_blob = Some(peer_bytes);
    s.peer_ecdh = Some(peer_ecdh);
    s.peer_ecdsa = Some(peer_ecdsa);
    s.transcript = Some(transcript);
    st.session_salt = Some(salt);

    let mut keys = session_keys.lock().map_err(|_| CoreError::state_error("Failed to acquire session_keys lock"))?;
    keys.encryption_key = Some(enc.to_vec());
    keys.mac_key = Some(mac.to_vec());
    keys.metadata_key = Some(meta.to_vec());
    keys.key_fingerprint = Some(key_fingerprint.clone());
    keys.verification_code = Some(sas.clone());
    keys.peer_supports_ratchet = true;
    keys.ratchet = ratchet;

    Ok(serde_json::json!({
        "proof": B64.encode(sig.to_bytes()),
        "sas": sas,
        "keyFingerprint": key_fingerprint,
        "ratchetActive": true,
    }))
}

/// Verify the peer's transcript signature. Failure is fatal to the session.
pub fn verify_peer_proof(
    offer_state: Arc<Mutex<OfferContext>>, proof_b64: &str,
) -> Result<bool, CoreError> {
    let sig_bytes = B64.decode(proof_b64.trim())
        .map_err(|e| bad(format!("proof is not valid base64: {}", e)))?;
    let mut st = offer_state.lock().map_err(|_| lock_err())?;
    let s = st.sbq2.as_mut().ok_or_else(|| bad("this session is not an SBQ2 session"))?;
    let transcript = s.transcript.clone().ok_or_else(|| bad("the transcript is not closed yet"))?;
    let vk = s.peer_ecdsa.ok_or_else(|| bad("no peer identity key"))?;

    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|e| bad(format!("proof is not a valid P-384 signature: {}", e)))?;
    let digest = Sha384::digest(keyexchange::proof_payload(&transcript));
    vk.verify_prehash(&digest, &sig)
        .map_err(|_| bad("the other side could not prove it owns its identity key"))?;
    s.proof_verified = true;
    Ok(true)
}
