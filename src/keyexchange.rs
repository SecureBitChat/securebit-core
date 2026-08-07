//! In-band key exchange for SBQ2.
//!
//! Port of `src/network/descriptor/keyexchange.js`. Same requirement as the
//! descriptor: byte-identical, because both sides hash the same blobs into the
//! same transcript and read the resulting digits aloud to each other.
//!
//! The out-of-band descriptor carries a 16-byte commitment; the key material
//! itself — ECDH key, ECDSA identity key — is the first frame on the data
//! channel. Order matters and is enforced by the shape of this module:
//!
//!   1. Both sides send their blob as soon as the channel opens.
//!   2. `verify_blob_commitment` takes RAW BYTES, not a parsed structure, so a
//!      substituted blob is rejected before `decode_key_blob` or any key import
//!      can touch it.
//!   3. Only then is the transcript defined — both descriptors verbatim and both
//!      blobs, length-prefixed — and the HKDF salt derived from it, so session
//!      keys are bound to both DTLS fingerprints and every candidate and neither
//!      side can steer the salt alone.
//!   4. Each side signs the transcript with its ECDSA key. One signature over
//!      everything, replacing the old challenge/response that echoed a nonce back
//!      across seven fields.
//!   5. The SAS is HKDF over the ECDH shared secret salted with the transcript.

use crate::error::CoreError;
use sha2::{Digest, Sha256, Sha512};
use hkdf::Hkdf;

pub const KEY_BLOB_VERSION: u8 = 0x02;

pub const MAX_SPKI: usize = 256;
pub const MIN_SPKI: usize = 40;
pub const MAX_BLOB_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role { Offer = 0, Answer = 1 }

impl Role {
    pub fn peer(self) -> Role { if self == Role::Offer { Role::Answer } else { Role::Offer } }
    fn from_u8(v: u8) -> Option<Role> {
        match v { 0 => Some(Role::Offer), 1 => Some(Role::Answer), _ => None }
    }
}

#[derive(Debug, Clone)]
pub struct KeyBlob {
    pub version: u8,
    pub role: Role,
    pub ecdh_spki: Vec<u8>,
    pub ecdsa_spki: Vec<u8>,
}

fn bad(msg: impl Into<String>) -> CoreError { CoreError::invalid_input(msg.into()) }

/// `version u8 | role u8 | ecdhLen u16 | ecdh | ecdsaLen u16 | ecdsa`
///
/// No signature lives in here: the blob is what the commitment and the transcript
/// cover, and a signature over the transcript cannot sit inside the thing it
/// signs. It travels separately, in the proof frame.
pub fn encode_key_blob(role: Role, ecdh_spki: &[u8], ecdsa_spki: &[u8]) -> Result<Vec<u8>, CoreError> {
    for (name, v) in [("ecdh", ecdh_spki), ("ecdsa", ecdsa_spki)] {
        if v.len() < MIN_SPKI || v.len() > MAX_SPKI {
            return Err(bad(format!("{} SPKI length out of range", name)));
        }
    }
    let mut out = Vec::with_capacity(6 + ecdh_spki.len() + ecdsa_spki.len());
    out.push(KEY_BLOB_VERSION);
    out.push(role as u8);
    out.extend_from_slice(&(ecdh_spki.len() as u16).to_be_bytes());
    out.extend_from_slice(ecdh_spki);
    out.extend_from_slice(&(ecdsa_spki.len() as u16).to_be_bytes());
    out.extend_from_slice(ecdsa_spki);
    Ok(out)
}

/// Strict parser. Anything unexpected is an error; there is no partial result.
pub fn decode_key_blob(buf: &[u8]) -> Result<KeyBlob, CoreError> {
    if buf.is_empty() { return Err(bad("key blob is empty")); }
    if buf.len() > MAX_BLOB_BYTES { return Err(bad("key blob exceeds the size limit")); }
    let mut i = 0usize;
    let need = |i: usize, n: usize| -> Result<(), CoreError> {
        if i + n > buf.len() { Err(bad("key blob is truncated")) } else { Ok(()) }
    };

    need(i, 1)?; let version = buf[i]; i += 1;
    // Same rule as the descriptor: a version mismatch is an error, never an
    // attempt to parse a different shape.
    if version != KEY_BLOB_VERSION {
        return Err(bad(format!("unsupported key blob version 0x{:02x}", version)));
    }
    need(i, 1)?; let role = Role::from_u8(buf[i]).ok_or_else(|| bad("reserved key blob role"))?; i += 1;

    need(i, 2)?; let ecdh_len = u16::from_be_bytes([buf[i], buf[i + 1]]) as usize; i += 2;
    if !(MIN_SPKI..=MAX_SPKI).contains(&ecdh_len) { return Err(bad("ECDH SPKI length out of range")); }
    need(i, ecdh_len)?; let ecdh_spki = buf[i..i + ecdh_len].to_vec(); i += ecdh_len;

    need(i, 2)?; let ecdsa_len = u16::from_be_bytes([buf[i], buf[i + 1]]) as usize; i += 2;
    if !(MIN_SPKI..=MAX_SPKI).contains(&ecdsa_len) { return Err(bad("ECDSA SPKI length out of range")); }
    need(i, ecdsa_len)?; let ecdsa_spki = buf[i..i + ecdsa_len].to_vec(); i += ecdsa_len;

    if i != buf.len() {
        return Err(bad(format!("{} trailing byte(s) after the key blob", buf.len() - i)));
    }
    Ok(KeyBlob { version, role, ecdh_spki, ecdsa_spki })
}

/// Canonical transcript. Ordered by ROLE, never by who is calling, so both peers
/// hash identical bytes. Lengths are prefixed so no field boundary can shift.
pub fn build_transcript(
    offer_descriptor: &[u8], answer_descriptor: &[u8], offer_blob: &[u8], answer_blob: &[u8],
) -> Result<Vec<u8>, CoreError> {
    for (name, v) in [
        ("offerDescriptor", offer_descriptor), ("answerDescriptor", answer_descriptor),
        ("offerBlob", offer_blob), ("answerBlob", answer_blob),
    ] {
        if v.is_empty() { return Err(bad(format!("transcript component {} is missing", name))); }
    }
    let mut out = Vec::new();
    out.extend_from_slice(b"sbq2/sas/v1\0");
    for part in [offer_descriptor, answer_descriptor, offer_blob, answer_blob] {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part);
    }
    Ok(out)
}

/// HKDF salt, derived rather than transmitted. `derive_shared_keys` wants exactly
/// 64 bytes, which SHA-512 supplies directly.
pub fn derive_transcript_salt(transcript: &[u8]) -> Vec<u8> {
    Sha512::digest(transcript).to_vec()
}

/// Bytes an ECDSA identity key signs to prove possession and bind the transcript.
pub fn proof_payload(transcript: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(14 + transcript.len());
    out.extend_from_slice(b"sbq2/proof/v1\0");
    out.extend_from_slice(transcript);
    out
}

/// SAS digits.
///
/// IKM is the raw ECDH shared secret, so an observer holding the whole transcript
/// still cannot predict the digits. The salt is the transcript hash, so nothing
/// in the handshake can move without moving the digits.
pub fn compute_transcript_sas(shared_secret: &[u8], transcript: &[u8]) -> Result<String, CoreError> {
    let salt = Sha256::digest(transcript);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut bits = [0u8; 8];
    hk.expand(b"sbq2-sas-v1", &mut bits)
        .map_err(|_| CoreError::internal_error("HKDF expand failed for SAS"))?;
    let n1 = u32::from_be_bytes([bits[0], bits[1], bits[2], bits[3]]);
    let n2 = u32::from_be_bytes([bits[4], bits[5], bits[6], bits[7]]);
    Ok(format!("{:07}", (n1 ^ n2) % 10_000_000))
}

/// Verify a peer blob against the commitment that arrived out of band.
///
/// Takes raw bytes on purpose: the check must happen before the blob is
/// interpreted. The comparison is constant-time out of habit rather than
/// necessity — the commitment is public — but it costs nothing.
pub fn verify_blob_commitment(blob_bytes: &[u8], expected: &[u8]) -> Result<(), CoreError> {
    if expected.len() != crate::descriptor::COMMITMENT_BYTES {
        return Err(bad("descriptor carried no usable commitment"));
    }
    let actual = crate::descriptor::commit_blob(blob_bytes);
    let mut diff = 0u8;
    for (a, b) in actual.iter().zip(expected.iter()) { diff |= a ^ b; }
    if diff != 0 {
        return Err(bad("the key material does not match the commitment in the invitation"));
    }
    Ok(())
}
