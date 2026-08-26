//! Group cryptography.
//!
//! This is a byte-for-byte port of `src/group/groupCrypto.js` in the web client.
//! The two implementations MUST agree exactly: a roster signed here is verified
//! by a browser, and every member of a group derives the same safety code from
//! the same bytes — so a single byte of disagreement is not a compatibility bug
//! that degrades, it is a group that cannot form.
//!
//! It lives in the core rather than in a platform's UI layer for the same reason
//! the key exchange does: desktop, mobile and any headless client need the same
//! signatures, and a reviewer needs one place to look.
//!
//! WHY A SEPARATE IDENTITY KEY EXISTS
//! ----------------------------------
//! The pairwise handshake generates a fresh ECDSA key pair per CONNECTION. That
//! is exactly right for 1:1 — there are no accounts, so nothing a long-term key
//! should outlive — but it means Alice presents a different identity key to Bob
//! than she presents to Carol. A group cannot be built on that: a membership
//! operation signed toward Bob would be unverifiable by Carol, and there would
//! be nothing stable to put in a group safety code.
//!
//! So a group gets its own ECDSA P-384 key pair, generated per group per device
//! and destroyed with the group. It never touches the pairwise handshake, and it
//! is published to the other members over the ALREADY VERIFIED pairwise
//! channels.
//!
//! WHY THE SAFETY CODE IS COMMIT-THEN-REVEAL
//! -----------------------------------------
//! The obvious construction — hash the sorted set of member key fingerprints and
//! show the digits, the way a Signal safety number works — is unsafe at the
//! length a group can actually read aloud.
//!
//! The attacker is a group member who introduces two others and sits in the
//! middle of the pair they could not reach directly. They present key K_b to Bob
//! and K_c to Carol. To go unnoticed they need Bob's digits and Carol's digits
//! to match, and both sets are under their control: they can generate candidate
//! key pairs until the two truncated hashes collide. That is a BIRTHDAY search,
//! not a preimage search — roughly 10^(d/2) work for d digits. A 7-digit code
//! falls in a few thousand tries.
//!
//! Commit-then-reveal removes the search instead of outrunning it. Every member
//! commits to a random nonce before any nonce is known, and the code is derived
//! from every member's key AND every member's nonce. By the time the attacker
//! learns the values that go into the digits, their own contribution is already
//! fixed. `GroupSasCeremony` is the only place that ordering is enforced, and
//! `reveal()` refusing to run early is the entire security argument for a code
//! short enough to read out loud.
//!
//! Everything here is a parser of hostile input: a group member is only as
//! trustworthy as the group makes them. Lengths, ranges and alphabets are
//! checked before a value is used.

use crate::error::CoreError;
use ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use hkdf::Hkdf;
use p384::ecdsa::{Signature, SigningKey, VerifyingKey};
use p384::pkcs8::{DecodePublicKey, EncodePublicKey};
use rand::RngCore;
use sha2::{Digest, Sha256, Sha384};
use std::collections::BTreeMap;
use zeroize::Zeroize;

fn bad(m: impl Into<String>) -> CoreError {
    CoreError::invalid_input(m.into())
}

// ---------------------------------------------------------------------------
// limits
// ---------------------------------------------------------------------------

/// Eight is a mesh limit, not a crypto limit: it is where N(N-1)/2 pairwise
/// connections and N-1 fan-out copies stop being comfortable on a phone.
pub const MAX_MEMBERS: usize = 8;
pub const MIN_MEMBERS: usize = 2;
pub const GROUP_ID_BYTES: usize = 16;
pub const NONCE_BYTES: usize = 32;
pub const COMMIT_BYTES: usize = 32;
pub const FINGERPRINT_BYTES: usize = 32;
/// Matches the pairwise SAS. Safe at this length only because of the
/// commit-reveal ordering — see the module header.
pub const SAS_DIGITS: u32 = 7;
/// Bytes, not characters. A 36-character Cyrillic name is 68 bytes, and a UI
/// that clamps by characters against a byte budget produces a name the user
/// typed and the roster refuses to sign.
pub const MAX_NAME_BYTES: usize = 128;
/// Epoch is a uint32 on the wire; a group that changes membership four billion
/// times has other problems.
pub const MAX_EPOCH: u64 = 0xffff_ffff;
pub const MAX_SPKI_BYTES: usize = 256;
pub const MIN_SPKI_BYTES: usize = 40;
pub const MAX_SIG_BYTES: usize = 160;
pub const MIN_SIG_BYTES: usize = 48;
/// Group frames travel as chat content, and that path truncates at 2000
/// characters. A frame that was truncated would no longer match the hash its
/// signature covers, so the body budget leaves room for the envelope.
pub const MAX_BODY_BYTES: usize = 1024;
pub const FRAME_BUDGET_CHARS: usize = 1800;
/// A mesh descriptor as it travels inside a group frame. SBQ2 caps a payload at
/// 512 bytes, which is "SB2:" plus 683 base64url characters at the worst.
pub const MAX_DESCRIPTOR_CHARS: usize = 768;
/// Binds an answer to the one dial attempt that asked for it.
pub const MESH_NONCE_BYTES: usize = 16;

/// A membership operation. The wire form is the lowercase word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberOp {
    Create,
    Add,
    Remove,
    Rename,
}

impl MemberOp {
    pub fn as_str(self) -> &'static str {
        match self {
            MemberOp::Create => "create",
            MemberOp::Add => "add",
            MemberOp::Remove => "remove",
            MemberOp::Rename => "rename",
        }
    }

    pub fn parse(value: &str) -> Result<Self, CoreError> {
        match value {
            "create" => Ok(MemberOp::Create),
            "add" => Ok(MemberOp::Add),
            "remove" => Ok(MemberOp::Remove),
            "rename" => Ok(MemberOp::Rename),
            _ => Err(bad("unknown membership operation")),
        }
    }
}

/// Which half of a mesh dial a signature covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshKind {
    Offer,
    Answer,
}

impl MeshKind {
    pub fn as_str(self) -> &'static str {
        match self {
            MeshKind::Offer => "moffer",
            MeshKind::Answer => "manswer",
        }
    }

    pub fn parse(value: &str) -> Result<Self, CoreError> {
        match value {
            "moffer" => Ok(MeshKind::Offer),
            "manswer" => Ok(MeshKind::Answer),
            _ => Err(bad("unknown mesh descriptor kind")),
        }
    }
}

// ---------------------------------------------------------------------------
// canonical encoding
// ---------------------------------------------------------------------------

/// One component of a length-prefixed payload.
pub enum Part<'a> {
    Bytes(&'a [u8]),
    Text(&'a str),
}

/// Length-prefixed concatenation.
///
/// Everything signed or hashed in this module goes through here, so that no two
/// distinct field sets can ever produce the same bytes. Plain concatenation
/// would let ("ab","c") and ("a","bc") sign the same payload, which is precisely
/// how a membership operation gets reinterpreted as a different one.
///
/// The label is NUL-terminated and NOT length-prefixed, exactly as in the web
/// client — this is wire format, not a style choice.
fn lp(label: &str, parts: &[Part<'_>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(label.as_bytes());
    out.push(0);
    for part in parts {
        let bytes = match part {
            Part::Bytes(b) => *b,
            Part::Text(t) => t.as_bytes(),
        };
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
    }
    out
}

fn u32_be(n: u64) -> Result<[u8; 4], CoreError> {
    if n > MAX_EPOCH {
        return Err(bad("value out of uint32 range"));
    }
    Ok((n as u32).to_be_bytes())
}

/// Constant-time byte comparison. Cheap, and keeps the habit uniform.
fn equal_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// validation of attacker-supplied values
// ---------------------------------------------------------------------------

fn is_lower_hex(value: &str) -> bool {
    value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn assert_group_id(group_id: &str) -> Result<Vec<u8>, CoreError> {
    if group_id.len() != GROUP_ID_BYTES * 2 || !is_lower_hex(group_id) {
        return Err(bad("malformed group id"));
    }
    hex::decode(group_id).map_err(|_| bad("malformed group id"))
}

pub fn assert_fingerprint(fp: &str) -> Result<Vec<u8>, CoreError> {
    if fp.len() != FINGERPRINT_BYTES * 2 || !is_lower_hex(fp) {
        return Err(bad("malformed member fingerprint"));
    }
    hex::decode(fp).map_err(|_| bad("malformed member fingerprint"))
}

pub fn assert_epoch(epoch: u64) -> Result<u64, CoreError> {
    if epoch > MAX_EPOCH {
        return Err(bad("epoch out of range"));
    }
    Ok(epoch)
}

pub fn assert_name(name: &str) -> Result<(), CoreError> {
    if name.as_bytes().len() > MAX_NAME_BYTES {
        return Err(bad("group name too long"));
    }
    Ok(())
}

/// Canonical member ordering.
///
/// Sorting by fingerprint — never by join order, never by however the list
/// arrived — is what makes every device hash identical bytes. A set that two
/// members order differently produces two different safety codes and the group
/// fails to form for no visible reason.
pub fn canonical_fingerprints(fps: &[String]) -> Result<Vec<String>, CoreError> {
    if fps.len() < MIN_MEMBERS {
        return Err(bad("a group needs at least two members"));
    }
    if fps.len() > MAX_MEMBERS {
        return Err(bad(format!("a group is limited to {} members", MAX_MEMBERS)));
    }
    let mut seen = std::collections::BTreeSet::new();
    for fp in fps {
        assert_fingerprint(fp)?;
        if !seen.insert(fp.clone()) {
            return Err(bad("duplicate member fingerprint"));
        }
    }
    let mut ordered: Vec<String> = fps.to_vec();
    ordered.sort();
    Ok(ordered)
}

// ---------------------------------------------------------------------------
// group identity key
// ---------------------------------------------------------------------------

/// A group identity key pair for this device, in this group.
///
/// The private half signs and nothing else. It is zeroized on drop rather than
/// left in memory for the lifetime of the process: a group is torn down when the
/// user leaves it, and the key must go with it.
pub struct GroupIdentity {
    signing: SigningKey,
    pub spki: Vec<u8>,
    pub fingerprint: String,
}

impl GroupIdentity {
    /// A fresh identity for one group on this device.
    pub fn generate() -> Result<Self, CoreError> {
        let signing = SigningKey::random(&mut rand::rngs::OsRng);
        let spki = signing
            .verifying_key()
            .to_public_key_der()
            .map_err(|e| CoreError::crypto_failure(format!("group SPKI export failed: {}", e)))?
            .as_bytes()
            .to_vec();
        let fingerprint = fingerprint_spki(&spki)?;
        Ok(Self { signing, spki, fingerprint })
    }

    /// Restore an identity from a PKCS#8 private key. For tests and for a
    /// platform that persists a group across a restart.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, CoreError> {
        use p384::pkcs8::DecodePrivateKey;
        let signing = SigningKey::from_pkcs8_der(der)
            .map_err(|_| bad("not a valid P-384 private key"))?;
        let spki = signing
            .verifying_key()
            .to_public_key_der()
            .map_err(|e| CoreError::crypto_failure(format!("group SPKI export failed: {}", e)))?
            .as_bytes()
            .to_vec();
        let fingerprint = fingerprint_spki(&spki)?;
        Ok(Self { signing, spki, fingerprint })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        *self.signing.verifying_key()
    }

    /// Sign a payload the way WebCrypto's ECDSA/SHA-384 does: the digest is
    /// signed and the signature is the raw r‖s pair, never DER. A DER signature
    /// here would be refused by every browser member.
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, CoreError> {
        let digest = Sha384::digest(payload);
        let sig: Signature = self
            .signing
            .sign_prehash(&digest)
            .map_err(|e| CoreError::crypto_failure(format!("group signing failed: {}", e)))?;
        Ok(sig.to_bytes().to_vec())
    }
}

impl Drop for GroupIdentity {
    fn drop(&mut self) {
        self.spki.zeroize();
    }
}

/// SHA-256 over the SPKI, hex. The stable name of a member inside a group.
pub fn fingerprint_spki(spki: &[u8]) -> Result<String, CoreError> {
    if spki.len() < MIN_SPKI_BYTES || spki.len() > MAX_SPKI_BYTES {
        return Err(bad("SPKI length out of range"));
    }
    Ok(hex::encode(Sha256::digest(spki)))
}

/// Import a member's published verifying key.
///
/// Returns the key AND the fingerprint computed from the bytes we were actually
/// given, never one the sender asserted. A member is identified by what their
/// key hashes to; accepting a claimed fingerprint would let a member occupy
/// someone else's slot in the safety code.
pub fn import_member_identity(spki: &[u8]) -> Result<(VerifyingKey, String), CoreError> {
    let fingerprint = fingerprint_spki(spki)?;
    let key = VerifyingKey::from_public_key_der(spki)
        .map_err(|_| bad("member identity key is not a valid P-384 public key"))?;
    Ok((key, fingerprint))
}

/// Check one signature against a member's key.
///
/// Bounds first: a signature outside the plausible range is refused before it
/// reaches the curve implementation.
fn verify_with(key: &VerifyingKey, payload: &[u8], signature: &[u8]) -> bool {
    if signature.len() < MIN_SIG_BYTES || signature.len() > MAX_SIG_BYTES {
        return false;
    }
    let sig = match Signature::from_slice(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };
    key.verify_prehash(&Sha384::digest(payload), &sig).is_ok()
}

// ---------------------------------------------------------------------------
// commit / reveal
// ---------------------------------------------------------------------------

/// Commitment to a member's nonce for one epoch.
///
/// The group id and epoch are inside the hash so a commitment cannot be replayed
/// into a different group or a later epoch, and the fingerprint is inside so one
/// member cannot claim another member's commitment as their own.
pub fn build_commitment(
    group_id: &str,
    epoch: u64,
    fingerprint: &str,
    nonce: &[u8],
) -> Result<[u8; 32], CoreError> {
    let gid = assert_group_id(group_id)?;
    let fp = assert_fingerprint(fingerprint)?;
    let epoch_be = u32_be(assert_epoch(epoch)?)?;
    if nonce.len() != NONCE_BYTES {
        return Err(bad("nonce must be 32 bytes"));
    }
    let payload = lp(
        "securebit/group/commit/v1",
        &[
            Part::Bytes(&gid),
            Part::Bytes(&epoch_be),
            Part::Bytes(&fp),
            Part::Bytes(nonce),
        ],
    );
    Ok(Sha256::digest(payload).into())
}

pub fn verify_commitment(
    commitment: &[u8],
    group_id: &str,
    epoch: u64,
    fingerprint: &str,
    nonce: &[u8],
) -> bool {
    if commitment.len() != COMMIT_BYTES {
        return false;
    }
    match build_commitment(group_id, epoch, fingerprint, nonce) {
        Ok(expected) => equal_bytes(commitment, &expected),
        Err(_) => false,
    }
}

/// One member's contribution to the code.
#[derive(Debug, Clone)]
pub struct Contribution {
    pub fingerprint: String,
    pub nonce: Vec<u8>,
}

/// The digits every member reads aloud.
///
/// Inputs are the full member set with their revealed nonces, sorted by
/// fingerprint. Every member's key AND every member's nonce is covered, so a
/// substituted key or a substituted nonce anywhere in the group changes the code
/// for the members who received the substitution — and not for the others, which
/// is the mismatch the humans are there to notice.
pub fn compute_group_sas(
    group_id: &str,
    epoch: u64,
    contributions: &[Contribution],
    digits: u32,
) -> Result<String, CoreError> {
    let gid = assert_group_id(group_id)?;
    let epoch_be = u32_be(assert_epoch(epoch)?)?;
    if !(4..=12).contains(&digits) {
        return Err(bad("digit count out of range"));
    }

    let fps: Vec<String> = contributions.iter().map(|c| c.fingerprint.clone()).collect();
    canonical_fingerprints(&fps)?;

    let mut ordered: Vec<&Contribution> = contributions.iter().collect();
    ordered.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));

    let mut decoded: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(ordered.len());
    for c in &ordered {
        if c.nonce.len() != NONCE_BYTES {
            return Err(bad("every member must contribute a 32-byte nonce"));
        }
        decoded.push((assert_fingerprint(&c.fingerprint)?, c.nonce.clone()));
    }

    let mut parts: Vec<Part<'_>> = Vec::with_capacity(2 + decoded.len() * 2);
    parts.push(Part::Bytes(&gid));
    parts.push(Part::Bytes(&epoch_be));
    for (fp, nonce) in &decoded {
        parts.push(Part::Bytes(fp));
        parts.push(Part::Bytes(nonce));
    }
    let mut ikm = lp("securebit/group/sas/v1", &parts);

    let salt = Sha256::digest(lp(
        "securebit/group/sas-salt/v1",
        &[Part::Bytes(&gid), Part::Bytes(&epoch_be)],
    ));

    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut bits = [0u8; 8];
    hk.expand(b"securebit-group-sas-v1", &mut bits)
        .map_err(|_| CoreError::crypto_failure("group SAS derivation failed"))?;
    ikm.zeroize();

    // 52 bits of entropy folded into the digits, exactly as the web client does
    // it: the first word scaled by 2^20 plus the top 20 bits of the second. The
    // modulo bias at 10^7 is ~1e-9.
    let hi = u32::from_be_bytes([bits[0], bits[1], bits[2], bits[3]]) as u64;
    let lo = u32::from_be_bytes([bits[4], bits[5], bits[6], bits[7]]) as u64;
    let n = hi * (1u64 << 20) + (lo >> 12);
    bits.zeroize();

    let modulus = 10u64.pow(digits);
    Ok(format!("{:0width$}", n % modulus, width = digits as usize))
}

/// The commit/reveal state machine.
///
/// This type exists so that the ordering rule has exactly one implementation.
/// `reveal()` fails until every expected commitment has arrived, and that
/// refusal is the entire security argument for a seven-digit group code.
pub struct GroupSasCeremony {
    group_id: String,
    epoch: u64,
    self_fingerprint: String,
    members: Vec<String>,
    nonce: Vec<u8>,
    commitments: BTreeMap<String, Vec<u8>>,
    nonces: BTreeMap<String, Vec<u8>>,
    pub revealed: bool,
    pub code: Option<String>,
}

impl GroupSasCeremony {
    pub fn new(
        group_id: &str,
        epoch: u64,
        self_fingerprint: &str,
        member_fingerprints: &[String],
    ) -> Result<Self, CoreError> {
        assert_group_id(group_id)?;
        assert_epoch(epoch)?;
        assert_fingerprint(self_fingerprint)?;
        let members = canonical_fingerprints(member_fingerprints)?;
        if !members.iter().any(|fp| fp == self_fingerprint) {
            return Err(bad("the local member is not in the member set"));
        }
        let mut nonce = vec![0u8; NONCE_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        Ok(Self {
            group_id: group_id.to_string(),
            epoch,
            self_fingerprint: self_fingerprint.to_string(),
            members,
            nonce,
            commitments: BTreeMap::new(),
            nonces: BTreeMap::new(),
            revealed: false,
            code: None,
        })
    }

    /// Our own commitment, to be broadcast first.
    pub fn own_commitment(&mut self) -> Result<[u8; 32], CoreError> {
        let commitment = build_commitment(
            &self.group_id,
            self.epoch,
            &self.self_fingerprint,
            &self.nonce,
        )?;
        self.commitments
            .insert(self.self_fingerprint.clone(), commitment.to_vec());
        Ok(commitment)
    }

    /// Record a peer commitment. Rejects anyone outside the member set, and
    /// refuses to overwrite one already recorded — a second, different
    /// commitment from the same member is an attempt to move after seeing more
    /// of the round.
    pub fn accept_commitment(&mut self, fingerprint: &str, commitment: &[u8]) -> Result<bool, CoreError> {
        assert_fingerprint(fingerprint)?;
        if !self.members.iter().any(|fp| fp == fingerprint) {
            return Err(bad("commitment from a non-member"));
        }
        if commitment.len() != COMMIT_BYTES {
            return Err(bad("malformed commitment"));
        }
        if let Some(existing) = self.commitments.get(fingerprint) {
            if !equal_bytes(existing, commitment) {
                return Err(bad("member changed their commitment"));
            }
            return Ok(false);
        }
        self.commitments
            .insert(fingerprint.to_string(), commitment.to_vec());
        Ok(true)
    }

    pub fn commitments_complete(&self) -> bool {
        self.members.iter().all(|fp| self.commitments.contains_key(fp))
    }

    pub fn has_commitment(&self, fingerprint: &str) -> bool {
        self.commitments.contains_key(fingerprint)
    }

    /// Our nonce — available ONLY once every commitment is in.
    ///
    /// This is the gate the whole construction rests on. Do not add a caller
    /// that bypasses it, and do not relax it when a member is slow: a timeout
    /// must fail the ceremony, never proceed without a commitment.
    pub fn reveal(&mut self) -> Result<Vec<u8>, CoreError> {
        if !self.commitments_complete() {
            return Err(bad("cannot reveal before every member has committed"));
        }
        self.revealed = true;
        self.nonces
            .insert(self.self_fingerprint.clone(), self.nonce.clone());
        Ok(self.nonce.clone())
    }

    /// Record a peer nonce, checking it against the commitment they are bound to.
    pub fn accept_reveal(&mut self, fingerprint: &str, nonce: &[u8]) -> Result<(), CoreError> {
        assert_fingerprint(fingerprint)?;
        if !self.members.iter().any(|fp| fp == fingerprint) {
            return Err(bad("reveal from a non-member"));
        }
        let commitment = self
            .commitments
            .get(fingerprint)
            .ok_or_else(|| bad("reveal arrived before the commitment"))?
            .clone();
        if !verify_commitment(&commitment, &self.group_id, self.epoch, fingerprint, nonce) {
            return Err(bad("revealed nonce does not match the commitment"));
        }
        self.nonces.insert(fingerprint.to_string(), nonce.to_vec());
        Ok(())
    }

    pub fn reveals_complete(&self) -> bool {
        self.members.iter().all(|fp| self.nonces.contains_key(fp))
    }

    /// The digits, once every nonce is in and verified.
    pub fn finish(&mut self) -> Result<String, CoreError> {
        if !self.reveals_complete() {
            return Err(bad("not every member has revealed"));
        }
        let contributions: Vec<Contribution> = self
            .members
            .iter()
            .map(|fp| Contribution {
                fingerprint: fp.clone(),
                nonce: self.nonces.get(fp).cloned().unwrap_or_default(),
            })
            .collect();
        let code = compute_group_sas(&self.group_id, self.epoch, &contributions, SAS_DIGITS)?;
        self.code = Some(code.clone());
        Ok(code)
    }
}

/// Wipe the nonce material once the code exists or the ceremony is abandoned.
impl Drop for GroupSasCeremony {
    fn drop(&mut self) {
        self.nonce.zeroize();
        for nonce in self.nonces.values_mut() {
            nonce.zeroize();
        }
    }
}

// ---------------------------------------------------------------------------
// membership operations
// ---------------------------------------------------------------------------

/// The bytes a membership change is signed over.
///
/// The resulting member set is signed in full rather than the delta, so a
/// recipient never has to reconstruct state from a sequence of operations it may
/// have received out of order or incompletely. The epoch is what orders them,
/// and accepting only a strictly greater epoch is what refuses both a replay and
/// a rollback to a set that used to be valid.
pub fn member_op_payload(
    group_id: &str,
    epoch: u64,
    op: MemberOp,
    member_fps: &[String],
    name: &str,
) -> Result<Vec<u8>, CoreError> {
    let gid = assert_group_id(group_id)?;
    let epoch_be = u32_be(assert_epoch(epoch)?)?;
    assert_name(name)?;
    let ordered = canonical_fingerprints(member_fps)?;
    let decoded: Vec<Vec<u8>> = ordered
        .iter()
        .map(|fp| assert_fingerprint(fp))
        .collect::<Result<_, _>>()?;

    let mut parts: Vec<Part<'_>> = vec![
        Part::Bytes(&gid),
        Part::Bytes(&epoch_be),
        Part::Text(op.as_str()),
        Part::Text(name),
    ];
    for fp in &decoded {
        parts.push(Part::Bytes(fp));
    }
    Ok(lp("securebit/group/member-op/v1", &parts))
}

pub fn sign_member_op(
    identity: &GroupIdentity,
    group_id: &str,
    epoch: u64,
    op: MemberOp,
    member_fps: &[String],
    name: &str,
) -> Result<Vec<u8>, CoreError> {
    identity.sign(&member_op_payload(group_id, epoch, op, member_fps, name)?)
}

pub fn verify_member_op(
    key: &VerifyingKey,
    group_id: &str,
    epoch: u64,
    op: MemberOp,
    member_fps: &[String],
    name: &str,
    signature: &[u8],
) -> bool {
    match member_op_payload(group_id, epoch, op, member_fps, name) {
        Ok(payload) => verify_with(key, &payload, signature),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// group messages
// ---------------------------------------------------------------------------

pub fn hash_body(body: &[u8]) -> Result<[u8; 32], CoreError> {
    if body.len() > MAX_BODY_BYTES {
        return Err(bad("message body exceeds the group limit"));
    }
    Ok(Sha256::digest(body).into())
}

/// The bytes a group message is signed over.
///
/// Only the hash of the body is signed, not the body: it keeps the payload a
/// fixed size regardless of message length, and the hash is what a later
/// consistency comparison needs anyway.
pub fn group_message_payload(
    group_id: &str,
    epoch: u64,
    seq: u64,
    sender_fp: &str,
    body_hash: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let gid = assert_group_id(group_id)?;
    let epoch_be = u32_be(assert_epoch(epoch)?)?;
    // Same uint32 range as the epoch; a per-sender counter.
    let seq_be = u32_be(assert_epoch(seq)?)?;
    let fp = assert_fingerprint(sender_fp)?;
    if body_hash.len() != 32 {
        return Err(bad("body hash must be 32 bytes"));
    }
    Ok(lp(
        "securebit/group/message/v1",
        &[
            Part::Bytes(&gid),
            Part::Bytes(&epoch_be),
            Part::Bytes(&seq_be),
            Part::Bytes(&fp),
            Part::Bytes(body_hash),
        ],
    ))
}

pub fn sign_group_message(
    identity: &GroupIdentity,
    group_id: &str,
    epoch: u64,
    seq: u64,
    sender_fp: &str,
    body_hash: &[u8],
) -> Result<Vec<u8>, CoreError> {
    identity.sign(&group_message_payload(group_id, epoch, seq, sender_fp, body_hash)?)
}

pub fn verify_group_message(
    key: &VerifyingKey,
    group_id: &str,
    epoch: u64,
    seq: u64,
    sender_fp: &str,
    body_hash: &[u8],
    signature: &[u8],
) -> bool {
    match group_message_payload(group_id, epoch, seq, sender_fp, body_hash) {
        Ok(payload) => verify_with(key, &payload, signature),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// mesh links
// ---------------------------------------------------------------------------
//
// WHY A MESH DESCRIPTOR IS SIGNED WITH THE GROUP IDENTITY KEY
// -----------------------------------------------------------
// Two members who have never met have no pairwise channel to introduce
// themselves over, so their WebRTC descriptors have to travel through a member
// who CAN reach both — in practice the admin. That relay is not trusted with the
// content of the group, and it must not become trusted with the shape of the
// group's transport either: a relay that could swap a descriptor for its own
// would sit in the middle of the very link that was built to route around it.
//
// The descriptor is therefore signed with the sender's group identity key — the
// same key whose fingerprint the signed roster names and whose presence the
// humans confirmed when they compared the group code. A relay can drop a dial or
// delay it, which costs availability and nothing else. It cannot substitute one.
//
// The signature covers the direction, BOTH fingerprints and a per-attempt nonce
// as well as the descriptor bytes:
//   - the direction stops an offer being replayed back as an answer;
//   - both fingerprints stop a descriptor addressed to one member being
//     re-aimed at another;
//   - the nonce binds an answer to the one dial that asked for it.

pub fn mesh_descriptor_payload(
    group_id: &str,
    epoch: u64,
    kind: MeshKind,
    from_fp: &str,
    to_fp: &str,
    descriptor: &str,
    nonce: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let gid = assert_group_id(group_id)?;
    let epoch_be = u32_be(assert_epoch(epoch)?)?;
    let from = assert_fingerprint(from_fp)?;
    let to = assert_fingerprint(to_fp)?;
    if from_fp == to_fp {
        return Err(bad("a member cannot dial itself"));
    }
    if descriptor.is_empty() || descriptor.len() > MAX_DESCRIPTOR_CHARS {
        return Err(bad("mesh descriptor is missing or oversized"));
    }
    if nonce.len() != MESH_NONCE_BYTES {
        return Err(bad("mesh nonce must be 16 bytes"));
    }
    Ok(lp(
        "securebit/group/mesh-descriptor/v1",
        &[
            Part::Bytes(&gid),
            Part::Bytes(&epoch_be),
            Part::Text(kind.as_str()),
            Part::Bytes(&from),
            Part::Bytes(&to),
            Part::Text(descriptor),
            Part::Bytes(nonce),
        ],
    ))
}

pub fn sign_mesh_descriptor(
    identity: &GroupIdentity,
    group_id: &str,
    epoch: u64,
    kind: MeshKind,
    from_fp: &str,
    to_fp: &str,
    descriptor: &str,
    nonce: &[u8],
) -> Result<Vec<u8>, CoreError> {
    identity.sign(&mesh_descriptor_payload(
        group_id, epoch, kind, from_fp, to_fp, descriptor, nonce,
    )?)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_mesh_descriptor(
    key: &VerifyingKey,
    group_id: &str,
    epoch: u64,
    kind: MeshKind,
    from_fp: &str,
    to_fp: &str,
    descriptor: &str,
    nonce: &[u8],
    signature: &[u8],
) -> bool {
    match mesh_descriptor_payload(group_id, epoch, kind, from_fp, to_fp, descriptor, nonce) {
        Ok(payload) => verify_with(key, &payload, signature),
        Err(_) => false,
    }
}

/// The bytes a link probe is signed over.
///
/// A probe is how a member says "the pairwise chat you are reading this on is
/// me, member <fp>". It exists because two members can perfectly well already
/// hold a verified 1:1 chat with each other before the group was formed, and
/// dialling a second connection between them would be pure waste.
///
/// The claim has to be authenticated TO THIS SESSION. A bare signed claim would
/// be replayable: any member could capture one and present it on their own link
/// to impersonate its author, and group traffic meant for that member would then
/// be encrypted to the impersonator's pairwise session — a plaintext disclosure,
/// not merely a routing mistake.
///
/// `link_fp` is what closes that. It is the pairwise session's own key
/// fingerprint, derived from the ECDH shared secret, so it is known to exactly
/// the two endpoints of that session and to nobody else. The receiver checks it
/// against the fingerprint IT holds for the session the probe arrived on, never
/// against a value inside the frame.
pub fn link_probe_payload(
    group_id: &str,
    epoch: u64,
    fp: &str,
    link_fp: &str,
) -> Result<Vec<u8>, CoreError> {
    let gid = assert_group_id(group_id)?;
    let epoch_be = u32_be(assert_epoch(epoch)?)?;
    let member = assert_fingerprint(fp)?;
    if link_fp.is_empty() || link_fp.len() > 256 {
        return Err(bad("link fingerprint is missing or oversized"));
    }
    Ok(lp(
        "securebit/group/link-probe/v1",
        &[
            Part::Bytes(&gid),
            Part::Bytes(&epoch_be),
            Part::Bytes(&member),
            Part::Text(link_fp),
        ],
    ))
}

pub fn sign_link_probe(
    identity: &GroupIdentity,
    group_id: &str,
    epoch: u64,
    fp: &str,
    link_fp: &str,
) -> Result<Vec<u8>, CoreError> {
    identity.sign(&link_probe_payload(group_id, epoch, fp, link_fp)?)
}

pub fn verify_link_probe(
    key: &VerifyingKey,
    group_id: &str,
    epoch: u64,
    fp: &str,
    link_fp: &str,
    signature: &[u8],
) -> bool {
    match link_probe_payload(group_id, epoch, fp, link_fp) {
        Ok(payload) => verify_with(key, &payload, signature),
        Err(_) => false,
    }
}

/// A fresh group id. Shared between members, unlike a local session id.
pub fn new_group_id() -> String {
    let mut bytes = [0u8; GROUP_ID_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------
//
// The vectors below were produced by the JavaScript implementation that the web
// client actually runs (`src/group/groupCrypto.js`). They are the whole point of
// this file: they are what says the port agrees with the browser rather than
// merely looking like it does.

#[cfg(test)]
mod tests {
    use super::*;

    const GID: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";
    const EPOCH: u64 = 7;
    const FP_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const FP_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const FP_C: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const NAME: &str = "Наша группа";

    fn fps() -> Vec<String> {
        vec![FP_B.to_string(), FP_A.to_string(), FP_C.to_string()]
    }

    /// The key the JS side signed with, so a browser-made signature can be
    /// checked here and a Rust-made one can be checked the same way.
    const PKCS8_HEX: &str = "3081b6020100301006072a8648ce3d020106052b8104002204819e30819b020101043014ffd3da2b0faa0a363f85b7fdeee6ef67d355fe9fa8ae342edc20e06dca17079b7259dd22becbf96259cbd10b35c7d3a16403620004230efeef9be21917d98301a74839f6aa1aac0cb883cb566b609e34f1a0f50cc2ab23429de2a0e41adc2ff033471e376e96397aaa40727d239908c966da53a12d23ef36a9b13a3e5730ee167bbef4a7828bfe814fd2312d181642ae7a5093a788";
    const SPKI_HEX: &str = "3076301006072a8648ce3d020106052b8104002203620004230efeef9be21917d98301a74839f6aa1aac0cb883cb566b609e34f1a0f50cc2ab23429de2a0e41adc2ff033471e376e96397aaa40727d239908c966da53a12d23ef36a9b13a3e5730ee167bbef4a7828bfe814fd2312d181642ae7a5093a788";
    const SPKI_FINGERPRINT: &str =
        "4f39122eb7607b3b668d00d831372172a9fd558f7f1b98bdd1a350236b5d5284";
    /// Produced by WebCrypto over `member_op_payload(GID, 7, add, fps, NAME)`.
    const JS_MEMBER_OP_SIG_HEX: &str = "7340c8f4c3a2de1984a908c406897e6da96ecd83e65d344dc7b99c1b301aec27cb487dcac6a27fbd152237a3d6099cf978fce82f3b71f55faf56fdea109af549ae7145721da92be693746f98eca5005ed9cec5e029d90d615a739f379977282f";

    #[test]
    fn member_op_payload_matches_web_reference() {
        let payload = member_op_payload(GID, EPOCH, MemberOp::Add, &fps(), NAME).unwrap();
        assert_eq!(hex::encode(payload), "7365637572656269742f67726f75702f6d656d6265722d6f702f763100000000100f1e2d3c4b5a69788796a5b4c3d2e1f000000004000000070000000361646400000015d09dd0b0d188d0b020d0b3d180d183d0bfd0bfd0b000000020111111111111111111111111111111111111111111111111111111111111111100000020aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000020bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    }

    #[test]
    fn message_payload_and_body_hash_match_web_reference() {
        let body_hash = hash_body("привет".as_bytes()).unwrap();
        assert_eq!(
            hex::encode(body_hash),
            "e58f1e8c55fa105bdd3f40e5037eb0b039b5998d52c05e6cd98878dd2da5cab2"
        );
        let payload = group_message_payload(GID, EPOCH, 3, FP_A, &body_hash).unwrap();
        assert_eq!(hex::encode(payload), "7365637572656269742f67726f75702f6d6573736167652f763100000000100f1e2d3c4b5a69788796a5b4c3d2e1f00000000400000007000000040000000300000020aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000020e58f1e8c55fa105bdd3f40e5037eb0b039b5998d52c05e6cd98878dd2da5cab2");
    }

    #[test]
    fn mesh_payloads_match_web_reference() {
        let nonce: Vec<u8> = (1..=16u8).collect();
        let offer = mesh_descriptor_payload(GID, EPOCH, MeshKind::Offer, FP_A, FP_B, "SB2:abc", &nonce).unwrap();
        assert_eq!(hex::encode(offer), "7365637572656269742f67726f75702f6d6573682d64657363726970746f722f763100000000100f1e2d3c4b5a69788796a5b4c3d2e1f00000000400000007000000066d6f6666657200000020aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000020bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000075342323a616263000000100102030405060708090a0b0c0d0e0f10");

        let answer = mesh_descriptor_payload(GID, EPOCH, MeshKind::Answer, FP_B, FP_A, "SB2:xyz", &nonce).unwrap();
        assert_eq!(hex::encode(answer), "7365637572656269742f67726f75702f6d6573682d64657363726970746f722f763100000000100f1e2d3c4b5a69788796a5b4c3d2e1f00000000400000007000000076d616e7377657200000020bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb00000020aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000000075342323a78797a000000100102030405060708090a0b0c0d0e0f10");
    }

    #[test]
    fn link_probe_payload_matches_web_reference() {
        let payload = link_probe_payload(GID, EPOCH, FP_A, "ab:cd:ef").unwrap();
        assert_eq!(hex::encode(payload), "7365637572656269742f67726f75702f6c696e6b2d70726f62652f763100000000100f1e2d3c4b5a69788796a5b4c3d2e1f0000000040000000700000020aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000861623a63643a6566");
    }

    #[test]
    fn commitment_matches_web_reference() {
        let nonce: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(7).wrapping_add(3)).collect();
        let commitment = build_commitment(GID, EPOCH, FP_A, &nonce).unwrap();
        assert_eq!(
            hex::encode(commitment),
            "1e269f1da6a02ab57068aa56659b8ce74477f766eaee845aeafb069d511df9b1"
        );
        assert!(verify_commitment(&commitment, GID, EPOCH, FP_A, &nonce));
        // A nonce that is not the committed one must not verify.
        assert!(!verify_commitment(&commitment, GID, EPOCH, FP_A, &[0u8; 32]));
        // Nor the right nonce in a different epoch or group.
        assert!(!verify_commitment(&commitment, GID, EPOCH + 1, FP_A, &nonce));
    }

    #[test]
    fn group_sas_matches_web_reference() {
        let contributions = vec![
            Contribution {
                fingerprint: FP_A.to_string(),
                nonce: (0..32u8).map(|i| i.wrapping_mul(7).wrapping_add(3)).collect(),
            },
            Contribution { fingerprint: FP_B.to_string(), nonce: vec![0x5a; 32] },
            Contribution { fingerprint: FP_C.to_string(), nonce: vec![0xc3; 32] },
        ];
        let code = compute_group_sas(GID, EPOCH, &contributions, SAS_DIGITS).unwrap();
        assert_eq!(code, "2595495", "the digits every member reads aloud must match the web client");
        assert_eq!(code.len(), SAS_DIGITS as usize);
    }

    #[test]
    fn sas_order_does_not_depend_on_the_order_members_arrive_in() {
        let a = Contribution { fingerprint: FP_A.to_string(), nonce: vec![1u8; 32] };
        let b = Contribution { fingerprint: FP_B.to_string(), nonce: vec![2u8; 32] };
        let c = Contribution { fingerprint: FP_C.to_string(), nonce: vec![3u8; 32] };
        let one = compute_group_sas(GID, EPOCH, &[a.clone(), b.clone(), c.clone()], SAS_DIGITS).unwrap();
        let two = compute_group_sas(GID, EPOCH, &[c, a, b], SAS_DIGITS).unwrap();
        assert_eq!(one, two);
    }

    #[test]
    fn a_substituted_nonce_changes_the_code() {
        let base = vec![
            Contribution { fingerprint: FP_A.to_string(), nonce: vec![1u8; 32] },
            Contribution { fingerprint: FP_B.to_string(), nonce: vec![2u8; 32] },
        ];
        let mut swapped = base.clone();
        swapped[1].nonce = vec![3u8; 32];
        assert_ne!(
            compute_group_sas(GID, EPOCH, &base, SAS_DIGITS).unwrap(),
            compute_group_sas(GID, EPOCH, &swapped, SAS_DIGITS).unwrap()
        );
    }

    #[test]
    fn identity_fingerprint_matches_web_reference() {
        let spki = hex::decode(SPKI_HEX).unwrap();
        assert_eq!(fingerprint_spki(&spki).unwrap(), SPKI_FINGERPRINT);
        let (_, fp) = import_member_identity(&spki).unwrap();
        assert_eq!(fp, SPKI_FINGERPRINT);
    }

    #[test]
    fn a_signature_made_by_the_web_client_verifies_here() {
        let spki = hex::decode(SPKI_HEX).unwrap();
        let (key, _) = import_member_identity(&spki).unwrap();
        let sig = hex::decode(JS_MEMBER_OP_SIG_HEX).unwrap();
        assert_eq!(sig.len(), 96, "WebCrypto emits the raw r‖s pair, never DER");
        assert!(
            verify_member_op(&key, GID, EPOCH, MemberOp::Add, &fps(), NAME, &sig),
            "a roster signed in a browser must verify in the core"
        );
        // The same signature over anything else must not.
        assert!(!verify_member_op(&key, GID, EPOCH, MemberOp::Remove, &fps(), NAME, &sig));
        assert!(!verify_member_op(&key, GID, EPOCH + 1, MemberOp::Add, &fps(), NAME, &sig));
        assert!(!verify_member_op(&key, GID, EPOCH, MemberOp::Add, &fps(), "Other name", &sig));
    }

    #[test]
    fn a_signature_made_here_uses_the_shape_the_web_client_accepts() {
        let identity = GroupIdentity::from_pkcs8_der(&hex::decode(PKCS8_HEX).unwrap()).unwrap();
        assert_eq!(hex::encode(&identity.spki), SPKI_HEX, "the SPKI encoding must be identical");
        assert_eq!(identity.fingerprint, SPKI_FINGERPRINT);

        let sig = sign_member_op(&identity, GID, EPOCH, MemberOp::Add, &fps(), NAME).unwrap();
        assert_eq!(sig.len(), 96);
        let key = identity.verifying_key();
        assert!(verify_member_op(&key, GID, EPOCH, MemberOp::Add, &fps(), NAME, &sig));
    }

    #[test]
    fn every_signed_payload_round_trips() {
        let identity = GroupIdentity::generate().unwrap();
        let key = identity.verifying_key();
        let fp = identity.fingerprint.clone();
        let members = vec![fp.clone(), FP_B.to_string()];

        let body_hash = hash_body(b"hello").unwrap();
        let msg_sig = sign_group_message(&identity, GID, EPOCH, 1, &fp, &body_hash).unwrap();
        assert!(verify_group_message(&key, GID, EPOCH, 1, &fp, &body_hash, &msg_sig));
        // A different sequence number is a different message.
        assert!(!verify_group_message(&key, GID, EPOCH, 2, &fp, &body_hash, &msg_sig));

        let op_sig = sign_member_op(&identity, GID, EPOCH, MemberOp::Create, &members, "g").unwrap();
        assert!(verify_member_op(&key, GID, EPOCH, MemberOp::Create, &members, "g", &op_sig));

        let nonce: Vec<u8> = (1..=16u8).collect();
        let mesh_sig = sign_mesh_descriptor(&identity, GID, EPOCH, MeshKind::Offer, &fp, FP_B, "SB2:d", &nonce).unwrap();
        assert!(verify_mesh_descriptor(&key, GID, EPOCH, MeshKind::Offer, &fp, FP_B, "SB2:d", &nonce, &mesh_sig));
        // An offer replayed back as an answer must not verify.
        assert!(!verify_mesh_descriptor(&key, GID, EPOCH, MeshKind::Answer, &fp, FP_B, "SB2:d", &nonce, &mesh_sig));
        // Nor may it be re-aimed at a different member, or matched to another dial.
        assert!(!verify_mesh_descriptor(&key, GID, EPOCH, MeshKind::Offer, &fp, FP_C, "SB2:d", &nonce, &mesh_sig));
        assert!(!verify_mesh_descriptor(&key, GID, EPOCH, MeshKind::Offer, &fp, FP_B, "SB2:d", &[9u8; 16], &mesh_sig));

        let probe_sig = sign_link_probe(&identity, GID, EPOCH, &fp, "ab:cd").unwrap();
        assert!(verify_link_probe(&key, GID, EPOCH, &fp, "ab:cd", &probe_sig));
        // A probe replayed onto a different session carries the wrong link
        // fingerprint and must be refused — this is the check that stops a
        // member impersonating another on their own link.
        assert!(!verify_link_probe(&key, GID, EPOCH, &fp, "ef:01", &probe_sig));
    }

    #[test]
    fn hostile_values_are_refused_before_use() {
        assert!(assert_group_id("nope").is_err());
        assert!(assert_group_id("0F1E2D3C4B5A69788796A5B4C3D2E1F0").is_err(), "hex is lowercase on the wire");
        assert!(assert_fingerprint("aa").is_err());
        assert!(assert_epoch(MAX_EPOCH + 1).is_err());
        assert!(assert_name(&"x".repeat(MAX_NAME_BYTES + 1)).is_err());
        assert!(hash_body(&vec![0u8; MAX_BODY_BYTES + 1]).is_err());
        assert!(fingerprint_spki(&[0u8; 8]).is_err());
        assert!(import_member_identity(&[7u8; 64]).is_err());

        // A group is at least two members and at most eight, with no duplicates.
        assert!(canonical_fingerprints(&[FP_A.to_string()]).is_err());
        assert!(canonical_fingerprints(&[FP_A.to_string(), FP_A.to_string()]).is_err());
        let too_many: Vec<String> = (0..=MAX_MEMBERS)
            .map(|i| format!("{:02x}", i).repeat(32))
            .collect();
        assert!(canonical_fingerprints(&too_many).is_err());

        // Descriptor bounds, and a member dialling itself.
        let nonce: Vec<u8> = (1..=16u8).collect();
        assert!(mesh_descriptor_payload(GID, EPOCH, MeshKind::Offer, FP_A, FP_A, "SB2:d", &nonce).is_err());
        assert!(mesh_descriptor_payload(GID, EPOCH, MeshKind::Offer, FP_A, FP_B, "", &nonce).is_err());
        let huge = "x".repeat(MAX_DESCRIPTOR_CHARS + 1);
        assert!(mesh_descriptor_payload(GID, EPOCH, MeshKind::Offer, FP_A, FP_B, &huge, &nonce).is_err());
        assert!(mesh_descriptor_payload(GID, EPOCH, MeshKind::Offer, FP_A, FP_B, "SB2:d", &[0u8; 8]).is_err());
    }

    #[test]
    fn the_ceremony_refuses_to_reveal_early() {
        let a = GroupIdentity::generate().unwrap();
        let b = GroupIdentity::generate().unwrap();
        let members = vec![a.fingerprint.clone(), b.fingerprint.clone()];

        let mut ca = GroupSasCeremony::new(GID, EPOCH, &a.fingerprint, &members).unwrap();
        let mut cb = GroupSasCeremony::new(GID, EPOCH, &b.fingerprint, &members).unwrap();

        let commit_a = ca.own_commitment().unwrap();
        let commit_b = cb.own_commitment().unwrap();

        // Nobody may reveal while a commitment is still outstanding. This is the
        // whole security argument for a seven-digit code.
        assert!(ca.reveal().is_err());
        assert!(!ca.commitments_complete());

        ca.accept_commitment(&b.fingerprint, &commit_b).unwrap();
        cb.accept_commitment(&a.fingerprint, &commit_a).unwrap();
        assert!(ca.commitments_complete());

        let nonce_a = ca.reveal().unwrap();
        let nonce_b = cb.reveal().unwrap();

        ca.accept_reveal(&b.fingerprint, &nonce_b).unwrap();
        cb.accept_reveal(&a.fingerprint, &nonce_a).unwrap();

        let code_a = ca.finish().unwrap();
        let code_b = cb.finish().unwrap();
        assert_eq!(code_a, code_b, "both members must read the same digits");
        assert_eq!(code_a.len(), SAS_DIGITS as usize);
    }

    #[test]
    fn the_ceremony_refuses_a_changed_commitment_and_a_wrong_nonce() {
        let a = GroupIdentity::generate().unwrap();
        let b = GroupIdentity::generate().unwrap();
        let members = vec![a.fingerprint.clone(), b.fingerprint.clone()];
        let mut ca = GroupSasCeremony::new(GID, EPOCH, &a.fingerprint, &members).unwrap();
        ca.own_commitment().unwrap();

        let commit_b = build_commitment(GID, EPOCH, &b.fingerprint, &[1u8; 32]).unwrap();
        ca.accept_commitment(&b.fingerprint, &commit_b).unwrap();
        // Recording the same one twice is idempotent; a different one is not.
        assert_eq!(ca.accept_commitment(&b.fingerprint, &commit_b).unwrap(), false);
        let other = build_commitment(GID, EPOCH, &b.fingerprint, &[2u8; 32]).unwrap();
        assert!(ca.accept_commitment(&b.fingerprint, &other).is_err());

        // A commitment from outside the member set is refused outright.
        assert!(ca.accept_commitment(FP_C, &commit_b).is_err());

        ca.reveal().unwrap();
        // The nonce must be the one that was committed to.
        assert!(ca.accept_reveal(&b.fingerprint, &[2u8; 32]).is_err());
        ca.accept_reveal(&b.fingerprint, &[1u8; 32]).unwrap();
        assert!(ca.reveals_complete());
    }
}
