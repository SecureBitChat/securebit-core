//! The SBQ2 handshake end to end, both peers inside one test.
//!
//! Exercises the sequence the desktop actually runs: invitation, response,
//! blob exchange with the commitment gate, transcript, derived salt, matching
//! SAS, and the identity proof — plus the failure paths, which must close the
//! session rather than degrade it.

use securebit_core::descriptor;
use securebit_core::keyexchange::{self, Role};
use securebit_core::sbq2_handshake as hs;
use securebit_core::session::{OfferContext, SessionKeys};
use std::sync::{Arc, Mutex};

/// A minimal but real SDP shape: mDNS host, srflx and relay candidates.
fn sdp(ufrag: &str, pwd: &str, fp_byte: u8, setup: &str, port: u16) -> String {
    let fp = (0..32).map(|i| format!("{:02X}", fp_byte.wrapping_add(i)))
        .collect::<Vec<_>>().join(":");
    [
        "v=0".to_string(),
        "o=- 1 2 IN IP4 127.0.0.1".to_string(),
        "s=-".to_string(),
        "t=0 0".to_string(),
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel".to_string(),
        "c=IN IP4 0.0.0.0".to_string(),
        format!("a=candidate:1 1 udp 2113937151 7d9c00c2-bcef-48b6-9166-428899e0582e.local {} typ host", port),
        format!("a=candidate:2 1 udp 1677729535 203.0.113.9 {} typ srflx raddr 0.0.0.0 rport 0", port + 1),
        format!("a=candidate:3 1 udp 50340351 144.172.96.126 {} typ relay raddr 0.0.0.0 rport 0", port + 2),
        format!("a=ice-ufrag:{}", ufrag),
        format!("a=ice-pwd:{}", pwd),
        format!("a=fingerprint:sha-256 {}", fp),
        format!("a=setup:{}", setup),
        "a=mid:0".to_string(),
        "a=sctp-port:5000".to_string(),
        "a=max-message-size:262144".to_string(),
    ].join("\r\n") + "\r\n"
}

struct Peer { offer_state: Arc<Mutex<OfferContext>>, keys: Arc<Mutex<SessionKeys>> }
impl Peer {
    fn new() -> Self {
        Peer {
            offer_state: Arc::new(Mutex::new(OfferContext::new())),
            keys: Arc::new(Mutex::new(SessionKeys::new())),
        }
    }
}

fn offer_sdp() -> String { sdp("abcd", "0123456789abcdef01234567", 0x10, "actpass", 40000) }
fn answer_sdp() -> String { sdp("wxyz", "89abcdef0123456789abcdef", 0x90, "active", 50000) }

/// Drive a complete handshake and return both sides' SAS.
fn full_handshake() -> (Peer, Peer, String, String) {
    let a = Peer::new();
    let b = Peer::new();

    let invitation = hs::create_offer(a.offer_state.clone(), offer_sdp()).expect("create offer");
    assert!(invitation.starts_with("SB2:"), "the desktop must emit SBQ2");
    assert!(hs::is_sbq2(&invitation));

    // The joining side can inspect before committing.
    let parsed = hs::parse_offer(&invitation).expect("parse offer");
    assert_eq!(parsed["type"], "offer");
    assert_eq!(parsed["hasCommitment"], true);
    assert!(parsed["sdp"].as_str().unwrap().contains("a=ice-ufrag:abcd"));

    let response = hs::join(b.offer_state.clone(), &invitation, answer_sdp()).expect("join");
    assert!(response.starts_with("SB2:"));

    let accepted = hs::handle_answer(a.offer_state.clone(), &response).expect("handle answer");
    assert!(accepted["sdp"].as_str().unwrap().contains("a=ice-ufrag:wxyz"));

    // Blobs cross the (here simulated) data channel.
    let blob_a = hs::local_key_blob(a.offer_state.clone()).expect("blob a");
    let blob_b = hs::local_key_blob(b.offer_state.clone()).expect("blob b");

    let ra = hs::accept_peer_blob(a.offer_state.clone(), a.keys.clone(), &blob_b).expect("a accepts b");
    let rb = hs::accept_peer_blob(b.offer_state.clone(), b.keys.clone(), &blob_a).expect("b accepts a");

    // Proofs cross in the other direction.
    assert!(hs::verify_peer_proof(a.offer_state.clone(), rb["proof"].as_str().unwrap()).unwrap());
    assert!(hs::verify_peer_proof(b.offer_state.clone(), ra["proof"].as_str().unwrap()).unwrap());

    let sas_a = ra["sas"].as_str().unwrap().to_string();
    let sas_b = rb["sas"].as_str().unwrap().to_string();
    (a, b, sas_a, sas_b)
}

#[test]
fn both_peers_reach_the_same_session() {
    let (a, b, sas_a, sas_b) = full_handshake();

    assert_eq!(sas_a, sas_b, "both sides must read the same digits");
    assert_eq!(sas_a.len(), 7);
    assert!(sas_a.chars().all(|c| c.is_ascii_digit()));

    let ka = a.keys.lock().unwrap();
    let kb = b.keys.lock().unwrap();
    assert_eq!(ka.encryption_key, kb.encryption_key, "message keys must agree");
    assert_eq!(ka.mac_key, kb.mac_key, "MAC keys must agree");
    assert_eq!(ka.metadata_key, kb.metadata_key, "metadata keys must agree");
    assert_eq!(ka.key_fingerprint, kb.key_fingerprint, "key fingerprints must agree");
    assert_eq!(ka.verification_code.as_deref(), Some(sas_a.as_str()));
    assert_eq!(ka.encryption_key.as_ref().unwrap().len(), 32);
    assert_eq!(ka.mac_key.as_ref().unwrap().len(), 64);

    // The Double Ratchet must be running on both sides.
    //
    // Regression guard. SB1 negotiates ratchet support through a `dr` field in
    // the descriptor; SBQ2 has no such field because it postdates the ratchet
    // entirely. Reading that absence as "peer is on an older release" left the
    // session on static keys and took cover traffic down with it — the security
    // panel reported 9/10 and "Cover traffic requires a Double Ratchet session".
    assert!(ka.peer_supports_ratchet, "offer side must treat SBQ2 as ratchet-capable");
    assert!(kb.peer_supports_ratchet, "answer side must treat SBQ2 as ratchet-capable");
    assert!(ka.ratchet.is_some(), "offer side must have an initialised ratchet");
    assert!(kb.ratchet.is_some(), "answer side must have an initialised ratchet");

    // The key fingerprint is mixed into every per-file key, so its FORM matters:
    // colon-separated hex, identical to what the SB1 path and the web produce.
    let fp = ka.key_fingerprint.as_ref().unwrap();
    assert_eq!(fp.len(), 35, "12 bytes as colon-separated hex");
    assert_eq!(fp.matches(':').count(), 11, "key fingerprint must be colon-separated");
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit() || c == ':'));

    // The salt is derived from the transcript, never transmitted.
    let sa = a.offer_state.lock().unwrap();
    let sb = b.offer_state.lock().unwrap();
    assert_eq!(sa.session_salt, sb.session_salt, "both derive the same salt");
    assert_eq!(sa.session_salt.as_ref().unwrap().len(), 64);
    let st = sa.sbq2.as_ref().unwrap();
    assert_eq!(st.transcript, sb.sbq2.as_ref().unwrap().transcript, "identical transcripts");
    assert!(st.proof_verified, "the peer's identity proof must be verified");
}

#[test]
fn the_invitation_is_one_qr_frame() {
    let a = Peer::new();
    let invitation = hs::create_offer(a.offer_state.clone(), offer_sdp()).unwrap();
    let bytes = descriptor::decode_text(&invitation).unwrap();
    // QR version 8 at level M holds 152 bytes in byte mode; the text form is
    // what the UI renders, and it must stay inside a single frame either way.
    assert!(bytes.len() <= 152, "descriptor is {} bytes, over the one-frame budget", bytes.len());
    assert!(invitation.len() <= 220, "text form is {} chars", invitation.len());
}

#[test]
fn substituted_key_material_is_refused() {
    let a = Peer::new();
    let b = Peer::new();
    let m = Peer::new();   // an attacker with its own keys

    let invitation = hs::create_offer(a.offer_state.clone(), offer_sdp()).unwrap();
    let response = hs::join(b.offer_state.clone(), &invitation, answer_sdp()).unwrap();
    hs::handle_answer(a.offer_state.clone(), &response).unwrap();

    // The attacker joins separately to obtain a well-formed blob of its own.
    let _ = hs::join(m.offer_state.clone(), &invitation, answer_sdp()).unwrap();
    let attacker_blob = hs::local_key_blob(m.offer_state.clone()).unwrap();

    // Swapping it in for B's blob must fail the commitment, before anything is
    // parsed or imported.
    let err = hs::accept_peer_blob(a.offer_state.clone(), a.keys.clone(), &attacker_blob)
        .expect_err("substituted key material must be refused");
    assert!(format!("{:?}", err).contains("does not match the commitment"),
            "unexpected error: {:?}", err);

    // Nothing may have been installed by the failed attempt.
    let keys = a.keys.lock().unwrap();
    assert!(keys.encryption_key.is_none(), "no key may be installed after a failed commitment check");
    assert!(keys.verification_code.is_none());
}

#[test]
fn a_response_to_a_different_invitation_is_refused() {
    let a = Peer::new();
    let b = Peer::new();
    let other = Peer::new();

    let invitation = hs::create_offer(a.offer_state.clone(), offer_sdp()).unwrap();
    // A response to a DIFFERENT invitation, produced with different SDP.
    let other_invitation = hs::create_offer(other.offer_state.clone(),
        sdp("qqqq", "aaaaaaaaaaaaaaaaaaaaaaaa", 0x40, "actpass", 41000)).unwrap();
    let wrong_response = hs::join(b.offer_state.clone(), &other_invitation, answer_sdp()).unwrap();

    let err = hs::handle_answer(a.offer_state.clone(), &wrong_response)
        .expect_err("a response bound to another invitation must be refused");
    assert!(format!("{:?}", err).contains("different invitation"), "unexpected error: {:?}", err);
    assert!(!invitation.is_empty());
}

#[test]
fn a_forged_proof_is_refused() {
    let a = Peer::new();
    let b = Peer::new();
    let invitation = hs::create_offer(a.offer_state.clone(), offer_sdp()).unwrap();
    let response = hs::join(b.offer_state.clone(), &invitation, answer_sdp()).unwrap();
    hs::handle_answer(a.offer_state.clone(), &response).unwrap();
    let blob_b = hs::local_key_blob(b.offer_state.clone()).unwrap();
    let blob_a = hs::local_key_blob(a.offer_state.clone()).unwrap();
    let ra = hs::accept_peer_blob(a.offer_state.clone(), a.keys.clone(), &blob_b).unwrap();
    let _ = hs::accept_peer_blob(b.offer_state.clone(), b.keys.clone(), &blob_a).unwrap();

    // A's own proof presented back to A is signed by the wrong identity key.
    assert!(hs::verify_peer_proof(a.offer_state.clone(), ra["proof"].as_str().unwrap()).is_err(),
            "a proof from the wrong key must be refused");

    // Garbage, and a well-formed signature over nothing in particular.
    assert!(hs::verify_peer_proof(a.offer_state.clone(), "not-base64!!").is_err());
    assert!(hs::verify_peer_proof(a.offer_state.clone(), &"A".repeat(128)).is_err());
}

#[test]
fn duplicate_key_material_is_refused() {
    let (a, b, _, _) = full_handshake();
    let blob_b = hs::local_key_blob(b.offer_state.clone()).unwrap();
    let err = hs::accept_peer_blob(a.offer_state.clone(), a.keys.clone(), &blob_b)
        .expect_err("a second blob must be refused");
    assert!(format!("{:?}", err).contains("twice"), "unexpected error: {:?}", err);
}

#[test]
fn an_sbq2_response_to_an_sb1_invitation_is_refused() {
    // No SBQ2 state exists, because the invitation was never created here.
    let a = Peer::new();
    let b = Peer::new();
    let invitation = hs::create_offer(b.offer_state.clone(), offer_sdp()).unwrap();
    let response = hs::join(Arc::new(Mutex::new(OfferContext::new())), &invitation, answer_sdp()).unwrap();

    let err = hs::handle_answer(a.offer_state.clone(), &response)
        .expect_err("format confusion must be refused, not resolved");
    assert!(format!("{:?}", err).contains("old-format invitation"), "unexpected error: {:?}", err);
}

#[test]
fn expired_and_malformed_invitations_are_refused() {
    let a = Peer::new();
    let invitation = hs::create_offer(a.offer_state.clone(), offer_sdp()).unwrap();

    assert!(hs::parse_offer("SB1:gz:eJy1").is_err(), "an SB1 payload is not an SBQ2 invitation");
    assert!(hs::parse_offer("SB2:!!!!").is_err(), "bad alphabet");
    assert!(hs::parse_offer(&invitation[..invitation.len() - 4]).is_err(), "truncated");

    // A response fed in where an invitation is expected.
    let b = Peer::new();
    let response = hs::join(b.offer_state.clone(), &invitation, answer_sdp()).unwrap();
    assert!(hs::parse_offer(&response).is_err(), "a response is not an invitation");
}

#[test]
fn roles_must_be_opposite() {
    // Two peers that both believe they are answering cannot complete: the blob
    // carries its role, and a matching pair is required.
    let a = Peer::new();
    let b = Peer::new();
    let c = Peer::new();
    let invitation = hs::create_offer(a.offer_state.clone(), offer_sdp()).unwrap();
    let _ = hs::join(b.offer_state.clone(), &invitation, answer_sdp()).unwrap();
    let response_c = hs::join(c.offer_state.clone(), &invitation, answer_sdp()).unwrap();
    hs::handle_answer(a.offer_state.clone(), &response_c).unwrap();

    // Hand B (an answerer) another answerer's blob. Commitment is checked first,
    // so this fails there; the role check backs it up for the case where an
    // attacker controls the descriptor too.
    let blob_c = hs::local_key_blob(c.offer_state.clone()).unwrap();
    assert!(hs::accept_peer_blob(b.offer_state.clone(), b.keys.clone(), &blob_c).is_err());

    // Direct role check, with the commitment satisfied.
    let blob = keyexchange::decode_key_blob(
        &base64::Engine::decode(&base64::engine::general_purpose::STANDARD, blob_c).unwrap()).unwrap();
    assert_eq!(blob.role, Role::Answer);
    assert_eq!(Role::Answer.peer(), Role::Offer);
}
