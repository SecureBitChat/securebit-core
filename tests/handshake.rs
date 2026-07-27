// End-to-end handshake round-trip within the core, exercising the active path the
// Tauri frontend uses: create_secure_offer -> join_secure_connection -> handle_secure_answer.
// Verifies the protocol version is 4.1, the ECDH signature verifies, both sides derive
// the same session keys (proven by an encrypt/decrypt round-trip), and the SAS code is
// produced. This guards against regressions in the web-compatibility fixes.
use securebit_core::Core;
use serde_json::Value;

#[test]
fn offer_join_handle_roundtrip() {
    // Offerer creates a secure offer (protocol v4.1).
    let offerer = Core::new();
    let offer = offerer.create_secure_offer(None, None).expect("create_secure_offer failed");
    assert!(offer.starts_with("SB1:gz:"), "offer should be SB1:gz encoded");

    // Answerer joins, deriving its session keys and returning a signed answer.
    let answerer = Core::new();
    let answer = answerer
        .join_secure_connection(None, offer.clone(), None)
        .expect("join_secure_connection failed");
    assert!(answer.starts_with("SB1:gz:"), "answer should be SB1:gz encoded");

    // Offerer verifies the answer signature, derives keys, and computes the SAS.
    let confirmation = offerer
        .handle_secure_answer(None, answer)
        .expect("handle_secure_answer failed (signature or key derivation)");
    let conf: Value = serde_json::from_str(&confirmation).unwrap();

    assert_eq!(conf["protocolVersion"].as_str(), Some("4.1"), "protocol must be 4.1");

    let vc = conf["verificationCode"].as_str().unwrap_or("");
    assert_eq!(vc.len(), 7, "SAS must be 7 digits, got '{}'", vc);
    assert!(vc.chars().all(|c| c.is_ascii_digit()), "SAS must be numeric");

    // Both sides must expose the SAS they derived THEMSELVES through the same API
    // the frontend reads (get_session_crypto). The joining side used to derive
    // none and displayed whatever the offerer announced over the wire, so a peer
    // in the middle could show both users the same number.
    let joiner_crypto = answerer.get_session_crypto(None);
    let offerer_crypto = offerer.get_session_crypto(None);

    let joiner_vc = joiner_crypto["verificationCode"]
        .as_str()
        .expect("the joining side must derive and expose its own SAS");
    let offerer_vc = offerer_crypto["verificationCode"]
        .as_str()
        .expect("the offering side must expose its SAS");

    assert_eq!(joiner_vc, offerer_vc, "both peers must independently reach the same SAS");
    assert_eq!(offerer_vc, vc, "the exposed SAS must match the one reported to the frontend");

    // Prove both sides agreed on the same keys: answerer encrypts, offerer decrypts.
    let plaintext = "hello from desktop";
    let enc = answerer
        .encrypt_enhanced_message(None, plaintext.to_string(), "m1".to_string(), 1)
        .expect("encrypt_enhanced_message failed");
    let enc_payload: Value = serde_json::from_str(&enc).unwrap();

    // decrypt_enhanced_message expects the payload under a "data" field.
    let wrapped = serde_json::json!({ "type": "enhanced_message", "data": enc_payload });
    let dec = offerer
        .decrypt_enhanced_message(None, wrapped.to_string())
        .expect("decrypt_enhanced_message failed (key mismatch?)");
    let dec_val: Value = serde_json::from_str(&dec).unwrap();
    assert_eq!(dec_val["message"].as_str(), Some(plaintext), "decrypted message mismatch");
}
