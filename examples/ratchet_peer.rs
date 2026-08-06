// Line-delimited JSON driver around DoubleRatchet, so the WEB reference
// implementation (securebit-chat/src/crypto/DoubleRatchet.js, running in Node)
// can hold a live conversation with this Rust port and prove byte
// compatibility — KDF tree, header format, AAD discipline, SPKI encoding, DH
// truncation — over real frames in both directions.
//
// Driven by tests/ratchet-interop.mjs in the desktop repo. Protocol, one JSON
// object per line on stdin, one per line on stdout:
//
//   {"cmd":"init","role":"initiator","root":[..32],"salt":[..64],"peerPublicSpki":"<b64>"}
//   {"cmd":"init","role":"responder","root":[..32],"salt":[..64],"selfPrivatePkcs8":"<b64>"}
//   {"cmd":"canEncrypt"}                    -> {"canEncrypt":bool}
//   {"cmd":"encrypt","plaintext":"..."}     -> {"h":"...","c":"..."}
//   {"cmd":"decrypt","h":"...","c":"..."}   -> {"plaintext":"..."} | {"error":"..."}

use base64::{engine::general_purpose, Engine};
use securebit_core::ratchet::DoubleRatchet;
use std::io::{BufRead, Write};

fn bytes(v: &serde_json::Value) -> Vec<u8> {
    v.as_array()
        .expect("byte array")
        .iter()
        .map(|n| n.as_u64().expect("byte") as u8)
        .collect()
}

fn main() {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut ratchet: Option<DoubleRatchet> = None;

    for line in stdin.lock().lines() {
        let line = line.expect("stdin read");
        if line.trim().is_empty() {
            continue;
        }
        let req: serde_json::Value = serde_json::from_str(&line).expect("valid JSON command");
        let reply = match req["cmd"].as_str() {
            Some("init") => {
                let root = bytes(&req["root"]);
                let salt = bytes(&req["salt"]);
                let result = match req["role"].as_str() {
                    Some("initiator") => {
                        let spki = general_purpose::STANDARD
                            .decode(req["peerPublicSpki"].as_str().expect("peerPublicSpki"))
                            .expect("b64 spki");
                        use p384::pkcs8::DecodePublicKey;
                        let peer = p384::PublicKey::from_public_key_der(&spki).expect("peer key");
                        DoubleRatchet::init_initiator(&root, &salt, &peer)
                    }
                    Some("responder") => {
                        let pkcs8 = general_purpose::STANDARD
                            .decode(req["selfPrivatePkcs8"].as_str().expect("selfPrivatePkcs8"))
                            .expect("b64 pkcs8");
                        use p384::pkcs8::DecodePrivateKey;
                        let own = p384::SecretKey::from_pkcs8_der(&pkcs8).expect("own key");
                        DoubleRatchet::init_responder(&root, &salt, own)
                    }
                    _ => panic!("unknown role"),
                };
                match result {
                    Ok(r) => {
                        ratchet = Some(r);
                        serde_json::json!({"ok": true})
                    }
                    Err(e) => serde_json::json!({"error": e}),
                }
            }
            Some("canEncrypt") => {
                serde_json::json!({"canEncrypt": ratchet.as_ref().map(|r| r.can_encrypt()).unwrap_or(false)})
            }
            Some("encrypt") => {
                let r = ratchet.as_mut().expect("init first");
                match r.encrypt(req["plaintext"].as_str().expect("plaintext")) {
                    Ok((h, c)) => serde_json::json!({"h": h, "c": c}),
                    Err(e) => serde_json::json!({"error": e}),
                }
            }
            Some("decrypt") => {
                let r = ratchet.as_mut().expect("init first");
                match r.decrypt(
                    req["h"].as_str().expect("h"),
                    req["c"].as_str().expect("c"),
                ) {
                    Ok(p) => serde_json::json!({"plaintext": p}),
                    Err(e) => serde_json::json!({"error": e}),
                }
            }
            _ => serde_json::json!({"error": "unknown command"}),
        };
        writeln!(stdout, "{}", reply).expect("stdout write");
        stdout.flush().expect("stdout flush");
    }
}
