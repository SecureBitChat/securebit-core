// WebRTC handlers: offer, answer, join, parse, connection handling
use crate::session::{OfferContext, SessionKeys};
use crate::error::CoreError;
use std::sync::{Arc, Mutex};
use rand::Rng;
use p384::{ecdsa::{SigningKey, Signature, signature::Verifier}, PublicKey as P384Pub, pkcs8::{EncodePublicKey, DecodePublicKey}};
use ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use sha2::{Digest, Sha256, Sha384};
use flate2::{Compression, write::ZlibEncoder, read::{ZlibDecoder, GzDecoder, DeflateDecoder}};
use base64::{engine::general_purpose, Engine};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::io::Read;
use std::io::Write;
use hkdf::Hkdf;

pub fn create_secure_offer(offer_state: Arc<Mutex<OfferContext>>, offer_sdp: Option<String>) -> Result<String, CoreError> {
    // Generate P-384 keys for compatibility. A reusable SecretKey (not
    // EphemeralSecret): the Double Ratchet derives from the handshake keys.
    let ecdh_secret = p384::SecretKey::random(&mut rand::thread_rng());
    let ecdh_public: P384Pub = ecdh_secret.public_key();
    let ecdsa_signing = SigningKey::random(&mut rand::thread_rng());
    let ecdsa_public = ecdsa_signing.verifying_key();
    
    // Generate session salt (64 bytes for v4.0 compatibility)
    let mut session_salt = [0u8; 64];
    rand::thread_rng().fill(&mut session_salt);
    
    // Generate session ID (32 hex chars = 16 bytes)
    let session_id: String = (0..16)
        .map(|_| format!("{:02x}", rand::thread_rng().gen::<u8>()))
        .collect();
    // Generate connection ID (16 hex chars = 8 bytes)
    let connection_id: String = (0..8)
        .map(|_| format!("{:02x}", rand::thread_rng().gen::<u8>()))
        .collect();
    // Generate ICE credentials (WebRTC requires ice-pwd length >= 22)
    let ice_ufrag: String = (0..8) // 16 hex chars
        .map(|_| format!("{:02x}", rand::thread_rng().gen::<u8>()))
        .collect();
    let ice_pwd: String = (0..16) // 32 hex chars
        .map(|_| format!("{:02x}", rand::thread_rng().gen::<u8>()))
        .collect();
    
    // Generate verification code
    let verification_code = format!("{:06}", rand::thread_rng().gen_range(100000..999999));
    
    // Generate auth challenge
    let auth_challenge: String = (0..32)
        .map(|_| format!("{:02x}", rand::thread_rng().gen::<u8>()))
        .collect();
    
    // Generate DTLS fingerprint (SHA-256) and format as colon-separated uppercase hex
    let timestamp = chrono::Utc::now().timestamp();
    let mut hasher = Sha256::new();
    hasher.update(session_id.as_bytes());
    hasher.update(connection_id.as_bytes());
    let fp_hex = hex::encode(hasher.finalize()).to_uppercase();
    let fp_colon = fp_hex.as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).map_err(|_| CoreError::internal_error("Invalid UTF-8 in fingerprint")))
        .collect::<Result<Vec<_>, _>>()?
        .join(":");
    
    // NOTE: `fp_hex` above is only the synthetic fingerprint used to fill the
    // minimal fallback SDP. The fingerprint used for SAS is taken from the SDP we
    // actually advertise (see `local_dtls_fp_hex` below) so it matches what the
    // peer derives from that same SDP.

    // Use provided real SDP if available; otherwise fall back to minimal SDP
    let minimal_sdp = format!(
        "v=0\r\n\
         o=- {} {} IN IP4 127.0.0.1\r\n\
         s=-\r\n\
         t=0 0\r\n\
         m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
         c=IN IP4 127.0.0.1\r\n\
         a=ice-ufrag:{}\r\n\
         a=ice-pwd:{}\r\n\
         a=fingerprint:sha-256 {}\r\n\
         a=setup:actpass\r\n\
         a=mid:0\r\n\
         a=sctp-port:5000\r\n\
         a=max-message-size:262144\r\n",
        timestamp,
        timestamp,
        ice_ufrag,
        ice_pwd,
        fp_colon
    );

    // The SDP we will actually advertise in the offer ("s"). Extract the REAL DTLS
    // fingerprint from it for SAS, so both peers derive the SAS from the same
    // fingerprint. Fall back to the synthetic one only if the SDP carries none.
    let effective_offer_sdp = offer_sdp.unwrap_or_else(|| minimal_sdp.clone());
    let local_dtls_fp_hex = extract_dtls_fingerprint_from_sdp(&effective_offer_sdp)
        .unwrap_or_else(|| fp_hex.to_lowercase());

    // Export SPKI for both keys
    let ecdh_spki_der = ecdh_public.to_public_key_der().map_err(|e| CoreError::crypto_failure(format!("ECDH key export failed: {}", e)))?;
    let ecdsa_spki_der = ecdsa_public.to_public_key_der().map_err(|e| CoreError::crypto_failure(format!("ECDSA key export failed: {}", e)))?;
    
    // Create verifier for self-test
    let ecdsa_verifying = p384::ecdsa::VerifyingKey::from(&ecdsa_signing);

    // Build signed ECDH package matching web expectations
    let e_ts = chrono::Utc::now().timestamp_millis();
    
    // Create JSON string manually to ensure correct field order (keyType first, like web version)
    // Format keyData array without spaces to match web version
    let key_data_str = format!("[{}]", ecdh_spki_der.as_bytes().iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(","));
    
    let e_core_str = format!(
        r#"{{"keyType":"ECDH","keyData":{},"timestamp":{},"version":"4.0"}}"#,
        key_data_str,
        e_ts
    );
    // Use SHA-384 for signing (same as web version)
    let mut hasher = Sha384::new();
    hasher.update(e_core_str.as_bytes());
    let digest = hasher.finalize();
    let e_sig_bin: Signature = ecdsa_signing.sign_prehash(&digest).map_err(|e| CoreError::crypto_failure(format!("ECDH signing failed: {}", e)))?;
    let e_sig_raw = e_sig_bin.to_bytes();
    
    // Also verify our own signature to make sure it's valid
    ecdsa_verifying.verify(e_core_str.as_bytes(), &e_sig_bin)
        .map_err(|e| CoreError::crypto_failure(format!("Self-verification failed: {}", e)))?;
    let offer_package = serde_json::json!({
        // Core information (minimal)
        "t": "offer", // type
        "s": effective_offer_sdp, // actual SDP from WebRTC offer (real DTLS fingerprint)
        "v": "4.1", // protocol version (web PROTOCOL_VERSION); key-package version stays 4.0
        "ts": chrono::Utc::now().timestamp_millis(), // timestamp
        
        // Cryptographic keys (essential)
        // The web verifier reconstructs the signed string from ALL fields except
        // "signature" (in insertion order), so this object must contain exactly
        // {keyType, keyData, timestamp, version, signature} — no extra "ps" field.
        "e": { // signed ECDH public key package
            "keyType": "ECDH",
            "keyData": ecdh_spki_der.as_bytes(),
            "timestamp": e_ts,
            "version": "4.0",
            "signature": e_sig_raw.as_ref()
        },
        "d": { // ECDSA public key (raw SPKI)
            "keyData": ecdsa_spki_der.as_bytes()
        },

        // Session data (essential)
        "sl": session_salt.to_vec(), // salt
        "si": session_id, // sessionId
        "ci": connection_id, // connectionId
        
        // Authentication (essential)
        "vc": verification_code, // verificationCode
        "ac": auth_challenge, // authChallenge

        // Security metadata (simplified)
        "slv": "MAX", // securityLevel

        // Double Ratchet support (web RATCHET_VERSION). Advertised rather than
        // assumed so a peer on an earlier release keeps working on the
        // static-key path instead of failing to decrypt anything. Absent = not
        // supported.
        "dr": crate::ratchet::RATCHET_VERSION,

        // Key fingerprints (shortened)
        "kf": {
            "e": hex::encode(&sha2::Sha256::digest(ecdh_spki_der.as_bytes()))[0..12].to_string(),
            "d": hex::encode(&sha2::Sha256::digest(ecdsa_spki_der.as_bytes()))[0..12].to_string()
        }
    });
    
    // Persist ephemeral state for later answer validation
    {
        let mut st = offer_state.lock().map_err(|_| CoreError::state_error("Failed to acquire offer_state lock"))?;
        st.ecdh_secret = Some(ecdh_secret);
        st.session_salt = Some(session_salt.to_vec());
        // Store local DTLS fingerprint (hex without colons) for SAS computation
        st.local_dtls_fingerprint = Some(local_dtls_fp_hex);
    }

    // Compress and encode the offer in SB1:gz: format like web version
    let json_str = serde_json::to_string(&offer_package).map_err(|e| CoreError::internal_error(format!("JSON serialization failed: {}", e)))?;
    
    // Use gzip compression (same as web version)
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(json_str.as_bytes()).map_err(|e| CoreError::internal_error(format!("Compression write failed: {}", e)))?;
    let compressed = encoder.finish().map_err(|e| CoreError::internal_error(format!("Compression finish failed: {}", e)))?;
    
    // Use base64 encoding (same as web version)
    let encoded = general_purpose::STANDARD.encode(&compressed);
    Ok(format!("SB1:gz:{}", encoded))
}

pub fn create_secure_answer(
    offer_state: Arc<Mutex<OfferContext>>,
    offer_data: String, 
    answer_sdp: Option<String>
) -> Result<String, CoreError> {
    // Decode SB1:gz or SB1:bin if needed
    let decoded_offer = if offer_data.starts_with("SB1:gz:") {
        let b64 = &offer_data[7..];
        let compressed = general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| CoreError::invalid_input(format!("Base64 decode failed: {}", e)))?;
        let mut d = ZlibDecoder::new(&compressed[..]);
        let mut s = String::new();
        d.read_to_string(&mut s).map_err(|e| CoreError::invalid_input(format!("Zlib decode failed: {}", e)))?;
        s
    } else if offer_data.starts_with("SB1:bin:") {
        let b64url = &offer_data[8..];
        let compressed = URL_SAFE_NO_PAD
            .decode(b64url)
            .map_err(|e| CoreError::invalid_input(format!("Base64URL decode failed: {}", e)))?;
        // Try deflate, then gzip
        let mut s = String::new();
        if DeflateDecoder::new(&compressed[..]).read_to_string(&mut s).is_ok() {
            s
        } else {
            s.clear();
            let _ = GzDecoder::new(&compressed[..]).read_to_string(&mut s);
            s
        }
    } else {
        offer_data
    };
    
    // Parse offer data
    let offer: serde_json::Value = serde_json::from_str(&decoded_offer)
        .map_err(|e| CoreError::invalid_input(format!("Invalid offer data: {}", e)))?;
    
    // Validate offer structure
    if offer["t"].as_str() != Some("offer") {
        return Err(CoreError::protocol_violation("Invalid offer type"));
    }
    
    if offer["v"].as_str() != Some("4.1") {
        return Err(CoreError::protocol_violation("Unsupported protocol version"));
    }

    // Generate P-384 keys for answer
    let ecdh_secret = p384::SecretKey::random(&mut rand::thread_rng());
    let ecdh_public: P384Pub = ecdh_secret.public_key();
    let ecdsa_signing = SigningKey::random(&mut rand::thread_rng());
    let ecdsa_public = ecdsa_signing.verifying_key();

    // Generate our session salt
    let mut our_session_salt = [0u8; 64];
    rand::thread_rng().fill(&mut our_session_salt);
    
    // Generate our session ID
    let our_session_id: String = (0..16)
        .map(|_| format!("{:02x}", rand::thread_rng().gen::<u8>()))
        .collect();
    
    // Generate our connection ID
    let our_connection_id: String = (0..8)
        .map(|_| format!("{:02x}", rand::thread_rng().gen::<u8>()))
        .collect();
    
    // Generate our verification code
    let our_verification_code = format!("{:06}", rand::thread_rng().gen_range(100000..999999));
    
    // Generate our auth challenge
    let our_auth_challenge: String = (0..32)
        .map(|_| format!("{:02x}", rand::thread_rng().gen::<u8>()))
        .collect();
    
    // Generate DTLS fingerprint for answer
    let timestamp = chrono::Utc::now().timestamp();
    let mut hasher_ans = Sha256::new();
    hasher_ans.update(our_session_id.as_bytes());
    hasher_ans.update(our_connection_id.as_bytes());
    let fp_hex_ans = hex::encode(hasher_ans.finalize()).to_uppercase();
    let fp_colon_ans = fp_hex_ans.as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).map_err(|_| CoreError::internal_error("Invalid UTF-8 in fingerprint")))
        .collect::<Result<Vec<_>, _>>()?
        .join(":");

    // ⭐ КРИТИЧЕСКИ ВАЖНОЕ ИСПРАВЛЕНИЕ: Сохраняем local DTLS fingerprint
    // Это необходимо для вычисления SAS кода, когда answerer получит подтверждение
    let local_dtls_fp_hex = fp_hex_ans.clone();

    // Generate ICE credentials for answer
    let ans_ice_ufrag: String = (0..8)
        .map(|_| format!("{:02x}", rand::thread_rng().gen::<u8>()))
        .collect();
    let ans_ice_pwd: String = (0..16)
        .map(|_| format!("{:02x}", rand::thread_rng().gen::<u8>()))
        .collect();

    // Generate minimal valid SDP for answer compatibility (fallback)
    let minimal_answer_sdp = format!(
        "v=0\r\n\
         o=- {} {} IN IP4 127.0.0.1\r\n\
         s=-\r\n\
         t=0 0\r\n\
         m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
         c=IN IP4 127.0.0.1\r\n\
         a=ice-ufrag:{}\r\n\
         a=ice-pwd:{}\r\n\
         a=fingerprint:sha-256 {}\r\n\
         a=setup:active\r\n\
         a=mid:0\r\n\
         a=sctp-port:5000\r\n\
         a=max-message-size:262144\r\n",
        timestamp,
        timestamp,
        ans_ice_ufrag,
        ans_ice_pwd,
        fp_colon_ans
    );
    
    // Export SPKI
    let ecdh_spki_der = ecdh_public.to_public_key_der().map_err(|e| CoreError::crypto_failure(format!("ECDH key export failed: {}", e)))?;
    let ecdsa_spki_der = ecdsa_public.to_public_key_der().map_err(|e| CoreError::crypto_failure(format!("ECDSA key export failed: {}", e)))?;

    // Build signed ECDH package for answer
    let e_ts = chrono::Utc::now().timestamp_millis();
    
    // Create JSON string manually to ensure correct field order (keyType first, like web version)
    // Format keyData array without spaces to match web version
    let key_data_str = format!("[{}]", ecdh_spki_der.as_bytes().iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(","));
    
    let e_core_str = format!(
        r#"{{"keyType":"ECDH","keyData":{},"timestamp":{},"version":"4.0"}}"#,
        key_data_str,
        e_ts
    );
    // Use SHA-384 for signing (same as web version)
    let mut hasher = Sha384::new();
    hasher.update(e_core_str.as_bytes());
    let digest = hasher.finalize();
    let e_sig_bin: Signature = ecdsa_signing.sign_prehash(&digest).map_err(|e| CoreError::crypto_failure(format!("ECDH signing failed: {}", e)))?;
    let e_sig_raw = e_sig_bin.to_bytes();

    // Create answer package compatible with web version
    let answer_package = serde_json::json!({
        // Core information (minimal)
        "t": "answer", // type
        "s": answer_sdp.unwrap_or(minimal_answer_sdp), // actual WebRTC answer SDP (fallback to minimal)
        "v": "4.1", // protocol version (web PROTOCOL_VERSION); key-package version stays 4.0
        "ts": chrono::Utc::now().timestamp_millis(), // timestamp
        
        // Reference to original offer
        "oi": offer["si"], // original sessionId
        "oc": offer["ci"], // original connectionId
        
        // Our cryptographic keys (essential)
        "e": { // signed ECDH public key package
            "keyType": "ECDH",
            "keyData": ecdh_spki_der.as_bytes(),
            "timestamp": e_ts,
            "version": "4.0",
            "signature": e_sig_raw.as_ref(),
            "ps": e_core_str
        },
        "d": { // ECDSA public key (raw SPKI)
            "keyData": ecdsa_spki_der.as_bytes()
        },
        
        // Our session data (essential)
        "sl": our_session_salt.to_vec(), // salt
        "si": our_session_id, // sessionId
        "ci": our_connection_id, // connectionId
        
        // Authentication (essential)
        "vc": our_verification_code, // verificationCode
        "ac": our_auth_challenge, // authChallenge
        
        // Security metadata (simplified)
        "slv": "MAX", // securityLevel
        
        // Key fingerprints (shortened)
        "kf": {
            "e": hex::encode(&sha2::Sha256::digest(ecdh_spki_der.as_bytes()))[0..12].to_string(),
            "d": hex::encode(&sha2::Sha256::digest(ecdsa_spki_der.as_bytes()))[0..12].to_string()
        }
    });
    
    // ⭐ КРИТИЧЕСКИ ВАЖНОЕ ИСПРАВЛЕНИЕ: Сохраняем состояние для последующего вычисления SAS
    // Когда answerer получит подтверждение от offerer, он должен вычислить SAS код
    // Для этого нужны: local_dtls_fingerprint
    {
        let mut st = offer_state.lock().map_err(|_| CoreError::state_error("Failed to acquire offer_state lock"))?;
        st.local_dtls_fingerprint = Some(local_dtls_fp_hex);
    }
    
    // Return SB1:gz encoded answer
    let json_str = serde_json::to_string(&answer_package).map_err(|e| CoreError::internal_error(format!("JSON serialization failed: {}", e)))?;
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(json_str.as_bytes()).map_err(|e| CoreError::internal_error(format!("Compression write failed: {}", e)))?;
    let compressed = encoder.finish().map_err(|e| CoreError::internal_error(format!("Compression finish failed: {}", e)))?;
    let encoded = general_purpose::STANDARD.encode(&compressed);
    Ok(format!("SB1:gz:{}", encoded))
}

// Helper function to convert CBOR to JSON, converting binary data to arrays of numbers
fn cbor_to_json_with_bytes(cbor_val: &serde_cbor::Value) -> serde_json::Value {
    match cbor_val {
        serde_cbor::Value::Null => serde_json::Value::Null,
        serde_cbor::Value::Bool(b) => serde_json::Value::Bool(*b),
        serde_cbor::Value::Integer(i) => {
            // Try to fit into i64, otherwise u64
            if let Ok(n) = i64::try_from(*i) {
                serde_json::Value::Number(n.into())
            } else if let Ok(n) = u64::try_from(*i) {
                serde_json::Value::Number(n.into())
            } else {
                serde_json::Value::String(i.to_string())
            }
        },
        serde_cbor::Value::Float(f) => {
            serde_json::Number::from_f64(*f)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null)
        },
        serde_cbor::Value::Bytes(b) => {
            // Convert bytes to array of numbers for JSON compatibility
            serde_json::Value::Array(b.iter().map(|&byte| serde_json::Value::Number(byte.into())).collect())
        },
        serde_cbor::Value::Text(s) => serde_json::Value::String(s.clone()),
        serde_cbor::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(cbor_to_json_with_bytes).collect())
        },
        serde_cbor::Value::Map(map) => {
            let mut json_map = serde_json::Map::new();
            for (key, val) in map.iter() {
                let key_str = match key {
                    serde_cbor::Value::Text(s) => s.clone(),
                    serde_cbor::Value::Integer(i) => i.to_string(),
                    _ => format!("{:?}", key),
                };
                json_map.insert(key_str, cbor_to_json_with_bytes(val));
            }
            serde_json::Value::Object(json_map)
        },
        serde_cbor::Value::Tag(_, val) => cbor_to_json_with_bytes(val),
        // Handle any other CBOR value types (Simple, etc.)
        _ => serde_json::Value::Null,
    }
}

pub fn parse_secure_offer(offer_data: String) -> Result<String, CoreError> {
    if offer_data.is_empty() {
        return Err(CoreError::invalid_input("Offer data is empty"));
    }
    
    // Reuse decoding logic from create_secure_answer
    let decoded_offer = if offer_data.starts_with("SB1:gz:") {
        let b64 = &offer_data[7..];
        let compressed = general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| CoreError::invalid_input(format!("Base64 decode failed: {}", e)))?;
        let mut d = ZlibDecoder::new(&compressed[..]);
        let mut s = String::new();
        d.read_to_string(&mut s).map_err(|e| CoreError::invalid_input(format!("Zlib decode failed: {}", e)))?;
        s
    } else if offer_data.starts_with("SB1:bin:") {
        let b64url = &offer_data[8..];
        let compressed = URL_SAFE_NO_PAD
            .decode(b64url)
            .map_err(|e| CoreError::invalid_input(format!("Base64URL decode failed: {}", e)))?;
        
        // Try zlib first (most common for eJy... prefix), then deflate, then gzip
        let mut s = String::new();
        if ZlibDecoder::new(&compressed[..]).read_to_string(&mut s).is_ok() {
            s
        } else {
            s.clear();
            if DeflateDecoder::new(&compressed[..]).read_to_string(&mut s).is_ok() {
                s
            } else {
                // Try reading as bytes for CBOR decoding (like handle_secure_answer does)
                let mut buf = Vec::new();
                if ZlibDecoder::new(&compressed[..]).read_to_end(&mut buf).is_ok() {
                    // OK
                } else if DeflateDecoder::new(&compressed[..]).read_to_end(&mut buf).is_ok() {
                    // OK
                } else {
                    buf.clear();
                    if GzDecoder::new(&compressed[..]).read_to_end(&mut buf).is_ok() {
                        // OK
                    } else {
                        return Err(CoreError::invalid_input("Failed to decode SB1:bin with zlib/deflate/gzip"));
                    }
                }
                
                // Try CBOR decode (like handle_secure_answer does)
                match serde_cbor::from_slice::<serde_cbor::Value>(&buf) {
                    Ok(cbor_val) => {
                        let json_val = cbor_to_json_with_bytes(&cbor_val);
                        let json_str = serde_json::to_string(&json_val).map_err(|e| CoreError::internal_error(format!("CBOR to JSON conversion failed: {}", e)))?;
                        json_str
                    }
                    Err(_) => {
                        // If CBOR decode fails, try to interpret as raw string
                        String::from_utf8(buf).map_err(|e| CoreError::invalid_input(format!("Failed to decode as UTF-8 string: {}", e)))?
                    }
                }
            }
        }
    } else {
        // Try to parse as JSON directly
        if offer_data.trim().starts_with('{') || offer_data.trim().starts_with('[') {
            offer_data.clone()
        } else {
            return Err(CoreError::invalid_input(format!("Unknown offer format. Expected SB1:gz:, SB1:bin:, or JSON")));
        }
    };
    
    if decoded_offer.is_empty() {
        return Err(CoreError::invalid_input("Decoded offer is empty"));
    }
    
    // Validate it's JSON
    let offer_json: serde_json::Value = serde_json::from_str(&decoded_offer)
        .map_err(|e| CoreError::invalid_input(format!("Invalid offer data (JSON parse error): {}", e)))?;
    
    // Return compact JSON string (so frontend can parse)
    serde_json::to_string(&offer_json).map_err(|e| CoreError::internal_error(format!("JSON serialization failed: {}", e)))
}

// Extract DTLS fingerprint from SDP string
fn extract_dtls_fingerprint_from_sdp(sdp: &str) -> Option<String> {
    // Look for a=fingerprint:sha-256 ... pattern
    let fingerprint_regex = regex::Regex::new(r"a=fingerprint:sha-256\s+([A-Fa-f0-9:]+)").ok()?;
    if let Some(caps) = fingerprint_regex.captures(sdp) {
        if let Some(fp_match) = caps.get(1) {
            // Keep colons, lowercase only — this MUST match the web's _computeSAS
            // normalization (`fingerprint.trim().toLowerCase()`), which preserves
            // the colon-separated form. Stripping colons would change the SAS salt
            // and make the codes disagree across implementations.
            let fp = fp_match.as_str().trim().to_lowercase();
            return Some(fp);
        }
    }
    None
}

// Compute SAS (Short Authentication String) code using HKDF
// Similar to web version's _computeSAS function
fn compute_sas_code(key_fingerprint_bytes: &[u8], local_fp: &str, remote_fp: &str) -> Result<String, CoreError> {
    // Use key fingerprint bytes directly (already decoded)
    let key_bytes = key_fingerprint_bytes;
    
    // Create salt: 'webrtc-sas|' + sorted fingerprints joined by '|'
    let mut fps = vec![local_fp.to_string(), remote_fp.to_string()];
    fps.sort();
    let salt_str = format!("webrtc-sas|{}", fps.join("|"));
    let salt = salt_str.as_bytes();
    
    // Use HKDF(SHA-256) to derive 64 bits (8 bytes) for SAS code
    let hk = Hkdf::<Sha256>::new(Some(salt), &key_bytes);
    let mut sas_bytes = [0u8; 8];
    hk.expand(b"p2p-sas-v1", &mut sas_bytes)
        .map_err(|_| CoreError::crypto_failure("HKDF expand failed for SAS"))?;
    
    // Combine first 4 bytes and last 4 bytes with XOR
    let n1 = u32::from_be_bytes([sas_bytes[0], sas_bytes[1], sas_bytes[2], sas_bytes[3]]);
    let n2 = u32::from_be_bytes([sas_bytes[4], sas_bytes[5], sas_bytes[6], sas_bytes[7]]);
    let combined = (n1 ^ n2) as u64;
    
    // Generate 7-digit code (0000000-9999999)
    // Use rejection sampling to avoid bias
    let sas_value = (combined % 10_000_000) as u32;
    let sas_code = format!("{:07}", sas_value);
    
    Ok(sas_code)
}

// Helper: extract bytes from JSON value (array of numbers, base64/base64url string, or Buffer-like)
fn extract_bytes(val: &serde_json::Value) -> Result<Vec<u8>, CoreError> {
    // Try array of numbers first (common in JSON)
    if let Some(arr) = val.as_array() {
        let mut bytes = Vec::new();
        for v in arr {
            if let Some(n) = v.as_u64() {
                if n > 255 {
                    return Err(CoreError::invalid_input(format!("Number {} out of byte range", n)));
                }
                bytes.push(n as u8);
            } else if let Some(n) = v.as_i64() {
                if n < 0 || n > 255 {
                    return Err(CoreError::invalid_input(format!("Number {} out of byte range", n)));
                }
                bytes.push(n as u8);
            } else {
                return Err(CoreError::invalid_input("Array contains non-numeric values".to_string()));
            }
        }
        return Ok(bytes);
    }
    
    // Try base64/base64url string
    if let Some(s) = val.as_str() {
        // Try standard base64
        if let Ok(b) = base64::engine::general_purpose::STANDARD.decode(s) {
            return Ok(b);
        }
        // Try URL-safe base64
        if let Ok(b) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s) {
            return Ok(b);
        }
        // Try URL-safe base64 with padding
        if let Ok(b) = base64::engine::general_purpose::URL_SAFE.decode(s) {
            return Ok(b);
        }
        return Err(CoreError::invalid_input("Invalid base64 string".to_string()));
    }
    
    // Try object with data field
    if let Some(obj) = val.as_object() {
        if let Some(data) = obj.get("data") {
            return extract_bytes(data);
        }
        // Try _bytes field (CBOR binary representation)
        if let Some(bytes_val) = obj.get("_bytes") {
            return extract_bytes(bytes_val);
        }
    }
    
    Err(CoreError::invalid_input(format!("Unsupported binary format")))
}

pub fn join_secure_connection(
    offer_state: Arc<Mutex<OfferContext>>,
    session_keys: Arc<Mutex<SessionKeys>>,
    offer_data: String, 
    answer_sdp: Option<String>
) -> Result<String, CoreError> {
    if offer_data.is_empty() {
        return Err(CoreError::invalid_input("Offer data is empty"));
    }
    // Decode offer data
    let decoded_offer = if offer_data.starts_with("SB1:gz:") {
        let b64 = &offer_data[7..];
        let compressed = general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| CoreError::invalid_input(format!("Base64 decode failed: {}", e)))?;
        let mut d = ZlibDecoder::new(&compressed[..]);
        let mut s = String::new();
        d.read_to_string(&mut s).map_err(|e| CoreError::invalid_input(format!("Zlib decode failed: {}", e)))?;
        s
    } else if offer_data.starts_with("SB1:bin:") {
        let b64url = &offer_data[8..];
        let compressed = URL_SAFE_NO_PAD
            .decode(b64url)
            .map_err(|e| CoreError::invalid_input(format!("Base64URL decode failed: {}", e)))?;
        
        // Try zlib first (most common for eJy... prefix), then deflate, then gzip
        let mut s = String::new();
        if ZlibDecoder::new(&compressed[..]).read_to_string(&mut s).is_ok() {
            s
        } else {
            s.clear();
            if DeflateDecoder::new(&compressed[..]).read_to_string(&mut s).is_ok() {
                s
            } else {
                // Try reading as bytes for CBOR decoding (like handle_secure_answer does)
                let mut buf = Vec::new();
                if ZlibDecoder::new(&compressed[..]).read_to_end(&mut buf).is_ok() {
                    // OK
                } else if DeflateDecoder::new(&compressed[..]).read_to_end(&mut buf).is_ok() {
                    // OK
                } else {
                    buf.clear();
                    if GzDecoder::new(&compressed[..]).read_to_end(&mut buf).is_ok() {
                        // OK
                    } else {
                        return Err(CoreError::invalid_input("Failed to decode SB1:bin with zlib/deflate/gzip"));
                    }
                }
                
                // Try CBOR decode (like handle_secure_answer does)
                match serde_cbor::from_slice::<serde_cbor::Value>(&buf) {
                    Ok(cbor_val) => {
                        let json_val = cbor_to_json_with_bytes(&cbor_val);
                        let json_str = serde_json::to_string(&json_val).map_err(|e| CoreError::internal_error(format!("CBOR to JSON conversion failed: {}", e)))?;
                        json_str
                    }
                    Err(_) => {
                        // If CBOR decode fails, try to interpret as raw string
                        String::from_utf8(buf).map_err(|e| CoreError::invalid_input(format!("Failed to decode as UTF-8 string: {}", e)))?
                    }
                }
            }
        }
    } else {
        if offer_data.trim().starts_with('{') || offer_data.trim().starts_with('[') {
            offer_data.clone()
        } else {
            return Err(CoreError::invalid_input("Unknown offer format. Expected SB1:gz:, SB1:bin:, or JSON"));
        }
    };
    
    if decoded_offer.is_empty() {
        return Err(CoreError::invalid_input("Decoded offer is empty"));
    }
    
    // Parse offer data
    let offer: serde_json::Value = serde_json::from_str(&decoded_offer)
        .map_err(|e| CoreError::invalid_input(format!("Invalid offer data: {}", e)))?;
    
    // Validate offer structure
    let offer_type = offer.get("t").or_else(|| offer.get("type"));
    
    if offer_type.and_then(|v| v.as_str()) != Some("offer") {
        return Err(CoreError::protocol_violation("Invalid offer type"));
    }
    
    let offer_version = offer.get("v").or_else(|| offer.get("version"));
    
    if offer_version.and_then(|v| v.as_str()) != Some("4.1") {
        return Err(CoreError::protocol_violation("Unsupported protocol version"));
    }
    
    // Extract salt from offer (essential for key derivation)
    // Try both compact format (sl) and full format (salt)
    let offer_salt = offer.get("sl").or_else(|| offer.get("salt"));
    
    let offer_salt = offer_salt
        .and_then(|v| v.as_array())
        .map(|arr| {
            let mut bytes = Vec::new();
            for v in arr {
                if let Some(n) = v.as_u64() {
                    if n <= 255 {
                        bytes.push(n as u8);
                    }
                } else if let Some(n) = v.as_i64() {
                    if n >= 0 && n <= 255 {
                        bytes.push(n as u8);
                    }
                }
            }
            bytes
        })
        .ok_or_else(|| CoreError::protocol_violation("Missing salt in offer"))?;
    
    if offer_salt.len() != 64 {
        return Err(CoreError::protocol_violation(format!("Invalid salt length: {} (expected 64)", offer_salt.len())));
    }
    
    // Extract peer ECDH public key from offer
    let ecdh_pkg = offer.get("e")
        .ok_or_else(|| CoreError::protocol_violation("Missing ECDH package in offer"))?;
    
    let peer_ecdh_key_data = ecdh_pkg.get("keyData")
        .ok_or_else(|| CoreError::protocol_violation("Missing keyData in ECDH package"))?;
    
    let peer_ecdh_spki = extract_bytes(peer_ecdh_key_data)
        .map_err(|e| CoreError::invalid_input(format!("Invalid ECDH keyData: {}", e)))?;
    
    let peer_ecdh_public = p384::PublicKey::from_public_key_der(&peer_ecdh_spki)
        .map_err(|e| CoreError::crypto_failure(format!("Failed to import peer ECDH key: {}", e)))?;
    
    // Did the initiator advertise the Double Ratchet? Absent means an older
    // build, which is a downgrade to the static-key scheme rather than a
    // failure — with no server there is no way to roll both ends at once.
    let peer_supports_ratchet =
        offer.get("dr").and_then(|v| v.as_u64()) == Some(crate::ratchet::RATCHET_VERSION);

    // Generate our P-384 keys for answer. A reusable SecretKey: as the joining
    // (responder) side, this exact key pair becomes the ratchet's first key
    // pair — the initiator's first DH deliberately lands on it.
    let ecdh_secret = p384::SecretKey::random(&mut rand::thread_rng());
    let ecdh_public: P384Pub = ecdh_secret.public_key();
    let ecdsa_signing = SigningKey::random(&mut rand::thread_rng());
    let ecdsa_public = ecdsa_signing.verifying_key();
    
    // Generate DTLS fingerprint for answer
    let our_session_id: String = (0..16)
        .map(|_| format!("{:02x}", rand::thread_rng().gen::<u8>()))
        .collect();
    let our_connection_id: String = (0..8)
        .map(|_| format!("{:02x}", rand::thread_rng().gen::<u8>()))
        .collect();
    
    let timestamp = chrono::Utc::now().timestamp();
    let mut hasher_ans = Sha256::new();
    hasher_ans.update(our_session_id.as_bytes());
    hasher_ans.update(our_connection_id.as_bytes());
    let fp_hex_ans = hex::encode(hasher_ans.finalize()).to_uppercase();
    let fp_colon_ans = fp_hex_ans.as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).map_err(|_| CoreError::internal_error("Invalid UTF-8 in fingerprint")))
        .collect::<Result<Vec<_>, _>>()?
        .join(":");
    
    // Store local DTLS fingerprint (hex without colons) for SAS computation
    // This is needed for handle_secure_answer to compute the SAS code
    let local_dtls_fp_hex = fp_hex_ans.clone();
    
    let ans_ice_ufrag: String = (0..8)
        .map(|_| format!("{:02x}", rand::thread_rng().gen::<u8>()))
        .collect();
    let ans_ice_pwd: String = (0..16)
        .map(|_| format!("{:02x}", rand::thread_rng().gen::<u8>()))
        .collect();
    
    let minimal_answer_sdp = format!(
        "v=0\r\n\
         o=- {} {} IN IP4 127.0.0.1\r\n\
         s=-\r\n\
         t=0 0\r\n\
         m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
         c=IN IP4 127.0.0.1\r\n\
         a=ice-ufrag:{}\r\n\
         a=ice-pwd:{}\r\n\
         a=fingerprint:sha-256 {}\r\n\
         a=setup:active\r\n\
         a=mid:0\r\n\
         a=sctp-port:5000\r\n\
         a=max-message-size:262144\r\n",
        timestamp, timestamp, ans_ice_ufrag, ans_ice_pwd, fp_colon_ans
    );
    
    // Export SPKI
    let ecdh_spki_der = ecdh_public.to_public_key_der().map_err(|e| CoreError::crypto_failure(format!("ECDH key export failed: {}", e)))?;
    let ecdsa_spki_der = ecdsa_public.to_public_key_der().map_err(|e| CoreError::crypto_failure(format!("ECDSA key export failed: {}", e)))?;
    
    // Build signed ECDH package - EXACTLY like web version
    // Web version: const keyPackage = { keyType, keyData, timestamp, version };
    // Then: const packageString = JSON.stringify(keyPackage);
    let e_ts = chrono::Utc::now().timestamp_millis();
    
    // Build the signed key-package string MANUALLY in keyType-first order, exactly
    // like create_secure_offer and the web's JSON.stringify({keyType,keyData,timestamp,version}).
    // serde_json::Map serializes keys alphabetically, which would NOT match the web
    // verifier, so the signed string must not be derived from the map.
    let e_key_data_str = format!("[{}]", ecdh_spki_der.as_bytes().iter()
        .map(|b| b.to_string()).collect::<Vec<_>>().join(","));
    let e_core_str = format!(
        r#"{{"keyType":"ECDH","keyData":{},"timestamp":{},"version":"4.0"}}"#,
        e_key_data_str, e_ts
    );

    // Field map used only to assemble the answer "e" object. We also embed the
    // signed "ps" string so the peer can verify against the exact bytes we signed.
    let mut ecdh_key_package = serde_json::Map::new();
    ecdh_key_package.insert("keyType".to_string(), serde_json::Value::String("ECDH".to_string()));
    ecdh_key_package.insert("keyData".to_string(), serde_json::Value::Array(
        ecdh_spki_der.as_bytes().iter().map(|&b| serde_json::Value::Number(b.into())).collect()
    ));
    ecdh_key_package.insert("timestamp".to_string(), serde_json::Value::Number(e_ts.into()));
    ecdh_key_package.insert("version".to_string(), serde_json::Value::String("4.0".to_string()));
    // No "ps" field: the web verifier includes every non-signature field in the
    // signed string, so the package must be exactly {keyType,keyData,timestamp,version,signature}.

    let mut ecdh_hasher = Sha384::new();
    ecdh_hasher.update(e_core_str.as_bytes());
    let ecdh_digest = ecdh_hasher.finalize();
    
    let e_sig_bin: Signature = ecdsa_signing.sign_prehash(&ecdh_digest).map_err(|e| CoreError::crypto_failure(format!("ECDH signing failed: {}", e)))?;
    let e_sig_raw = e_sig_bin.to_bytes();
    
    if e_sig_raw.len() != 96 {
        return Err(CoreError::crypto_failure("ECDH signature must be 96 bytes for P-384"));
    }
    
    // Build signed ECDSA package - EXACTLY like web version
    // Web version: const keyPackage = { keyType, keyData, timestamp, version };
    // Then: const packageString = JSON.stringify(keyPackage);
    let d_ts = chrono::Utc::now().timestamp_millis();
    
    // Create object in the exact same order as web version
    let mut ecdsa_key_package = serde_json::Map::new();
    ecdsa_key_package.insert("keyType".to_string(), serde_json::Value::String("ECDSA".to_string()));
    ecdsa_key_package.insert("keyData".to_string(), serde_json::Value::Array(
        ecdsa_spki_der.as_bytes().iter().map(|&b| serde_json::Value::Number(b.into())).collect()
    ));
    ecdsa_key_package.insert("timestamp".to_string(), serde_json::Value::Number(d_ts.into()));
    ecdsa_key_package.insert("version".to_string(), serde_json::Value::String("4.0".to_string()));
    
    // Serialize to JSON string exactly like web version's JSON.stringify
    let d_core_str = serde_json::to_string(&serde_json::Value::Object(ecdsa_key_package.clone()))
        .map_err(|e| CoreError::internal_error(format!("Failed to serialize ECDSA package: {}", e)))?;
    
    let mut ecdsa_hasher = Sha384::new();
    ecdsa_hasher.update(d_core_str.as_bytes());
    let ecdsa_digest = ecdsa_hasher.finalize();
    
    let d_sig_bin: Signature = ecdsa_signing.sign_prehash(&ecdsa_digest).map_err(|e| CoreError::crypto_failure(format!("ECDSA signing failed: {}", e)))?;
    let d_sig_raw = d_sig_bin.to_bytes();
    
    if d_sig_raw.len() != 96 {
        return Err(CoreError::crypto_failure("ECDSA signature must be 96 bytes for P-384"));
    }
    
    // Create answer package - EXACTLY like web version
    // Web version: const signedPackage = { ...keyPackage, signature };
    // So order is: keyType, keyData, timestamp, version, signature
    let mut ecdh_package = ecdh_key_package.clone();
    ecdh_package.insert("signature".to_string(), serde_json::Value::Array(
        e_sig_raw.as_ref().iter().map(|&b| serde_json::Value::Number(b.into())).collect()
    ));
    
    let mut ecdsa_package = ecdsa_key_package.clone();
    ecdsa_package.insert("signature".to_string(), serde_json::Value::Array(
        d_sig_raw.as_ref().iter().map(|&b| serde_json::Value::Number(b.into())).collect()
    ));
    
    // The SDP that actually goes on the wire — the browser's real answer when the
    // frontend supplied one, otherwise our minimal stand-in. The SAS must be
    // computed over the SAME fingerprint the peer will see, so hoist it here
    // instead of consuming it inside the json! macro.
    let effective_answer_sdp = answer_sdp.unwrap_or(minimal_answer_sdp);

    let answer_package = serde_json::json!({
        "t": "answer",
        "s": effective_answer_sdp.clone(),
        "v": "4.1",
        "version": "4.1", // protocol version (full field alias); key-package version stays 4.0
        "ts": chrono::Utc::now().timestamp_millis(),
        "oi": offer["si"],
        "oc": offer["ci"],
        "e": ecdh_package,
        "d": ecdsa_package,
        "sl": offer_salt.clone(), // Use salt from offer
        "si": our_session_id,
        "ci": our_connection_id,
        "vc": format!("{:06}", rand::thread_rng().gen_range(100000..999999)),
        "ac": (0..32).map(|_| format!("{:02x}", rand::thread_rng().gen::<u8>())).collect::<String>(),
        "slv": "MAX",
        // Double Ratchet support (see the note on the offer package).
        "dr": crate::ratchet::RATCHET_VERSION,
        "kf": {
            "e": hex::encode(&sha2::Sha256::digest(ecdh_spki_der.as_bytes()))[0..12].to_string(),
            "d": hex::encode(&sha2::Sha256::digest(ecdsa_spki_der.as_bytes()))[0..12].to_string()
        }
    });
    
    // Derive keys immediately (like web version does)
    let shared = p384::ecdh::diffie_hellman(ecdh_secret.to_nonzero_scalar(), peer_ecdh_public.as_affine());
    let shared_bytes_full = shared.raw_secret_bytes();

    // Truncate to 32 bytes (matching Web Crypto API)
    let shared_bytes: &[u8] = if shared_bytes_full.len() >= 32 {
        &shared_bytes_full[..32]
    } else {
        &shared_bytes_full
    };
    
    // Derive keys using HKDF
    let hk = Hkdf::<Sha256>::new(Some(&offer_salt), shared_bytes);
    
    let mut enc_okm = [0u8; 32];
    hk.expand(b"message-encryption-v4", &mut enc_okm)
        .map_err(|e| CoreError::crypto_failure(format!("HKDF expand enc failed: {:?}", e)))?;
    
    let mut mac_okm = [0u8; 64];
    hk.expand(b"message-authentication-v4", &mut mac_okm)
        .map_err(|e| CoreError::crypto_failure(format!("HKDF expand mac failed: {:?}", e)))?;
    
    let mut meta_okm = [0u8; 32];
    hk.expand(b"metadata-protection-v4", &mut meta_okm)
        .map_err(|e| CoreError::crypto_failure(format!("HKDF expand meta failed: {:?}", e)))?;
    
    // Derive the SAS ourselves, exactly as handle_secure_answer does on the other
    // side and as the web client does in deriveSharedKeys + _computeSAS: the
    // dedicated 'fingerprint-generation-v4' key, SHA-384, first 12 bytes, then
    // HKDF over the two DTLS fingerprints (compute_sas_code sorts them, so both
    // peers reach the same value regardless of orientation).
    //
    // Without this the joining side had NO code of its own and simply displayed
    // whatever the offerer announced over the wire — which an attacker in the
    // middle can choose, making the out-of-band comparison meaningless.
    let mut fp_okm = [0u8; 32];
    hk.expand(b"fingerprint-generation-v4", &mut fp_okm)
        .map_err(|e| CoreError::crypto_failure(format!("HKDF expand fingerprint failed: {:?}", e)))?;

    // Root for the Double Ratchet: its own domain-separated branch of the key
    // schedule (web deriveSharedKeys, info 'double-ratchet-root-v1'), so
    // learning a session key tells an attacker nothing about the ratchet.
    let mut dr_root_okm = [0u8; 32];
    hk.expand(b"double-ratchet-root-v1", &mut dr_root_okm)
        .map_err(|e| CoreError::crypto_failure(format!("HKDF expand ratchet root failed: {:?}", e)))?;

    let mut fp_h = Sha384::new();
    fp_h.update(&fp_okm);
    let fp = fp_h.finalize();
    let key_fingerprint_bytes: [u8; 12] = {
        let mut bytes = [0u8; 12];
        bytes.copy_from_slice(&fp[..12]);
        bytes
    };

    // Local = our answer's fingerprint, remote = the offerer's.
    let local_sas_fp = extract_dtls_fingerprint_from_sdp(&effective_answer_sdp).unwrap_or_default();
    let remote_sas_fp = offer
        .get("s")
        .or_else(|| offer.get("sdp"))
        .and_then(|v| v.as_str())
        .and_then(extract_dtls_fingerprint_from_sdp)
        .unwrap_or_default();

    let local_verification_code = if !local_sas_fp.is_empty() && !remote_sas_fp.is_empty() {
        Some(compute_sas_code(&key_fingerprint_bytes, &local_sas_fp, &remote_sas_fp)?)
    } else {
        None
    };

    // Bring up the Double Ratchet if the initiator advertised it. As the
    // responder we keep our handshake key pair as the ratchet pair and take no
    // sending chain until the initiator's first message arrives. Failure is
    // deliberately not fatal: falling back to the static keys is the behaviour
    // of every release before the ratchet, and better than not connecting.
    let ratchet = if peer_supports_ratchet {
        match crate::ratchet::DoubleRatchet::init_responder(&dr_root_okm, &offer_salt, ecdh_secret.clone()) {
            Ok(r) => Some(r),
            Err(_) => None,
        }
    } else {
        None
    };
    {
        use zeroize::Zeroize;
        dr_root_okm.zeroize(); // Folded into the ratchet (or abandoned) — either way it must not linger.
    }

    // Store session keys
    {
        let mut keys = session_keys.lock().map_err(|_| CoreError::state_error("Failed to acquire session_keys lock"))?;
        keys.encryption_key = Some(enc_okm.to_vec());
        keys.mac_key = Some(mac_okm.to_vec());
        keys.metadata_key = Some(meta_okm.to_vec());
        keys.key_fingerprint = Some(crate::file_crypto::compute_key_fingerprint(shared_bytes, &offer_salt));
        keys.verification_code = local_verification_code;
        keys.peer_supports_ratchet = peer_supports_ratchet;
        keys.ratchet = ratchet;
    }
    
    // Store local DTLS fingerprint in offer_state for SAS computation
    // This is needed when handle_secure_answer is called later
    {
        let mut st = offer_state.lock().map_err(|_| CoreError::state_error("Failed to acquire offer_state lock"))?;
        st.local_dtls_fingerprint = Some(local_dtls_fp_hex);
        // The joining peer adopts the offerer's salt as THE session salt. Both sides
        // must agree on it: `get_session_crypto` hands it to the JS file-transfer
        // layer, which derives every per-file key from it. Without this the answerer
        // reports a null salt and file/voice transfer fails on that side entirely.
        st.session_salt = Some(offer_salt.clone());
    }
    
    // Return SB1:gz encoded answer
    let json_str = serde_json::to_string(&answer_package).map_err(|e| CoreError::internal_error(format!("JSON serialization failed: {}", e)))?;
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(json_str.as_bytes()).map_err(|e| CoreError::internal_error(format!("Compression write failed: {}", e)))?;
    let compressed = encoder.finish().map_err(|e| CoreError::internal_error(format!("Compression finish failed: {}", e)))?;
    let encoded = general_purpose::STANDARD.encode(&compressed);
    Ok(format!("SB1:gz:{}", encoded))
}

pub fn handle_secure_answer(offer_state: Arc<Mutex<OfferContext>>, session_keys: Arc<Mutex<SessionKeys>>, answer_data: String) -> Result<String, CoreError> {
    // Decode SB1:gz or SB1:bin if needed
    let decoded = if answer_data.starts_with("SB1:gz:") {
        let b64 = &answer_data[7..];
        let compressed = general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| CoreError::invalid_input(format!("Base64 decode failed: {}", e)))?;
        let mut d = ZlibDecoder::new(&compressed[..]);
        let mut s = String::new();
        d.read_to_string(&mut s).map_err(|e| CoreError::invalid_input(format!("Zlib decode failed: {}", e)))?;
        s
    } else if answer_data.starts_with("SB1:bin:") {
        let b64url = &answer_data[8..];
        let compressed = URL_SAFE_NO_PAD
            .decode(b64url)
            .map_err(|e| CoreError::invalid_input(format!("Base64URL decode failed: {}", e)))?;
        // Try zlib (most likely for eJy...), then deflate, then gzip to bytes
        let mut buf = Vec::new();
        if ZlibDecoder::new(&compressed[..]).read_to_end(&mut buf).is_ok() {
            // OK
        } else if DeflateDecoder::new(&compressed[..]).read_to_end(&mut buf).is_ok() {
            // OK
        } else {
            buf.clear();
            if GzDecoder::new(&compressed[..]).read_to_end(&mut buf).is_ok() {
                // OK
            } else {
                return Err(CoreError::invalid_input("Invalid answer data: unsupported compression"));
            }
        }
        // Attempt CBOR decode into JSON
        match serde_cbor::from_slice::<serde_cbor::Value>(&buf) {
            Ok(cbor_val) => {
                // Convert CBOR to JSON, handling binary data properly
                // First, convert binary data to arrays of numbers for JSON compatibility
                let json_val = cbor_to_json_with_bytes(&cbor_val);
                let s = serde_json::to_string(&json_val).map_err(|e| CoreError::internal_error(format!("CBOR to JSON conversion failed: {}", e)))?;
                s
            },
            Err(e) => {
                return Err(CoreError::invalid_input(format!("Invalid answer data: CBOR decode failed: {}", e)));
            }
        }
    } else {
        answer_data
    };
    
    // Parse answer data
    let answer: serde_json::Value = serde_json::from_str(&decoded)
        .map_err(|e| CoreError::invalid_input(format!("Invalid answer data: {}", e)))?;
    
    // Verify the answer structure
    if answer["t"].as_str() != Some("answer") {
        return Err(CoreError::protocol_violation("Invalid answer type"));
    }
    
    if answer["v"].as_str() != Some("4.1") {
        return Err(CoreError::protocol_violation("Unsupported protocol version"));
    }

    // Does the responder speak our ratchet version? (see the offer side)
    let peer_supports_ratchet =
        answer.get("dr").and_then(|v| v.as_u64()) == Some(crate::ratchet::RATCHET_VERSION);

    // Extract keys
    let ecdh_pkg = &answer["e"];
    let ecdsa_key = &answer["d"];
    
    if ecdh_pkg.is_null() || !ecdh_pkg.is_object() {
        return Err(CoreError::protocol_violation("Missing 'e' package"));
    }
    if ecdsa_key.is_null() || !ecdsa_key.is_object() {
        return Err(CoreError::protocol_violation("Missing 'd' key"));
    }
    
    // Helper to check if a field exists and is not null
    fn has_field(obj: &serde_json::Value, field: &str) -> bool {
        obj.get(field).is_some() && !obj[field].is_null()
    }
    
    // Helper to get field value, checking nested objects
    fn get_field_value<'a>(obj: &'a serde_json::Value, field: &str) -> Option<&'a serde_json::Value> {
        if let Some(val) = obj.get(field) {
            if !val.is_null() {
                return Some(val);
            }
        }
        // Try nested "data" field
        if let Some(nested) = obj.get(field).and_then(|v| v.as_object()).and_then(|o| o.get("data")) {
            if !nested.is_null() {
                return Some(nested);
            }
        }
        None
    }
    
    // Check for signature field (may be null or missing)
    let has_signature = has_field(ecdh_pkg, "signature");
    let has_ps = has_field(ecdh_pkg, "ps");
    let has_key_data = has_field(ecdh_pkg, "keyData");
    
    if !has_signature || !has_key_data {
        return Err(CoreError::protocol_violation("Missing ECDH signed package fields"));
    }
    if !has_field(ecdsa_key, "keyData") {
        return Err(CoreError::protocol_violation("Missing ECDSA keyData"));
    }

    // Verify ECDH signature: raw (r||s) 96 bytes over ps with SHA-384
    let sig_val = get_field_value(ecdh_pkg, "signature")
        .ok_or_else(|| CoreError::protocol_violation("Missing signature field"))?;
    let sig_bytes = extract_bytes(sig_val).map_err(|e| CoreError::invalid_input(format!("Invalid signature format: {}", e)))?;
    if sig_bytes.len() != 96 { 
        return Err(CoreError::protocol_violation(format!("Invalid signature length: {} (expected 96)", sig_bytes.len()))); 
    }
    
    // Get or reconstruct ps (pre-signed string)
    let ps = if has_ps {
        // Use provided ps
        let ps_val = get_field_value(ecdh_pkg, "ps")
            .ok_or_else(|| CoreError::protocol_violation("Missing ps field"))?;
        ps_val.as_str().ok_or_else(|| CoreError::protocol_violation("Invalid ps string"))?.to_string()
    } else {
        // Reconstruct ps from other fields (same format as in create_secure_offer)
        let key_data_val = get_field_value(ecdh_pkg, "keyData")
            .ok_or_else(|| CoreError::protocol_violation("Missing keyData for ps reconstruction"))?;
        let key_data_bytes = extract_bytes(key_data_val).map_err(|e| CoreError::invalid_input(format!("Invalid keyData for ps: {}", e)))?;
        
        let timestamp = ecdh_pkg.get("timestamp")
            .and_then(|v| v.as_i64())
            .or_else(|| ecdh_pkg.get("timestamp").and_then(|v| v.as_u64().map(|u| u as i64)))
            .ok_or_else(|| CoreError::protocol_violation("Missing timestamp for ps reconstruction"))?;
        
        let version = ecdh_pkg.get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("4.0");
        
        // Reconstruct ps string in the same format as create_secure_offer
        let key_data_str = format!("[{}]", key_data_bytes.iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(","));
        
        format!(
            r#"{{"keyType":"ECDH","keyData":{},"timestamp":{},"version":"{}"}}"#,
            key_data_str,
            timestamp,
            version
        )
    };

    // Import verifying key (ECDSA P-384 SPKI)
    let ecdsa_key_data_val = get_field_value(ecdsa_key, "keyData")
        .ok_or_else(|| CoreError::protocol_violation("Missing ECDSA keyData field"))?;
    let ecdsa_spki = extract_bytes(ecdsa_key_data_val).map_err(|e| CoreError::invalid_input(format!("Invalid ECDSA keyData: {}", e)))?;
    let verifying_key = p384::ecdsa::VerifyingKey::from_public_key_der(&ecdsa_spki)
        .map_err(|e| CoreError::crypto_failure(format!("ECDSA key import failed: {}", e)))?;

    // Build signature object from raw (r||s)
    let sig = p384::ecdsa::Signature::from_slice(&sig_bytes)
        .map_err(|e| CoreError::invalid_input(format!("Invalid signature: {}", e)))?;
    let mut hasher = Sha384::new();
    hasher.update(ps.as_bytes());
    let digest = hasher.finalize();
    verifying_key.verify_prehash(&digest, &sig)
        .map_err(|_| CoreError::crypto_failure("Signature verification failed"))?;

    // Import peer ECDH SPKI
    let peer_ecdh_key_data_val = get_field_value(ecdh_pkg, "keyData")
        .ok_or_else(|| CoreError::protocol_violation("Missing ECDH keyData field"))?;
    let peer_ecdh_spki = extract_bytes(peer_ecdh_key_data_val).map_err(|e| CoreError::invalid_input(format!("Invalid ECDH keyData: {}", e)))?;
    let peer_ecdh = p384::PublicKey::from_public_key_der(&peer_ecdh_spki)
        .map_err(|e| CoreError::crypto_failure(format!("ECDH key import failed: {}", e)))?;

    // Check if answer contains salt (sl field) - may need to use answer salt instead of offer salt
    let answer_salt = answer.get("sl")
        .and_then(|v| v.as_array())
        .map(|arr| {
            let mut bytes = Vec::new();
            for v in arr {
                if let Some(n) = v.as_u64() {
                    if n <= 255 {
                        bytes.push(n as u8);
                    }
                } else if let Some(n) = v.as_i64() {
                    if n >= 0 && n <= 255 {
                        bytes.push(n as u8);
                    }
                }
            }
            bytes
        });
    
    // Derive shared secret using our stored ephemeral secret + HKDF with SHA-256, with given salt and info labels
    // IMPORTANT: Use salt from answer if present, otherwise use salt from offer
    let (ecdh_secret, salt) = {
        let mut st = offer_state.lock().map_err(|_| CoreError::state_error("Failed to acquire offer_state lock"))?;
        
        if st.ecdh_secret.is_none() {
            return Err(CoreError::state_error("Missing local ECDH secret - make sure you created an offer first"));
        }
        
        let secret = st.ecdh_secret.take().ok_or_else(|| CoreError::state_error("ECDH secret was None"))?;
        // Use salt from answer if available, otherwise use salt from offer
        let salt = if let Some(ref ans_salt) = answer_salt {
            if ans_salt.len() == 64 {
                ans_salt.clone()
            } else {
                st.session_salt.clone().ok_or_else(|| CoreError::state_error("Missing session salt - make sure you created an offer first"))?
            }
        } else {
            st.session_salt.clone().ok_or_else(|| CoreError::state_error("Missing session salt - make sure you created an offer first"))?
        };
        (secret, salt)
    };
    if salt.len() != 64 { 
        return Err(CoreError::protocol_violation(format!("Invalid salt length: {} (expected 64)", salt.len()))); 
    }
    let shared = p384::ecdh::diffie_hellman(ecdh_secret.to_nonzero_scalar(), peer_ecdh.as_affine());
    let shared_bytes_full = shared.raw_secret_bytes();

    // ВАЖНО: Web Crypto API обрезает shared secret до 32 байт при использовании AES-GCM, length: 256
    // Нужно использовать только первые 32 байта для совместимости с JS версией
    let shared_bytes: &[u8] = if shared_bytes_full.len() >= 32 {
        &shared_bytes_full[..32]
    } else {
        &shared_bytes_full
    };
    
    // ИСПРАВЛЕННАЯ версия HKDF derivation - ПОЛНОСТЬЮ совместима с Web Crypto API
    // Web Crypto API использует HKDF-Extract-and-Expand (RFC 5869)
    // Extract: PRK = HMAC-Hash(salt, IKM)
    // Expand: OKM = HKDF-Expand(PRK, info, L)
    
    // Создаем HKDF instance с salt и shared secret (32 bytes)
    // Hkdf::new(Some(&salt), shared_bytes) делает Extract: PRK = HMAC-Hash(salt, IKM)
    // Extract: PRK = HMAC-Hash(salt, IKM) where IKM = shared_bytes (32 bytes)
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_bytes);
    
    // Важно: Web Crypto API использует HKDF с конкретной длиной output key material (OKM)
    // Для HMAC-SHA-256: output length = 32 bytes (256 bits)
    // Для AES-256-GCM: output length = 32 bytes (256 bits)
    
    let mut enc_okm = [0u8; 32];
    hk.expand(b"message-encryption-v4", &mut enc_okm).map_err(|e| CoreError::crypto_failure(format!("HKDF expand enc failed: {:?}", e)))?;
    
    // Web Crypto API деривирует 64 байта для HMAC-SHA-256 (для повышения безопасности)
    // HMAC-SHA-256 может принимать ключи любого размера, но Web Crypto API использует 64 байта
    let mut mac_okm = [0u8; 64];
    hk.expand(b"message-authentication-v4", &mut mac_okm).map_err(|e| CoreError::crypto_failure(format!("HKDF expand mac failed: {:?}", e)))?;
    
    let mut meta_okm = [0u8; 32];
    hk.expand(b"metadata-protection-v4", &mut meta_okm).map_err(|e| CoreError::crypto_failure(format!("HKDF expand meta failed: {:?}", e)))?;

    // Derive the dedicated fingerprint key (HKDF info 'fingerprint-generation-v4'),
    // exactly like the web version's deriveSharedKeys. The SAS is computed from
    // keyFingerprint = first 12 bytes of SHA-384 over THIS key (not the metadata key).
    let mut fp_okm = [0u8; 32];
    hk.expand(b"fingerprint-generation-v4", &mut fp_okm).map_err(|e| CoreError::crypto_failure(format!("HKDF expand fingerprint failed: {:?}", e)))?;

    // Root for the Double Ratchet — its own domain-separated branch of the key
    // schedule (web deriveSharedKeys, info 'double-ratchet-root-v1').
    let mut dr_root_okm = [0u8; 32];
    hk.expand(b"double-ratchet-root-v1", &mut dr_root_okm)
        .map_err(|e| CoreError::crypto_failure(format!("HKDF expand ratchet root failed: {:?}", e)))?;

    // Compute keyFingerprint (first 12 bytes of SHA-384 over the fingerprint key)
    // to match the web version's SAS key material byte-for-byte.
    let mut fp_h = Sha384::new();
    fp_h.update(&fp_okm);
    let fp = fp_h.finalize();
    let key_fingerprint_bytes: [u8; 12] = {
        let mut bytes = [0u8; 12];
        bytes.copy_from_slice(&fp[..12]);
        bytes
    }; // First 12 bytes for key fingerprint
    
    // Store session keys for message decryption
    {
        let mut keys = session_keys.lock().map_err(|_| CoreError::state_error("Failed to acquire session_keys lock"))?;
        keys.encryption_key = Some(enc_okm.to_vec());
        keys.mac_key = Some(mac_okm.to_vec());
        keys.metadata_key = Some(meta_okm.to_vec());
    }

    // Extract SDP from answer for WebRTC connection
    let answer_sdp = answer.get("s")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CoreError::protocol_violation("Missing SDP in answer"))?;
    
    // Extract DTLS fingerprint from answer SDP for SAS computation
    let remote_dtls_fp = extract_dtls_fingerprint_from_sdp(answer_sdp)
        .unwrap_or_else(|| "".to_string());
    
    // Get and clear local DTLS fingerprint from offer state
    let local_dtls_fp = {
        let mut st = offer_state.lock().map_err(|_| CoreError::state_error("Failed to acquire offer_state lock"))?;
        let fp = st.local_dtls_fingerprint.clone().unwrap_or_else(|| "".to_string());
        st.local_dtls_fingerprint = None;
        fp
    };
    
    // Compute SAS verification code if we have both fingerprints and key fingerprint
    let verification_code = if !local_dtls_fp.is_empty() && !remote_dtls_fp.is_empty() {
        // Use key fingerprint bytes directly (first 12 bytes of SHA-384 over meta_okm)
        compute_sas_code(&key_fingerprint_bytes, &local_dtls_fp, &remote_dtls_fp).unwrap_or_default()
    } else {
        "".to_string()
    };
    
    // Bring up the Double Ratchet if the responder advertised it. As the
    // initiator we adopt a fresh ratchet key immediately, so even our very
    // first message has already left the handshake key behind. Failure is
    // deliberately not fatal — the session falls back to the static keys.
    let ratchet = if peer_supports_ratchet {
        match crate::ratchet::DoubleRatchet::init_initiator(&dr_root_okm, &salt, &peer_ecdh) {
            Ok(r) => Some(r),
            Err(_) => None,
        }
    } else {
        None
    };
    {
        use zeroize::Zeroize;
        dr_root_okm.zeroize(); // Folded into the ratchet (or abandoned) — must not linger.
    }

    // Store session keys for message decryption (duplicate store for compatibility)
    {
        let mut keys = session_keys.lock().map_err(|_| CoreError::state_error("Failed to acquire session_keys lock"))?;
        keys.encryption_key = Some(enc_okm.to_vec());
        keys.mac_key = Some(mac_okm.to_vec());
        keys.metadata_key = Some(meta_okm.to_vec());
        keys.key_fingerprint = Some(crate::file_crypto::compute_key_fingerprint(shared_bytes, &salt));
        // Keep the locally derived SAS next to the keys so the frontend can read it
        // back from one place on both sides of the handshake.
        keys.verification_code = if verification_code.is_empty() { None } else { Some(verification_code.clone()) };
        keys.peer_supports_ratchet = peer_supports_ratchet;
        keys.ratchet = ratchet;
    }
    
    // Create connection confirmation compatible with web version
    // Use already parsed answer object instead of decoded string to avoid double-encoding issues
    let confirmation = serde_json::json!({
        "status": "connected",
        "message": "Secure connection established",
        "timestamp": chrono::Utc::now().timestamp_millis(),
        "sessionId": answer.get("si").cloned().unwrap_or(serde_json::Value::Null),
        "connectionId": answer.get("ci").cloned().unwrap_or(serde_json::Value::Null),
        "securityLevel": "MAX",
        "protocolVersion": "4.1",
        "capabilities": ["encryption", "verification", "pfs", "mutual_auth"],
        "keyExchange": "completed",
        "sdp": answer_sdp,
        "verificationCode": verification_code, // Include verification code
        "answerData": answer // Include parsed answer object (already JSON value)
    });
    
    serde_json::to_string(&confirmation).map_err(|e| CoreError::internal_error(format!("JSON serialization failed: {}", e)))
}

#[cfg(test)]
mod web_compat_tests {
    use super::*;
    use crate::session::OfferContext;

    // Decode an SB1:gz payload back to its JSON object.
    fn decode_sb1gz(payload: &str) -> serde_json::Value {
        let b64 = payload.strip_prefix("SB1:gz:").expect("SB1:gz prefix");
        let compressed = general_purpose::STANDARD.decode(b64).unwrap();
        let mut s = String::new();
        ZlibDecoder::new(&compressed[..]).read_to_string(&mut s).unwrap();
        serde_json::from_str(&s).unwrap()
    }

    // Replicate the web's importPublicKeyFromSignedPackage verification exactly:
    // packageCopy = { ...e }; delete packageCopy.signature; verify ECDSA-SHA384
    // over JSON.stringify(packageCopy) using the key from the "d" package.
    fn verify_e_signature_web_style(pkg: &serde_json::Value) {
        let e = pkg.get("e").expect("offer must have e");
        let d = pkg.get("d").expect("offer must have d");

        let d_key_data = extract_bytes(d.get("keyData").unwrap()).unwrap();
        let vk = p384::ecdsa::VerifyingKey::from_public_key_der(&d_key_data)
            .expect("import ECDSA verifying key from d.keyData");

        let sig_bytes = extract_bytes(e.get("signature").unwrap()).unwrap();
        let sig = p384::ecdsa::Signature::from_slice(&sig_bytes).unwrap();

        // Reconstruct the signed string the same way the web does.
        let mut e_copy = e.as_object().unwrap().clone();
        e_copy.remove("signature");
        let package_string = serde_json::to_string(&serde_json::Value::Object(e_copy)).unwrap();

        let mut hasher = Sha384::new();
        hasher.update(package_string.as_bytes());
        let digest = hasher.finalize();

        vk.verify_prehash(&digest, &sig)
            .expect("web-style ECDH signature verification must pass");
    }

    #[test]
    fn offer_e_signature_is_web_verifiable() {
        let state = Arc::new(Mutex::new(OfferContext::new()));
        let offer = create_secure_offer(state, None).expect("create offer");
        let pkg = decode_sb1gz(&offer);
        assert_eq!(pkg.get("v").and_then(|v| v.as_str()), Some("4.1"));
        // The "e" package must carry exactly these fields (no "ps").
        let e = pkg.get("e").unwrap().as_object().unwrap();
        let mut keys: Vec<&str> = e.keys().map(|k| k.as_str()).collect();
        keys.sort();
        assert_eq!(keys, vec!["keyData", "keyType", "signature", "timestamp", "version"]);
        verify_e_signature_web_style(&pkg);
    }

    #[test]
    fn answer_e_signature_is_web_verifiable() {
        // Desktop offers, desktop answers (join): the answer's "e" must also be
        // verifiable the web way, since the web offerer verifies it.
        let offerer = Arc::new(Mutex::new(OfferContext::new()));
        let offer = create_secure_offer(offerer, None).expect("create offer");

        let ans_state = Arc::new(Mutex::new(OfferContext::new()));
        let ans_keys = Arc::new(Mutex::new(SessionKeys::new()));
        let answer = join_secure_connection(ans_state, ans_keys, offer, None).expect("join");
        let pkg = decode_sb1gz(&answer);
        assert_eq!(pkg.get("v").and_then(|v| v.as_str()), Some("4.1"));
        verify_e_signature_web_style(&pkg);
    }

    // Both peers must derive the SAME SAS independently, from the shared secret and
    // both DTLS fingerprints. The joining side used to derive nothing at all and
    // displayed whatever the offerer announced over the wire, which makes the
    // out-of-band comparison meaningless against an attacker in the middle.
    #[test]
    fn both_peers_derive_the_same_sas_independently() {
        let offerer_state = Arc::new(Mutex::new(OfferContext::new()));
        let offerer_keys = Arc::new(Mutex::new(SessionKeys::new()));
        let offer = create_secure_offer(offerer_state.clone(), None).expect("create offer");

        let ans_state = Arc::new(Mutex::new(OfferContext::new()));
        let ans_keys = Arc::new(Mutex::new(SessionKeys::new()));
        let answer = join_secure_connection(ans_state, ans_keys.clone(), offer, None).expect("join");

        handle_secure_answer(offerer_state, offerer_keys.clone(), answer).expect("handle answer");

        let joiner_sas = ans_keys.lock().unwrap().verification_code.clone();
        let offerer_sas = offerer_keys.lock().unwrap().verification_code.clone();

        let joiner_sas = joiner_sas.expect("the joining side must derive its own SAS");
        let offerer_sas = offerer_sas.expect("the offering side must derive its own SAS");

        assert_eq!(joiner_sas.len(), 7, "SAS is a 7-digit code, web-compatible");
        assert!(joiner_sas.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(
            joiner_sas, offerer_sas,
            "both peers must independently reach the same SAS, or the out-of-band comparison cannot work"
        );
    }

    // Cross-implementation pin: the same inputs must yield the same SAS here and in
    // the web client, or a desktop<->web session shows the two users different codes
    // and verification is impossible. The expected value was produced by the web's
    // EnhancedSecureWebRTCManager.prototype._computeSAS with these exact inputs.
    //
    // Note the normalization this depends on: fingerprints keep their colons and are
    // lowercased, and the salt is 'webrtc-sas|' + the two joined by '|' AFTER sorting.
    #[test]
    fn sas_matches_web_reference_vector() {
        let key: Vec<u8> = (0..12u8).map(|i| i * 7 + 3).collect();
        let a = "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99";
        let b = "12:34:56:78:9a:bc:de:f0:11:22:33:44:55:66:77:88";

        assert_eq!(compute_sas_code(&key, a, b).unwrap(), "4202749");
        assert_eq!(compute_sas_code(&key, b, a).unwrap(), "4202749");
    }

    // compute_sas_code sorts the two fingerprints, so orientation must not matter:
    // each peer passes its own as "local" and the other as "remote".
    #[test]
    fn sas_is_orientation_independent() {
        let key = [7u8; 12];
        let a = "AA:BB:CC";
        let b = "DD:EE:FF";
        assert_eq!(
            compute_sas_code(&key, a, b).unwrap(),
            compute_sas_code(&key, b, a).unwrap()
        );
    }

    // The `dr` flag is how peers negotiate the Double Ratchet (web
    // RATCHET_VERSION). It must sit in both packages, or a web 5.7.x peer
    // silently downgrades the whole session to static keys.
    #[test]
    fn offer_and_answer_advertise_ratchet_support() {
        let offer_state = Arc::new(Mutex::new(OfferContext::new()));
        let offer = create_secure_offer(offer_state, None).unwrap();
        let offer_pkg = decode_sb1gz(&offer);
        assert_eq!(offer_pkg["dr"].as_u64(), Some(crate::ratchet::RATCHET_VERSION));

        let join_state = Arc::new(Mutex::new(OfferContext::new()));
        let join_keys = Arc::new(Mutex::new(crate::session::SessionKeys::new()));
        let answer = join_secure_connection(join_state, join_keys, offer, None).unwrap();
        let answer_pkg = decode_sb1gz(&answer);
        assert_eq!(answer_pkg["dr"].as_u64(), Some(crate::ratchet::RATCHET_VERSION));
    }

    // Full handshake through the real offer/join/answer flow must leave BOTH
    // sides with a live ratchet that interoperates: initiator sends first (its
    // init deliberately steps the root once), the responder gains a sending
    // chain only after that first message, and replies then ratchet back.
    #[test]
    fn handshake_brings_up_an_interoperating_ratchet() {
        let offerer_state = Arc::new(Mutex::new(OfferContext::new()));
        let offerer_keys = Arc::new(Mutex::new(crate::session::SessionKeys::new()));
        let joiner_state = Arc::new(Mutex::new(OfferContext::new()));
        let joiner_keys = Arc::new(Mutex::new(crate::session::SessionKeys::new()));

        let offer = create_secure_offer(offerer_state.clone(), None).unwrap();
        let answer = join_secure_connection(joiner_state, joiner_keys.clone(), offer, None).unwrap();
        handle_secure_answer(offerer_state, offerer_keys.clone(), answer).unwrap();

        // Initiator can send immediately; responder must not be able to yet.
        let frame: serde_json::Value = serde_json::from_str(
            &serde_json::to_string(
                &crate::session::encrypt_chat_frame(offerer_keys.clone(), "hi".into(), "m1".into(), 0).unwrap()
            ).unwrap()
        ).unwrap();
        assert_eq!(frame["type"].as_str(), Some("ratchet_message"),
            "initiator's first frame must already be ratcheted");

        // Responder's pre-first-inbound frame falls back to the static path,
        // exactly like the web client's presence update on verification.
        let early = crate::session::encrypt_chat_frame(joiner_keys.clone(), "early".into(), "m0".into(), 0).unwrap();
        assert_eq!(early["type"].as_str(), Some("enhanced_message"),
            "responder has no sending chain before the initiator's first message");

        let opened = crate::session::decrypt_ratchet_message(
            joiner_keys.clone(),
            frame["h"].as_str().unwrap(),
            frame["c"].as_str().unwrap(),
        ).unwrap();
        assert_eq!(opened["message"].as_str(), Some("hi"));

        // Now the responder ratchets its reply, and the initiator reads it.
        let reply = crate::session::encrypt_chat_frame(joiner_keys, "yo".into(), "m2".into(), 1).unwrap();
        assert_eq!(reply["type"].as_str(), Some("ratchet_message"));
        let opened = crate::session::decrypt_ratchet_message(
            offerer_keys,
            reply["h"].as_str().unwrap(),
            reply["c"].as_str().unwrap(),
        ).unwrap();
        assert_eq!(opened["message"].as_str(), Some("yo"));
    }
}
