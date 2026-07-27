// Web-compatible file-transfer crypto (matches SecureBit web `EnhancedSecureFileTransfer.js`).
//
// Step 1 — the key fingerprint. The web derives, from the ECDH shared secret and the
// session salt, a "fingerprint key" via HKDF, then takes the first 12 bytes of its
// SHA-384 as a colon-separated hex string. That string ("safety number") is later mixed
// into every per-file key, so both peers MUST compute it identically.
//
//   fingerprintKey = HKDF-SHA256(ikm = shared_secret[..32], salt = session_salt,
//                                info = "fingerprint-generation-v4", L = 32)
//   keyFingerprint = hex(SHA-384(fingerprintKey)[0..12]) joined by ":"

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256, Sha384};

/// Compute the web-compatible key fingerprint from the (already 32-byte-truncated)
/// ECDH shared secret and the 64-byte session salt.
pub fn compute_key_fingerprint(shared_bytes: &[u8], salt: &[u8]) -> String {
    let hk = Hkdf::<Sha256>::new(Some(salt), shared_bytes);
    let mut fp_key = [0u8; 32];
    hk.expand(b"fingerprint-generation-v4", &mut fp_key)
        .expect("HKDF expand of fingerprint key (32 bytes) never fails");
    let hash = Sha384::digest(fp_key);
    hash[..12]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Per-file AES-256-GCM key, matching the web's `deriveFileSessionKeyFromSalt`:
///   fileKey = SHA-256( utf8(keyFingerprint) ‖ session_salt ‖ file_salt(32) ‖ utf8(fileId) )
pub fn derive_file_key(key_fingerprint: &str, session_salt: &[u8], file_salt: &[u8], file_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(key_fingerprint.as_bytes());
    hasher.update(session_salt);
    hasher.update(file_salt);
    hasher.update(file_id.as_bytes());
    let out = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

/// Encrypt one file chunk with AES-256-GCM (12-byte nonce, no AAD, 128-bit tag).
/// Output is `ciphertext ‖ tag` — identical to Web Crypto's AES-GCM output.
pub fn encrypt_chunk(file_key: &[u8; 32], nonce12: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(file_key).map_err(|e| e.to_string())?;
    cipher
        .encrypt(&Nonce::from(*nonce12), plaintext)
        .map_err(|e| format!("chunk encrypt failed: {}", e))
}

/// Decrypt one file chunk (`ciphertext ‖ tag`) with AES-256-GCM.
pub fn decrypt_chunk(file_key: &[u8; 32], nonce12: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(file_key).map_err(|e| e.to_string())?;
    cipher
        .decrypt(&Nonce::from(*nonce12), ciphertext)
        .map_err(|e| format!("chunk decrypt failed (auth): {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    // Reference vector computed with the browser Web Crypto API (the exact code the web
    // client runs): ikm = 0..32, salt = 0..64, info = "fingerprint-generation-v4".
    #[test]
    fn key_fingerprint_matches_web_reference() {
        let ikm: Vec<u8> = (0u8..32).collect();
        let salt: Vec<u8> = (0u8..64).collect();
        assert_eq!(
            compute_key_fingerprint(&ikm, &salt),
            "71:2e:1c:da:b7:cc:05:7c:78:cf:31:45"
        );
    }

    // Reference: keyFingerprint above, session_salt = 0..64, file_salt = (i*7)&0xff,
    // fileId = "test-file-id" — SHA-256 of the concatenation (web deriveFileSessionKeyFromSalt).
    #[test]
    fn file_key_matches_web_reference() {
        let fp = "71:2e:1c:da:b7:cc:05:7c:78:cf:31:45";
        let session_salt: Vec<u8> = (0u8..64).collect();
        let file_salt: Vec<u8> = (0u8..32).map(|i| i.wrapping_mul(7)).collect();
        let key = derive_file_key(fp, &session_salt, &file_salt, "test-file-id");
        assert_eq!(
            hex::encode(key),
            "86c3b712095b11b630c8c7b512dd86dfd1bcb1c0c9a23d47e53fb6f3d100c49b"
        );
    }

    // Reference: fileKey above, nonce = 0..12, plaintext = "hello secure world".
    // Web Crypto AES-GCM output (ciphertext‖tag) → base64.
    #[test]
    fn chunk_aes_gcm_matches_web() {
        let mut file_key = [0u8; 32];
        file_key.copy_from_slice(&hex::decode("86c3b712095b11b630c8c7b512dd86dfd1bcb1c0c9a23d47e53fb6f3d100c49b").unwrap());
        let nonce: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let pt = b"hello secure world";
        let ct = encrypt_chunk(&file_key, &nonce, pt).unwrap();
        assert_eq!(STANDARD.encode(&ct), "GBQ0Fkx2c94DpwGg/r76uA68m77d2FZvK826u/TiSTvGPg==");
        // Round-trip: decrypt the browser-produced ciphertext back to plaintext.
        let web_ct = STANDARD.decode("GBQ0Fkx2c94DpwGg/r76uA68m77d2FZvK826u/TiSTvGPg==").unwrap();
        assert_eq!(decrypt_chunk(&file_key, &nonce, &web_ct).unwrap(), pt);
    }
}
