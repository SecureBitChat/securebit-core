// Session management: keys, encryption, decryption, metadata protection
use rand::Rng;
use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead, Nonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::{Arc, Mutex};

// Offer context to persist ephemeral state between offer and answer handling
pub struct OfferContext {
    pub ecdh_secret: Option<p384::ecdh::EphemeralSecret>,
    pub session_salt: Option<Vec<u8>>, // 64 bytes
    pub local_dtls_fingerprint: Option<String>, // Local DTLS fingerprint for SAS computation
}

// Session keys for message encryption/decryption
pub struct SessionKeys {
    pub encryption_key: Option<Vec<u8>>, // 32 bytes
    pub mac_key: Option<Vec<u8>>, // 64 bytes - Web Crypto API использует 64-байтовый ключ для HMAC-SHA-256
    pub metadata_key: Option<Vec<u8>>, // 32 bytes
}

impl SessionKeys {
    pub fn new() -> Self {
        Self {
            encryption_key: None,
            mac_key: None,
            metadata_key: None,
        }
    }
}

impl OfferContext {
    pub fn new() -> Self {
        Self {
            ecdh_secret: None,
            session_salt: None,
            local_dtls_fingerprint: None,
        }
    }
}

pub fn encrypt_enhanced_message(
    session_keys: Arc<Mutex<SessionKeys>>,
    message: String,
    message_id: String,
    sequence_number: u64,
) -> Result<serde_json::Value, String> {
    // Get session keys
    let keys = session_keys.lock()
        .map_err(|_| "Failed to acquire session keys lock".to_string())?;
    let encryption_key = keys.encryption_key.as_ref().ok_or("Encryption key not available")?;
    let mac_key = keys.mac_key.as_ref().ok_or("MAC key not available")?;
    let metadata_key = keys.metadata_key.as_ref().ok_or("Metadata key not available")?;
    
    // Validate key lengths
    if encryption_key.len() != 32 {
        return Err(format!("Invalid encryption key length: {} (expected 32)", encryption_key.len()));
    }
    if mac_key.len() != 64 {
        return Err(format!("Invalid MAC key length: {} (expected 64)", mac_key.len()));
    }
    if metadata_key.len() != 32 {
        return Err(format!("Invalid metadata key length: {} (expected 32)", metadata_key.len()));
    }
    
    // Encode message to bytes
    let message_data = message.as_bytes();
    let timestamp = chrono::Utc::now().timestamp_millis() as u64;
    
    // Generate random IVs (12 bytes each for AES-GCM)
    let mut message_iv = [0u8; 12];
    let mut metadata_iv = [0u8; 12];
    rand::thread_rng().fill(&mut message_iv);
    rand::thread_rng().fill(&mut metadata_iv);
    
    // Add padding to message (pad to multiple of 16 bytes)
    let padding_size = 16 - (message_data.len() % 16);
    let mut padded_message = Vec::with_capacity(message_data.len() + padding_size);
    padded_message.extend_from_slice(message_data);
    let mut padding = vec![0u8; padding_size];
    rand::thread_rng().fill(&mut padding[..]);
    padded_message.extend_from_slice(&padding);
    
    // Encrypt message using AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(encryption_key)
        .map_err(|e| format!("Failed to create AES-GCM cipher: {}", e))?;
    let nonce = Nonce::from(message_iv);
    let encrypted_message = cipher.encrypt(&nonce, padded_message.as_slice())
        .map_err(|e| format!("Failed to encrypt message: {}", e))?;
    
    // Create metadata
    let metadata = serde_json::json!({
        "id": message_id,
        "timestamp": timestamp,
        "sequenceNumber": sequence_number,
        "originalLength": message_data.len(),
        "version": "4.0"
    });
    
    // Sort metadata keys alphabetically (like web version)
    let mut sorted_metadata = serde_json::Map::new();
    if let Some(obj) = metadata.as_object() {
        let mut keys: Vec<String> = obj.keys().cloned().collect();
        keys.sort();
        for key in keys {
            if let Some(value) = obj.get(&key) {
                sorted_metadata.insert(key, value.clone());
            }
        }
    }
    let sorted_metadata_value = serde_json::Value::Object(sorted_metadata);
    let metadata_str = serde_json::to_string(&sorted_metadata_value)
        .map_err(|e| format!("Failed to serialize metadata: {}", e))?;
    
    // Encrypt metadata using AES-256-GCM
    let metadata_cipher = Aes256Gcm::new_from_slice(metadata_key)
        .map_err(|e| format!("Failed to create metadata AES-GCM cipher: {}", e))?;
    let metadata_nonce = Nonce::from(metadata_iv);
    let encrypted_metadata = metadata_cipher.encrypt(&metadata_nonce, metadata_str.as_bytes())
        .map_err(|e| format!("Failed to encrypt metadata: {}", e))?;
    
    // Create payload (without MAC first)
    let payload_for_mac = serde_json::json!({
        "messageData": encrypted_message,
        "messageIv": message_iv.to_vec(),
        "metadataData": encrypted_metadata,
        "metadataIv": metadata_iv.to_vec(),
        "version": "4.0"
    });
    
    // Sort keys alphabetically (like web version)
    let mut sorted_payload = serde_json::Map::new();
    if let Some(obj) = payload_for_mac.as_object() {
        let mut keys: Vec<String> = obj.keys().cloned().collect();
        keys.sort();
        for key in keys {
            if let Some(value) = obj.get(&key) {
                sorted_payload.insert(key, value.clone());
            }
        }
    }
    let sorted_payload_value = serde_json::Value::Object(sorted_payload.clone());
    let payload_str = serde_json::to_string(&sorted_payload_value)
        .map_err(|e| format!("Failed to serialize payload for MAC: {}", e))?;
    
    // Compute MAC using HMAC-SHA256
    type HmacSha256 = Hmac<Sha256>;
    
    let mut mac_verifier = <HmacSha256 as Mac>::new_from_slice(mac_key)
        .map_err(|e| format!("Failed to create HMAC-SHA256: {}", e))?;
    mac_verifier.update(payload_str.as_bytes());
    let mac = mac_verifier.finalize().into_bytes();
    
    // Add MAC to payload
    let mut final_payload = sorted_payload;
    final_payload.insert("mac".to_string(), serde_json::Value::Array(
        mac.iter().map(|&b| serde_json::Value::Number(b.into())).collect()
    ));
    
    Ok(serde_json::Value::Object(final_payload))
}

pub fn decrypt_enhanced_message(
    session_keys: Arc<Mutex<SessionKeys>>,
    message_data: serde_json::Value,
) -> Result<serde_json::Value, String> {
    // Get session keys
    let keys = session_keys.lock()
        .map_err(|_| "Failed to acquire session keys lock".to_string())?;
    let encryption_key = keys.encryption_key.as_ref().ok_or("Encryption key not available")?;
    let mac_key = keys.mac_key.as_ref().ok_or("MAC key not available")?;
    let metadata_key = keys.metadata_key.as_ref().ok_or("Metadata key not available")?;
    
    // Extract encrypted data from message
    let data = message_data.get("data")
        .and_then(|v| v.as_object())
        .ok_or("Missing data field in enhanced_message")?;
    
    // Extract arrays of numbers and convert to Vec<u8>
    let extract_bytes = |field: &str| -> Result<Vec<u8>, String> {
        let arr = data.get(field)
            .and_then(|v| v.as_array())
            .ok_or_else(|| format!("Missing or invalid {} field", field))?;
        let mut bytes = Vec::new();
        for v in arr {
            let n = v.as_u64()
                .or_else(|| v.as_i64().map(|i| i as u64))
                .ok_or_else(|| format!("Invalid number in {} array", field))?;
            if n > 255 {
                return Err(format!("Number {} out of byte range in {}", n, field));
            }
            bytes.push(n as u8);
        }
        Ok(bytes)
    };
    
    let message_iv = extract_bytes("messageIv")?;
    let message_data_enc = extract_bytes("messageData")?;
    let metadata_iv = extract_bytes("metadataIv")?;
    let metadata_data_enc = extract_bytes("metadataData")?;
    let mac = extract_bytes("mac")?;
    
    // Verify MAC using HMAC-SHA-256
    // MAC is computed over JSON string of payload WITHOUT mac field, with sorted keys
    // This matches web version: sortObjectKeys(payloadCopy) then JSON.stringify
    
    // Create payload copy without mac field (exactly like web version: payloadCopy = { ...encryptedPayload }; delete payloadCopy.mac;)
    // Web version uses sortObjectKeys which sorts keys alphabetically
    let payload_for_mac = serde_json::json!({
        "messageData": message_data_enc,
        "messageIv": message_iv,
        "metadataData": metadata_data_enc,
        "metadataIv": metadata_iv,
        "version": data.get("version").and_then(|v| v.as_str()).unwrap_or("4.0")
    });
    
    // Sort keys alphabetically (web version uses sortObjectKeys)
    // Important: order must be: messageData, messageIv, metadataData, metadataIv, version (alphabetically sorted)
    let mut sorted_payload = serde_json::Map::new();
    if let Some(obj) = payload_for_mac.as_object() {
        let mut keys: Vec<String> = obj.keys().cloned().collect();
        keys.sort(); // Alphabetical sort
        for key in keys {
            if let Some(value) = obj.get(&key) {
                sorted_payload.insert(key, value.clone());
            }
        }
    }
    let sorted_payload_value = serde_json::Value::Object(sorted_payload);
    
    // Convert to JSON string (compact, no spaces, matching web version's JSON.stringify)
    // Web version: JSON.stringify(sortedPayloadCopy) - this produces compact JSON without spaces
    let payload_str = serde_json::to_string(&sorted_payload_value)
        .map_err(|e| format!("Failed to serialize payload for MAC: {}", e))?;
    
    // Compute MAC using HMAC-SHA256 (same as web version)
    type HmacSha256 = Hmac<Sha256>;
    
    let mut mac_verifier = <HmacSha256 as Mac>::new_from_slice(mac_key)
        .map_err(|e| format!("Failed to create HMAC-SHA256: {}", e))?;
    mac_verifier.update(payload_str.as_bytes());
    let expected_mac = mac_verifier.finalize().into_bytes();
    
    // Use constant-time comparison for MAC verification
    // Convert both to slices for comparison
    if expected_mac.as_ref() as &[u8] != mac.as_slice() {
        return Err("MAC verification failed".to_string());
    }
    
    // Decrypt metadataData first (needed to get originalLength)
    if metadata_iv.len() != 12 {
        return Err(format!("Invalid metadata IV length: {} (expected 12)", metadata_iv.len()));
    }
    if metadata_key.len() != 32 {
        return Err(format!("Invalid metadata key length: {} (expected 32)", metadata_key.len()));
    }
    
    let metadata_cipher = Aes256Gcm::new_from_slice(metadata_key)
        .map_err(|e| format!("Failed to create metadata AES-GCM cipher: {}", e))?;
    
    // Create nonce from array (AES-GCM nonce is 12 bytes)
    let mut metadata_nonce_bytes = [0u8; 12];
    metadata_nonce_bytes.copy_from_slice(&metadata_iv);
    let metadata_nonce = Nonce::from(metadata_nonce_bytes);
    
    let metadata_plaintext = metadata_cipher.decrypt(&metadata_nonce, metadata_data_enc.as_slice())
        .map_err(|e| format!("Failed to decrypt metadataData: {}", e))?;
    
    // Parse metadata to get originalLength
    let metadata_str = String::from_utf8(metadata_plaintext)
        .map_err(|e| format!("Failed to convert metadata to UTF-8: {}", e))?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata_str)
        .map_err(|e| format!("Failed to parse metadata JSON: {}", e))?;
    
    let original_length = metadata.get("originalLength")
        .and_then(|v| v.as_u64())
        .ok_or("Missing originalLength in metadata")? as usize;
    
    // Decrypt messageData using AES-256-GCM
    if message_iv.len() != 12 {
        return Err(format!("Invalid message IV length: {} (expected 12)", message_iv.len()));
    }
    if encryption_key.len() != 32 {
        return Err(format!("Invalid encryption key length: {} (expected 32)", encryption_key.len()));
    }
    
    let cipher = Aes256Gcm::new_from_slice(encryption_key)
        .map_err(|e| format!("Failed to create AES-GCM cipher: {}", e))?;
    
    // Create nonce from array (AES-GCM nonce is 12 bytes)
    let mut message_nonce_bytes = [0u8; 12];
    message_nonce_bytes.copy_from_slice(&message_iv);
    let nonce = Nonce::from(message_nonce_bytes);
    
    let padded_message = cipher.decrypt(&nonce, message_data_enc.as_slice())
        .map_err(|e| format!("Failed to decrypt messageData: {}", e))?;
    
    // Remove padding - take only originalLength bytes
    if padded_message.len() < original_length {
        return Err(format!("Decrypted message too short: {} < {}", padded_message.len(), original_length));
    }
    let message_plaintext = &padded_message[..original_length];
    
    // Decode message text
    let message_text = String::from_utf8(message_plaintext.to_vec())
        .map_err(|e| format!("Failed to convert decrypted message to UTF-8: {}", e))?;
    
    // Try to parse as JSON to extract the actual message text
    // Web version sends JSON like: {"type":"message","data":"test",...}
    let actual_message = if let Ok(message_json) = serde_json::from_str::<serde_json::Value>(&message_text) {
        // Extract "data" field if it exists, otherwise use the whole text
        if let Some(data_field) = message_json.get("data") {
            if let Some(text) = data_field.as_str() {
                text.to_string()
            } else {
                message_text
            }
        } else {
            message_text
        }
    } else {
        // Not JSON, use as-is
        message_text
    };
    
    // Return decrypted message (web version returns { message, messageId, timestamp, sequenceNumber })
    Ok(serde_json::json!({
        "message": actual_message,
        "messageId": metadata.get("id").and_then(|v| v.as_str()).unwrap_or(""),
        "timestamp": metadata.get("timestamp").and_then(|v| v.as_u64()).unwrap_or(0),
        "sequenceNumber": metadata.get("sequenceNumber").and_then(|v| v.as_u64()).unwrap_or(0)
    }))
}

