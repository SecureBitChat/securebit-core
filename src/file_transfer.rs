// Platform-agnostic secure file transfer.
//
// This module owns the *protocol and cryptography* of sending and receiving
// files over an already-established secure channel. It is deliberately free of
// any I/O or transport: the platform layer (Tauri webview, native mobile, ...)
// is responsible for picking/reading/saving files and for moving the JSON
// protocol messages produced here over the WebRTC data channel.
//
// Each chunk is encrypted with AES-256-GCM under the shared session
// `encryption_key` (the same symmetric key both peers derive during the
// handshake), with a fresh random 12-byte nonce per chunk. File integrity is
// verified end-to-end with a SHA-256 hash of the full plaintext.
//
// Protocol messages (all JSON, camelCase to match the JS side):
//   file_transfer_start    { fileId, fileName, fileSize, fileType, totalChunks, chunkSize, fileHash }
//   file_transfer_response { fileId, accepted, error? }
//   file_chunk             { fileId, chunkIndex, nonce(b64), data(b64), chunkSize }
//   chunk_confirmation     { fileId, chunkIndex }
//   file_transfer_complete { fileId, success, error? }

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose, Engine as _};
use rand::Rng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Raw bytes per chunk before encryption. 16 KB keeps the on-the-wire
/// (AES-GCM + Base64) message well under the 64 KB SCTP message-size floor that
/// WebRTC data channels enforce on some browsers/peers.
pub const CHUNK_SIZE: usize = 16 * 1024;

/// Hard ceiling on a single file, matching the web client.
pub const MAX_FILE_SIZE: usize = 100 * 1024 * 1024;

/// Outgoing (sender) transfer state.
struct SendingState {
    data: Vec<u8>,
    total_chunks: usize,
    next_chunk: usize,
    accepted: bool,
    confirmed_chunks: usize,
}

/// Incoming (receiver) transfer state.
struct ReceivingState {
    file_name: String,
    file_type: String,
    file_size: usize,
    total_chunks: usize,
    file_hash: String,
    chunks: HashMap<usize, Vec<u8>>,
    received_count: usize,
    accepted: bool,
    /// Guards assembly so a received file is delivered exactly once.
    assembled: bool,
}

/// Owns all in-flight transfers in both directions.
pub struct FileTransferManager {
    sending: HashMap<String, SendingState>,
    receiving: HashMap<String, ReceivingState>,
}

impl FileTransferManager {
    pub fn new() -> Self {
        Self {
            sending: HashMap::new(),
            receiving: HashMap::new(),
        }
    }

    /// Drop all transfer state (e.g. on disconnect).
    pub fn clear(&mut self) {
        self.sending.clear();
        self.receiving.clear();
    }

    // ---- Sender ---------------------------------------------------------

    /// Register an outgoing file and produce the `file_transfer_start` message
    /// the platform should send to the peer. No chunk is produced until the
    /// peer accepts (see [`next_chunk`]).
    pub fn prepare_outgoing(
        &mut self,
        file_id: String,
        file_name: String,
        file_type: String,
        data: Vec<u8>,
    ) -> Result<Value, String> {
        if data.is_empty() {
            return Err("Cannot send an empty file".to_string());
        }
        if data.len() > MAX_FILE_SIZE {
            return Err(format!(
                "File too large: {} bytes (max {} bytes)",
                data.len(),
                MAX_FILE_SIZE
            ));
        }

        let total_chunks = (data.len() + CHUNK_SIZE - 1) / CHUNK_SIZE;
        let file_hash = hex::encode(Sha256::digest(&data));

        let start = json!({
            "type": "file_transfer_start",
            "fileId": file_id,
            "fileName": file_name,
            "fileSize": data.len(),
            "fileType": file_type,
            "totalChunks": total_chunks,
            "chunkSize": CHUNK_SIZE,
            "fileHash": file_hash,
        });

        self.sending.insert(
            file_id,
            SendingState {
                data,
                total_chunks,
                next_chunk: 0,
                accepted: false,
                confirmed_chunks: 0,
            },
        );

        Ok(start)
    }

    /// Produce the next `file_chunk` message for an accepted outgoing transfer.
    /// Returns `Ok(None)` once every chunk has been produced.
    pub fn next_chunk(&mut self, file_id: &str, enc_key: &[u8]) -> Result<Option<Value>, String> {
        let state = self
            .sending
            .get_mut(file_id)
            .ok_or_else(|| "Unknown outgoing transfer".to_string())?;

        if !state.accepted {
            return Err("Transfer not accepted by peer yet".to_string());
        }
        if state.next_chunk >= state.total_chunks {
            return Ok(None);
        }

        let index = state.next_chunk;
        let start = index * CHUNK_SIZE;
        let end = ((index + 1) * CHUNK_SIZE).min(state.data.len());
        let plaintext = &state.data[start..end];

        let (nonce_b64, data_b64) = encrypt_chunk(enc_key, plaintext)?;
        state.next_chunk += 1;

        Ok(Some(json!({
            "type": "file_chunk",
            "fileId": file_id,
            "chunkIndex": index,
            "nonce": nonce_b64,
            "data": data_b64,
            "chunkSize": plaintext.len(),
        })))
    }

    // ---- Receiver consent ----------------------------------------------

    /// Accept an incoming transfer. Returns the `file_transfer_response`
    /// (accepted) message to send back so the sender starts streaming chunks.
    pub fn accept(&mut self, file_id: &str) -> Result<Value, String> {
        let state = self
            .receiving
            .get_mut(file_id)
            .ok_or_else(|| "Unknown incoming transfer".to_string())?;
        state.accepted = true;
        Ok(json!({
            "type": "file_transfer_response",
            "fileId": file_id,
            "accepted": true,
        }))
    }

    /// Reject an incoming transfer. Returns the `file_transfer_response`
    /// (rejected) message to send back, and forgets the transfer.
    pub fn reject(&mut self, file_id: &str, reason: &str) -> Result<Value, String> {
        self.receiving.remove(file_id);
        Ok(json!({
            "type": "file_transfer_response",
            "fileId": file_id,
            "accepted": false,
            "error": reason,
        }))
    }

    /// Forget any state for a transfer (cancel/cleanup), either direction.
    pub fn cancel(&mut self, file_id: &str) {
        self.sending.remove(file_id);
        self.receiving.remove(file_id);
    }

    // ---- Unified incoming message handler ------------------------------

    /// Process any incoming file-protocol message (both directions).
    ///
    /// `enc_key` is the shared session encryption key, required to decrypt
    /// chunks; pass `None` if no session key is available yet.
    ///
    /// Returns a JSON object describing what happened, with these `kind`s:
    ///   "request"       incoming offer awaiting consent { fileId, fileName, fileSize, fileType }
    ///   "response"      peer accepted/rejected our offer { fileId, accepted }
    ///   "progress"      a chunk was received             { fileId, received, total }
    ///   "complete"      file fully received & verified    { fileId, fileName, fileType, fileSize, dataB64 }
    ///   "ack"           peer confirmed a chunk we sent    { fileId, confirmed, total }
    ///   "sent"          peer reported our send finished   { fileId, success }
    ///   "ignored"       duplicate/irrelevant message      { fileId }
    /// Any result may carry a `"send"` array of messages the platform must
    /// transmit back to the peer over the data channel.
    pub fn handle_incoming(
        &mut self,
        message: &Value,
        enc_key: Option<&[u8]>,
    ) -> Result<Value, String> {
        let msg_type = message
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Message missing 'type'".to_string())?;

        match msg_type {
            "file_transfer_start" => self.on_start(message),
            "file_transfer_response" => self.on_response(message),
            "file_chunk" => self.on_chunk(message, enc_key),
            "chunk_confirmation" => self.on_chunk_confirmation(message),
            "file_transfer_complete" => self.on_transfer_complete(message),
            other => Err(format!("Unknown file message type: {}", other)),
        }
    }

    fn on_start(&mut self, message: &Value) -> Result<Value, String> {
        let file_id = get_str(message, "fileId")?;
        let file_name = get_str(message, "fileName")?;
        let file_type = message
            .get("fileType")
            .and_then(|v| v.as_str())
            .unwrap_or("application/octet-stream")
            .to_string();
        let file_size = get_usize(message, "fileSize")?;
        let total_chunks = get_usize(message, "totalChunks")?;
        let file_hash = get_str(message, "fileHash")?;

        if file_size > MAX_FILE_SIZE {
            let send = json!({
                "type": "file_transfer_response",
                "fileId": file_id,
                "accepted": false,
                "error": "File exceeds maximum allowed size",
            });
            return Ok(json!({ "kind": "error", "fileId": file_id, "message": "File too large", "send": [send] }));
        }
        if total_chunks == 0 {
            return Err("Invalid transfer: zero chunks".to_string());
        }

        // Duplicate offer for an in-flight transfer: ignore.
        if self.receiving.contains_key(&file_id) {
            return Ok(json!({ "kind": "ignored", "fileId": file_id }));
        }

        self.receiving.insert(
            file_id.clone(),
            ReceivingState {
                file_name: file_name.clone(),
                file_type: file_type.clone(),
                file_size,
                total_chunks,
                file_hash,
                chunks: HashMap::new(),
                received_count: 0,
                accepted: false,
                assembled: false,
            },
        );

        Ok(json!({
            "kind": "request",
            "fileId": file_id,
            "fileName": file_name,
            "fileSize": file_size,
            "fileType": file_type,
        }))
    }

    fn on_response(&mut self, message: &Value) -> Result<Value, String> {
        let file_id = get_str(message, "fileId")?;
        let accepted = message
            .get("accepted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if let Some(state) = self.sending.get_mut(&file_id) {
            state.accepted = accepted;
            if !accepted {
                self.sending.remove(&file_id);
            }
        }

        Ok(json!({ "kind": "response", "fileId": file_id, "accepted": accepted }))
    }

    fn on_chunk(&mut self, message: &Value, enc_key: Option<&[u8]>) -> Result<Value, String> {
        let file_id = get_str(message, "fileId")?;
        let chunk_index = get_usize(message, "chunkIndex")?;
        let nonce_b64 = get_str(message, "nonce")?;
        let data_b64 = get_str(message, "data")?;

        let key = enc_key.ok_or_else(|| "No session key available to decrypt chunk".to_string())?;

        // A missing receiving state usually means the transfer already completed
        // (state removed on assembly) or was cancelled. Treat a late/duplicate
        // chunk as benign rather than an error.
        let state = match self.receiving.get_mut(&file_id) {
            Some(state) => state,
            None => return Ok(json!({ "kind": "ignored", "fileId": file_id })),
        };

        if !state.accepted {
            return Err("Chunk received before transfer was accepted".to_string());
        }
        if chunk_index >= state.total_chunks {
            return Err(format!("Chunk index {} out of range", chunk_index));
        }
        // Idempotent: a re-sent chunk is acknowledged but not re-stored.
        if state.chunks.contains_key(&chunk_index) {
            let send = json!({ "type": "chunk_confirmation", "fileId": file_id, "chunkIndex": chunk_index });
            return Ok(json!({ "kind": "ignored", "fileId": file_id, "send": [send] }));
        }

        let plaintext = decrypt_chunk(key, &nonce_b64, &data_b64)?;
        state.chunks.insert(chunk_index, plaintext);
        state.received_count += 1;

        let confirmation =
            json!({ "type": "chunk_confirmation", "fileId": file_id, "chunkIndex": chunk_index });

        if state.received_count < state.total_chunks {
            return Ok(json!({
                "kind": "progress",
                "fileId": file_id,
                "received": state.received_count,
                "total": state.total_chunks,
                "send": [confirmation],
            }));
        }

        // All chunks present — assemble exactly once.
        if state.assembled {
            return Ok(json!({ "kind": "ignored", "fileId": file_id, "send": [confirmation] }));
        }
        state.assembled = true;

        let assembled = assemble(state)?;
        let file_name = state.file_name.clone();
        let file_type = state.file_type.clone();
        let file_size = assembled.len();
        self.receiving.remove(&file_id);

        let complete_msg =
            json!({ "type": "file_transfer_complete", "fileId": file_id, "success": true });

        Ok(json!({
            "kind": "complete",
            "fileId": file_id,
            "fileName": file_name,
            "fileType": file_type,
            "fileSize": file_size,
            "dataB64": general_purpose::STANDARD.encode(&assembled),
            "send": [confirmation, complete_msg],
        }))
    }

    fn on_chunk_confirmation(&mut self, message: &Value) -> Result<Value, String> {
        let file_id = get_str(message, "fileId")?;
        if let Some(state) = self.sending.get_mut(&file_id) {
            state.confirmed_chunks += 1;
            return Ok(json!({
                "kind": "ack",
                "fileId": file_id,
                "confirmed": state.confirmed_chunks,
                "total": state.total_chunks,
            }));
        }
        Ok(json!({ "kind": "ignored", "fileId": file_id }))
    }

    fn on_transfer_complete(&mut self, message: &Value) -> Result<Value, String> {
        let file_id = get_str(message, "fileId")?;
        let success = message
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        self.sending.remove(&file_id);
        Ok(json!({ "kind": "sent", "fileId": file_id, "success": success }))
    }
}

impl Default for FileTransferManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Reassemble the received chunks into the full file and verify its hash.
fn assemble(state: &ReceivingState) -> Result<Vec<u8>, String> {
    let mut data = Vec::with_capacity(state.file_size);
    for index in 0..state.total_chunks {
        let chunk = state
            .chunks
            .get(&index)
            .ok_or_else(|| format!("Missing chunk {} during assembly", index))?;
        data.extend_from_slice(chunk);
    }

    if data.len() != state.file_size {
        return Err(format!(
            "File size mismatch: expected {}, got {}",
            state.file_size,
            data.len()
        ));
    }

    let actual_hash = hex::encode(Sha256::digest(&data));
    if actual_hash != state.file_hash {
        return Err("File integrity check failed — hash mismatch".to_string());
    }

    Ok(data)
}

fn encrypt_chunk(key: &[u8], plaintext: &[u8]) -> Result<(String, String), String> {
    if key.len() != 32 {
        return Err(format!("Invalid session key length: {} (expected 32)", key.len()));
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("Failed to create AES-GCM cipher: {}", e))?;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| format!("Failed to encrypt chunk: {}", e))?;

    Ok((
        general_purpose::STANDARD.encode(nonce_bytes),
        general_purpose::STANDARD.encode(&ciphertext),
    ))
}

fn decrypt_chunk(key: &[u8], nonce_b64: &str, data_b64: &str) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err(format!("Invalid session key length: {} (expected 32)", key.len()));
    }
    let nonce_bytes = general_purpose::STANDARD
        .decode(nonce_b64)
        .map_err(|_| "Invalid chunk nonce encoding".to_string())?;
    if nonce_bytes.len() != 12 {
        return Err(format!("Invalid nonce length: {} (expected 12)", nonce_bytes.len()));
    }
    let ciphertext = general_purpose::STANDARD
        .decode(data_b64)
        .map_err(|_| "Invalid chunk data encoding".to_string())?;

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("Failed to create AES-GCM cipher: {}", e))?;
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(&nonce_bytes);
    let nonce = Nonce::from(nonce_arr);

    cipher
        .decrypt(&nonce, ciphertext.as_slice())
        .map_err(|e| format!("Failed to decrypt chunk: {}", e))
}

fn get_str(message: &Value, field: &str) -> Result<String, String> {
    message
        .get(field)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("Missing or invalid '{}'", field))
}

fn get_usize(message: &Value, field: &str) -> Result<usize, String> {
    message
        .get(field)
        .and_then(|v| v.as_u64())
        .map(|n| n as usize)
        .ok_or_else(|| format!("Missing or invalid '{}'", field))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Vec<u8> {
        vec![7u8; 32]
    }

    /// Drive a full sender -> receiver round trip and check the bytes survive.
    #[test]
    fn full_round_trip() {
        let k = key();
        let mut sender = FileTransferManager::new();
        let mut receiver = FileTransferManager::new();

        // A multi-chunk payload (just over 2 chunks).
        let original: Vec<u8> = (0..(CHUNK_SIZE * 2 + 123)).map(|i| (i % 251) as u8).collect();

        // Sender prepares the file.
        let start = sender
            .prepare_outgoing(
                "file-1".into(),
                "photo.png".into(),
                "image/png".into(),
                original.clone(),
            )
            .unwrap();
        assert_eq!(start["totalChunks"], 3);

        // Receiver sees the offer and accepts.
        let req = receiver.handle_incoming(&start, Some(&k)).unwrap();
        assert_eq!(req["kind"], "request");
        let response = receiver.accept("file-1").unwrap();

        // Sender processes the acceptance.
        let resp_event = sender.handle_incoming(&response, Some(&k)).unwrap();
        assert_eq!(resp_event["kind"], "response");
        assert_eq!(resp_event["accepted"], true);

        // Stream every chunk to the receiver.
        let mut completed: Option<Vec<u8>> = None;
        while let Some(chunk) = sender.next_chunk("file-1", &k).unwrap() {
            let event = receiver.handle_incoming(&chunk, Some(&k)).unwrap();
            match event["kind"].as_str().unwrap() {
                "progress" => {}
                "complete" => {
                    let b64 = event["dataB64"].as_str().unwrap();
                    completed = Some(general_purpose::STANDARD.decode(b64).unwrap());
                }
                other => panic!("unexpected event: {}", other),
            }
        }

        assert_eq!(completed.unwrap(), original);
    }

    #[test]
    fn rejection_stops_transfer() {
        let k = key();
        let mut sender = FileTransferManager::new();
        let mut receiver = FileTransferManager::new();

        let start = sender
            .prepare_outgoing("f".into(), "a.txt".into(), "text/plain".into(), vec![1, 2, 3])
            .unwrap();
        receiver.handle_incoming(&start, Some(&k)).unwrap();
        let rejection = receiver.reject("f", "not now").unwrap();
        let event = sender.handle_incoming(&rejection, Some(&k)).unwrap();
        assert_eq!(event["accepted"], false);

        // No chunk may be produced after rejection.
        assert!(sender.next_chunk("f", &k).is_err());
    }

    #[test]
    fn duplicate_chunk_is_idempotent() {
        let k = key();
        let mut sender = FileTransferManager::new();
        let mut receiver = FileTransferManager::new();

        let original = vec![9u8; 100];
        let start = sender
            .prepare_outgoing("f".into(), "a.bin".into(), "application/octet-stream".into(), original.clone())
            .unwrap();
        receiver.handle_incoming(&start, Some(&k)).unwrap();
        receiver.accept("f").unwrap();
        sender.handle_incoming(&receiver.accept("f").unwrap(), Some(&k)).unwrap();

        let chunk = sender.next_chunk("f", &k).unwrap().unwrap();
        let first = receiver.handle_incoming(&chunk, Some(&k)).unwrap();
        assert_eq!(first["kind"], "complete");
        // Re-delivering the same (and only) chunk must not produce a second file.
        let second = receiver.handle_incoming(&chunk, Some(&k)).unwrap();
        assert_eq!(second["kind"], "ignored");
    }

    #[test]
    fn corrupted_chunk_fails_decryption() {
        let k = key();
        let mut sender = FileTransferManager::new();
        let mut receiver = FileTransferManager::new();

        let start = sender
            .prepare_outgoing("f".into(), "a.bin".into(), "application/octet-stream".into(), vec![5u8; 50])
            .unwrap();
        receiver.handle_incoming(&start, Some(&k)).unwrap();
        sender.handle_incoming(&receiver.accept("f").unwrap(), Some(&k)).unwrap();

        let mut chunk = sender.next_chunk("f", &k).unwrap().unwrap();
        // Tamper with the ciphertext.
        chunk["data"] = json!("AAAAAAAAAAAAAAAAAAAAAA==");
        assert!(receiver.handle_incoming(&chunk, Some(&k)).is_err());
    }
}
