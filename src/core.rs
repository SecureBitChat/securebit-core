// Core struct that owns all internal state
use crate::crypto::CryptoUtils;
use crate::file_transfer::{AssembledFile, FileTransferManager, TransferCrypto};
use crate::session::{OfferContext, SessionKeys};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// The default session id used when a caller does not specify one. Keeps the
/// original single-session behaviour working unchanged while multi-session
/// callers pass their own ids.
pub const DEFAULT_SESSION: &str = "default";

/// All cryptographic + transfer state for ONE peer connection (one "chat").
///
/// This is the unit of multi-session: every open chat owns an isolated
/// `Session`, so their keys, handshakes and file transfers never mix. The type
/// is platform-agnostic — desktop (Tauri) and mobile share it verbatim.
pub struct Session {
    crypto: Arc<Mutex<CryptoUtils>>,
    offer_state: Arc<Mutex<OfferContext>>,
    session_keys: Arc<Mutex<SessionKeys>>,
    file_transfer: Arc<Mutex<FileTransferManager>>,
}

impl Session {
    fn new() -> Self {
        Self {
            crypto: Arc::new(Mutex::new(CryptoUtils::new())),
            offer_state: Arc::new(Mutex::new(OfferContext::new())),
            session_keys: Arc::new(Mutex::new(SessionKeys::new())),
            file_transfer: Arc::new(Mutex::new(FileTransferManager::new())),
        }
    }

    pub fn crypto(&self) -> Arc<Mutex<CryptoUtils>> { self.crypto.clone() }
    pub fn offer_state(&self) -> Arc<Mutex<OfferContext>> { self.offer_state.clone() }
    pub fn session_keys(&self) -> Arc<Mutex<SessionKeys>> { self.session_keys.clone() }
    pub fn file_transfer(&self) -> Arc<Mutex<FileTransferManager>> { self.file_transfer.clone() }

    /// Snapshot the shared session encryption key (32 bytes) used for chunks.
    #[allow(dead_code)]
    fn session_encryption_key(&self) -> Option<Vec<u8>> {
        self.session_keys
            .lock()
            .ok()
            .and_then(|keys| keys.encryption_key.clone())
    }

    /// The handshake-derived inputs every per-file transfer key is built from.
    ///
    /// Both are read off this session, never off the wire: the key fingerprint
    /// each peer computed independently, and the session salt they agreed on.
    fn transfer_crypto(&self) -> Result<TransferCrypto, String> {
        let fingerprint = self
            .session_keys
            .lock()
            .map_err(|_| "Failed to acquire session key lock".to_string())?
            .key_fingerprint
            .clone()
            .ok_or_else(|| "Session crypto not ready (complete the handshake first)".to_string())?;
        let salt = self
            .offer_state
            .lock()
            .map_err(|_| "Failed to acquire offer state lock".to_string())?
            .session_salt
            .clone()
            .ok_or_else(|| "Session crypto not ready (no session salt)".to_string())?;
        TransferCrypto::new(fingerprint, salt)
    }

    /// Securely wipe every secret this session holds (keys, handshake material)
    /// and drop any in-flight file transfers. Called on disconnect / close.
    pub fn clear_secrets(&self) {
        if let Ok(mut state) = self.offer_state.lock() {
            state.ecdh_secret = None;
            state.session_salt = None;
            state.local_dtls_fingerprint = None;
        }
        if let Ok(mut keys) = self.session_keys.lock() {
            if let Some(ref mut k) = keys.encryption_key { for byte in k.iter_mut() { *byte = 0; } }
            if let Some(ref mut k) = keys.mac_key { for byte in k.iter_mut() { *byte = 0; } }
            if let Some(ref mut k) = keys.metadata_key { for byte in k.iter_mut() { *byte = 0; } }
            keys.encryption_key = None;
            keys.mac_key = None;
            keys.metadata_key = None;
            // The ratchet holds the only raw chain/root key material in the
            // session; its Drop impl zeroizes every key it retains.
            keys.ratchet = None;
            keys.peer_supports_ratchet = false;
        }
        if let Ok(mut manager) = self.file_transfer.lock() {
            manager.clear();
        }
    }

    /// Report what handshake / key material this session currently holds.
    pub fn connection_state(&self) -> serde_json::Value {
        let state = self.offer_state.lock().ok();
        let keys = self.session_keys.lock().ok();
        let has_ecdh = state.as_ref().map(|s| s.ecdh_secret.is_some()).unwrap_or(false);
        let has_salt = state.as_ref().map(|s| s.session_salt.is_some()).unwrap_or(false);
        let has_fp = state.as_ref().map(|s| s.local_dtls_fingerprint.is_some()).unwrap_or(false);
        let has_enc = keys.as_ref().map(|k| k.encryption_key.is_some()).unwrap_or(false);
        let has_mac = keys.as_ref().map(|k| k.mac_key.is_some()).unwrap_or(false);
        let has_meta = keys.as_ref().map(|k| k.metadata_key.is_some()).unwrap_or(false);
        serde_json::json!({
            "has_offer_state": has_ecdh || has_salt,
            "has_session_keys": has_enc || has_mac,
            "has_ecdh_secret": has_ecdh,
            "has_session_salt": has_salt,
            "has_local_dtls_fingerprint": has_fp,
            "has_encryption_key": has_enc,
            "has_mac_key": has_mac,
            "has_metadata_key": has_meta,
        })
    }
}

/// Core owns a registry of sessions keyed by id. This is the main entry point
/// for the platform-agnostic core crate; every platform (desktop/mobile) drives
/// multi-session chat entirely through these methods.
pub struct Core {
    sessions: Arc<Mutex<HashMap<String, Arc<Session>>>>,
}

impl Core {
    /// Create a new Core with a single "default" session ready to use.
    pub fn new() -> Self {
        let mut map = HashMap::new();
        map.insert(DEFAULT_SESSION.to_string(), Arc::new(Session::new()));
        Self { sessions: Arc::new(Mutex::new(map)) }
    }

    /// Resolve a session by id, lazily creating it if it does not exist.
    /// `None` maps to the default session (back-compat for single-session code).
    fn session(&self, session_id: Option<&str>) -> Arc<Session> {
        let id = session_id.unwrap_or(DEFAULT_SESSION).to_string();
        let mut map = self.sessions.lock().expect("sessions lock poisoned");
        map.entry(id).or_insert_with(|| Arc::new(Session::new())).clone()
    }

    // ---- session lifecycle ----

    /// Explicitly create a session (no-op if it already exists).
    pub fn create_session(&self, session_id: &str) -> Result<(), String> {
        let mut map = self.sessions.lock().map_err(|_| "sessions lock poisoned".to_string())?;
        map.entry(session_id.to_string()).or_insert_with(|| Arc::new(Session::new()));
        Ok(())
    }

    /// Wipe a session's secrets and remove it from the registry.
    pub fn close_session(&self, session_id: &str) -> Result<(), String> {
        let existing = {
            let map = self.sessions.lock().map_err(|_| "sessions lock poisoned".to_string())?;
            map.get(session_id).cloned()
        };
        if let Some(sess) = existing {
            sess.clear_secrets();
        }
        let mut map = self.sessions.lock().map_err(|_| "sessions lock poisoned".to_string())?;
        map.remove(session_id);
        Ok(())
    }

    /// List all live session ids.
    pub fn list_sessions(&self) -> Vec<String> {
        self.sessions
            .lock()
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Clear a session's secrets in place (keeps it in the registry so the tab
    /// can be reused for a fresh handshake).
    pub fn disconnect_session(&self, session_id: Option<&str>) -> Result<(), String> {
        self.session(session_id).clear_secrets();
        Ok(())
    }

    pub fn get_connection_state(&self, session_id: Option<&str>) -> serde_json::Value {
        self.session(session_id).connection_state()
    }

    /// Web-compatible file-transfer crypto inputs for the JS layer: the key
    /// fingerprint ("safety number") and the raw session salt. The JS file/voice
    /// transfer derives per-file keys from these exactly like the web client.
    pub fn get_session_crypto(&self, session_id: Option<&str>) -> serde_json::Value {
        let s = self.session(session_id);
        let (fingerprint, verification_code) = s
            .session_keys()
            .lock()
            .ok()
            .map(|k| (k.key_fingerprint.clone(), k.verification_code.clone()))
            .unwrap_or((None, None));
        let session_salt = s.offer_state().lock().ok().and_then(|st| st.session_salt.clone());
        serde_json::json!({
            "fingerprint": fingerprint,
            "sessionSalt": session_salt,
            // SAS derived locally from the shared secret — never taken from the wire.
            "verificationCode": verification_code,
        })
    }

    // ---- accessors (default session, kept for compatibility) ----
    pub fn file_transfer(&self) -> Arc<Mutex<FileTransferManager>> { self.session(None).file_transfer() }
    pub fn crypto(&self) -> Arc<Mutex<CryptoUtils>> { self.session(None).crypto() }
    pub fn offer_state(&self) -> Arc<Mutex<OfferContext>> { self.session(None).offer_state() }
    pub fn session_keys(&self) -> Arc<Mutex<SessionKeys>> { self.session(None).session_keys() }

    // ---- crypto methods ----
    pub fn generate_key_pair(&self, session_id: Option<&str>) -> Result<String, String> {
        let s = self.session(session_id);
        let mut crypto = s.crypto.lock().map_err(|_| "Failed to acquire crypto lock".to_string())?;
        crypto.generate_key_pair()
    }

    pub fn encrypt_data(&self, session_id: Option<&str>, data: &str, key_id: &str) -> Result<String, String> {
        let s = self.session(session_id);
        let crypto = s.crypto.lock().map_err(|_| "Failed to acquire crypto lock".to_string())?;
        let encrypted = crypto.encrypt_data(data, key_id)?;
        serde_json::to_string(&encrypted).map_err(|e| e.to_string())
    }

    pub fn decrypt_data(&self, session_id: Option<&str>, encrypted_data: &str) -> Result<String, String> {
        let s = self.session(session_id);
        let crypto = s.crypto.lock().map_err(|_| "Failed to acquire crypto lock".to_string())?;
        let encrypted: crate::crypto::EncryptedData = serde_json::from_str(encrypted_data).map_err(|e| e.to_string())?;
        crypto.decrypt_data(&encrypted)
    }

    pub fn get_security_level(&self, session_id: Option<&str>) -> Result<String, String> {
        let s = self.session(session_id);
        let crypto = s.crypto.lock().map_err(|_| "Failed to acquire crypto lock".to_string())?;
        let security = crypto.calculate_security_level();
        serde_json::to_string(&security).map_err(|e| e.to_string())
    }

    pub fn generate_secure_password(&self, session_id: Option<&str>, length: usize) -> Result<String, String> {
        let s = self.session(session_id);
        let crypto = s.crypto.lock().map_err(|_| "Failed to acquire crypto lock".to_string())?;
        Ok(crypto.generate_secure_password(length))
    }

    // ---- WebRTC methods ----
    pub fn create_secure_offer(&self, session_id: Option<&str>, offer_sdp: Option<String>) -> Result<String, String> {
        let s = self.session(session_id);
        crate::webrtc::create_secure_offer(s.offer_state.clone(), offer_sdp).map_err(|e| e.to_string())
    }

    pub fn create_secure_answer(&self, session_id: Option<&str>, offer_data: String, answer_sdp: Option<String>) -> Result<String, String> {
        let s = self.session(session_id);
        crate::webrtc::create_secure_answer(s.offer_state.clone(), offer_data, answer_sdp).map_err(|e| e.to_string())
    }

    pub fn parse_secure_offer(&self, offer_data: String) -> Result<String, String> {
        crate::webrtc::parse_secure_offer(offer_data).map_err(|e| e.to_string())
    }

    pub fn join_secure_connection(&self, session_id: Option<&str>, offer_data: String, answer_sdp: Option<String>) -> Result<String, String> {
        let s = self.session(session_id);
        crate::webrtc::join_secure_connection(s.offer_state.clone(), s.session_keys.clone(), offer_data, answer_sdp)
            .map_err(|e| e.to_string())
    }

    pub fn handle_secure_answer(&self, session_id: Option<&str>, answer_data: String) -> Result<String, String> {
        let s = self.session(session_id);
        crate::webrtc::handle_secure_answer(s.offer_state.clone(), s.session_keys.clone(), answer_data)
            .map_err(|e| e.to_string())
    }

    // ---- session (messaging) methods ----
    pub fn encrypt_enhanced_message(&self, session_id: Option<&str>, message: String, message_id: String, sequence_number: u64) -> Result<String, String> {
        let s = self.session(session_id);
        let result = crate::session::encrypt_enhanced_message(s.session_keys.clone(), message, message_id, sequence_number)?;
        serde_json::to_string(&result).map_err(|e| e.to_string())
    }

    pub fn decrypt_enhanced_message(&self, session_id: Option<&str>, encrypted_message: String) -> Result<String, String> {
        let s = self.session(session_id);
        let message_data: serde_json::Value = serde_json::from_str(&encrypted_message)
            .map_err(|e| format!("Failed to parse encrypted message: {}", e))?;
        let result = crate::session::decrypt_enhanced_message(s.session_keys.clone(), message_data)?;
        serde_json::to_string(&result).map_err(|e| e.to_string())
    }

    /// Encrypt one outbound chat payload into the complete wire frame —
    /// `ratchet_message` when the Double Ratchet has a sending chain, otherwise
    /// the static `enhanced_message` envelope (see session::encrypt_chat_frame).
    pub fn encrypt_chat_frame(&self, session_id: Option<&str>, message: String, message_id: String, sequence_number: u64) -> Result<String, String> {
        let s = self.session(session_id);
        let frame = crate::session::encrypt_chat_frame(s.session_keys.clone(), message, message_id, sequence_number)?;
        serde_json::to_string(&frame).map_err(|e| e.to_string())
    }

    /// Decrypt an inbound `ratchet_message` frame. `header` must be the exact
    /// string off the wire — it is the AES-GCM AAD.
    pub fn decrypt_ratchet_message(&self, session_id: Option<&str>, header: String, ciphertext: String) -> Result<String, String> {
        let s = self.session(session_id);
        let result = crate::session::decrypt_ratchet_message(s.session_keys.clone(), &header, &ciphertext)?;
        serde_json::to_string(&result).map_err(|e| e.to_string())
    }

    /// What protection the message path is actually running, measured off the
    /// live session state — for the UI's security panel.
    pub fn ratchet_status(&self, session_id: Option<&str>) -> Result<String, String> {
        let s = self.session(session_id);
        let status = crate::session::ratchet_status(s.session_keys.clone());
        serde_json::to_string(&status).map_err(|e| e.to_string())
    }

    // ---- file transfer methods ----

    /// Register an outgoing file from raw bytes.
    ///
    /// Preferred over the base64 entry point on memory-constrained platforms: a
    /// 100 MB file costs ~133 MB more as base64, and both copies would be live
    /// at once.
    #[allow(clippy::too_many_arguments)]
    pub fn file_prepare_outgoing_bytes(
        &self,
        session_id: Option<&str>,
        file_id: String,
        file_name: String,
        file_type: String,
        data: Vec<u8>,
        is_voice: bool,
        voice_json: Option<String>,
    ) -> Result<String, String> {
        let s = self.session(session_id);
        let crypto = s.transfer_crypto()?;
        let voice = match voice_json {
            Some(text) if !text.trim().is_empty() => Some(
                serde_json::from_str(&text)
                    .map_err(|e| format!("Failed to parse voice descriptor: {}", e))?,
            ),
            _ => None,
        };
        let mut manager = s.file_transfer.lock().map_err(|_| "Lock poisoned".to_string())?;
        let start = manager.prepare_outgoing(file_id, file_name, file_type, data, is_voice, voice, &crypto)?;
        serde_json::to_string(&start).map_err(|e| e.to_string())
    }

    pub fn file_prepare_outgoing(&self, session_id: Option<&str>, file_id: String, file_name: String, file_type: String, data_base64: String) -> Result<String, String> {
        use base64::{engine::general_purpose, Engine as _};
        let data = general_purpose::STANDARD.decode(data_base64.trim()).map_err(|_| "Invalid base64 file data".to_string())?;
        self.file_prepare_outgoing_bytes(session_id, file_id, file_name, file_type, data, false, None)
    }

    /// The next chunk of an accepted transfer, or `"null"` when done.
    pub fn file_next_chunk(&self, session_id: Option<&str>, file_id: String) -> Result<String, String> {
        let s = self.session(session_id);
        let mut manager = s.file_transfer.lock().map_err(|_| "Lock poisoned".to_string())?;
        let chunk = manager.next_chunk(&file_id)?;
        serde_json::to_string(&chunk).map_err(|e| e.to_string())
    }

    /// Re-emit one chunk the peer asked for again (loss recovery).
    pub fn file_chunk_at(&self, session_id: Option<&str>, file_id: String, index: usize) -> Result<String, String> {
        let s = self.session(session_id);
        let mut manager = s.file_transfer.lock().map_err(|_| "Lock poisoned".to_string())?;
        let chunk = manager.chunk_at(&file_id, index)?;
        serde_json::to_string(&chunk).map_err(|e| e.to_string())
    }

    pub fn file_handle_incoming(&self, session_id: Option<&str>, message_json: String) -> Result<String, String> {
        let s = self.session(session_id);
        let message: serde_json::Value = serde_json::from_str(&message_json).map_err(|e| format!("Failed to parse file message: {}", e))?;
        let mut manager = s.file_transfer.lock().map_err(|_| "Lock poisoned".to_string())?;
        let event = manager.handle_incoming(&message)?;
        serde_json::to_string(&event).map_err(|e| e.to_string())
    }

    pub fn file_accept(&self, session_id: Option<&str>, file_id: String) -> Result<String, String> {
        let s = self.session(session_id);
        let crypto = s.transfer_crypto()?;
        let mut manager = s.file_transfer.lock().map_err(|_| "Lock poisoned".to_string())?;
        let response = manager.accept(&file_id, &crypto)?;
        serde_json::to_string(&response).map_err(|e| e.to_string())
    }

    /// Ask the peer to resend whatever an incoming transfer still lacks.
    /// Returns `"null"` when nothing is missing.
    pub fn file_request_missing(&self, session_id: Option<&str>, file_id: String) -> Result<String, String> {
        let s = self.session(session_id);
        let manager = s.file_transfer.lock().map_err(|_| "Lock poisoned".to_string())?;
        serde_json::to_string(&manager.request_missing(&file_id)).map_err(|e| e.to_string())
    }

    /// Collect a completed incoming file's bytes, exactly once.
    pub fn file_take_assembled(&self, session_id: Option<&str>, file_id: &str) -> Result<AssembledFile, String> {
        let s = self.session(session_id);
        let mut manager = s.file_transfer.lock().map_err(|_| "Lock poisoned".to_string())?;
        manager
            .take_assembled(file_id)
            .ok_or_else(|| "No assembled file with that id".to_string())
    }

    /// The `file_transfer_error` frame telling the peer we are giving up.
    pub fn file_error_message(&self, file_id: &str, reason: &str) -> Result<String, String> {
        serde_json::to_string(&FileTransferManager::error_message(file_id, reason))
            .map_err(|e| e.to_string())
    }

    pub fn file_reject(&self, session_id: Option<&str>, file_id: String, reason: String) -> Result<String, String> {
        let s = self.session(session_id);
        let mut manager = s.file_transfer.lock().map_err(|_| "Lock poisoned".to_string())?;
        let response = manager.reject(&file_id, &reason)?;
        serde_json::to_string(&response).map_err(|e| e.to_string())
    }

    pub fn file_cancel(&self, session_id: Option<&str>, file_id: String) -> Result<(), String> {
        let s = self.session(session_id);
        let mut manager = s.file_transfer.lock().map_err(|_| "Lock poisoned".to_string())?;
        manager.cancel(&file_id);
        Ok(())
    }

    pub fn file_clear(&self, session_id: Option<&str>) {
        let ft = self.session(session_id).file_transfer();
        let locked = ft.lock();
        if let Ok(mut manager) = locked {
            manager.clear();
        }
    }
}

impl Default for Core {
    fn default() -> Self {
        Self::new()
    }
}
