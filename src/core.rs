// Core struct that owns all internal state
use crate::crypto::CryptoUtils;
use crate::session::{OfferContext, SessionKeys};
use std::sync::{Arc, Mutex};

/// Core struct that owns all internal state (crypto, sessions, WebRTC)
/// This is the main entry point for the platform-agnostic core crate
pub struct Core {
    crypto: Arc<Mutex<CryptoUtils>>,
    offer_state: Arc<Mutex<OfferContext>>,
    session_keys: Arc<Mutex<SessionKeys>>,
}

impl Core {
    /// Create a new Core instance with initialized state
    pub fn new() -> Self {
        Self {
            crypto: Arc::new(Mutex::new(CryptoUtils::new())),
            offer_state: Arc::new(Mutex::new(OfferContext::new())),
            session_keys: Arc::new(Mutex::new(SessionKeys::new())),
        }
    }

    /// Get a reference to the crypto state
    pub fn crypto(&self) -> Arc<Mutex<CryptoUtils>> {
        self.crypto.clone()
    }

    /// Get a reference to the offer state
    pub fn offer_state(&self) -> Arc<Mutex<OfferContext>> {
        self.offer_state.clone()
    }

    /// Get a reference to the session keys
    pub fn session_keys(&self) -> Arc<Mutex<SessionKeys>> {
        self.session_keys.clone()
    }

    // Crypto methods
    pub fn generate_key_pair(&self) -> Result<String, String> {
        let mut crypto = self.crypto.lock()
            .map_err(|_| "Failed to acquire crypto lock".to_string())?;
        crypto.generate_key_pair()
    }

    pub fn encrypt_data(&self, data: &str, key_id: &str) -> Result<String, String> {
        let crypto = self.crypto.lock()
            .map_err(|_| "Failed to acquire crypto lock".to_string())?;
        let encrypted = crypto.encrypt_data(data, key_id)?;
        serde_json::to_string(&encrypted).map_err(|e| e.to_string())
    }

    pub fn decrypt_data(&self, encrypted_data: &str) -> Result<String, String> {
        let crypto = self.crypto.lock()
            .map_err(|_| "Failed to acquire crypto lock".to_string())?;
        let encrypted: crate::crypto::EncryptedData = serde_json::from_str(encrypted_data)
            .map_err(|e| e.to_string())?;
        crypto.decrypt_data(&encrypted)
    }

    pub fn get_security_level(&self) -> Result<String, String> {
        let crypto = self.crypto.lock()
            .map_err(|_| "Failed to acquire crypto lock".to_string())?;
        let security = crypto.calculate_security_level();
        serde_json::to_string(&security).map_err(|e| e.to_string())
    }

    pub fn generate_secure_password(&self, length: usize) -> Result<String, String> {
        let crypto = self.crypto.lock()
            .map_err(|_| "Failed to acquire crypto lock".to_string())?;
        Ok(crypto.generate_secure_password(length))
    }

    // WebRTC methods
    pub fn create_secure_offer(&self, offer_sdp: Option<String>) -> Result<String, String> {
        crate::webrtc::create_secure_offer(self.offer_state.clone(), offer_sdp)
            .map_err(|e| e.to_string())
    }

    pub fn create_secure_answer(&self, offer_data: String, answer_sdp: Option<String>) -> Result<String, String> {
        crate::webrtc::create_secure_answer(self.offer_state.clone(), offer_data, answer_sdp)
            .map_err(|e| e.to_string())
    }

    pub fn parse_secure_offer(&self, offer_data: String) -> Result<String, String> {
        crate::webrtc::parse_secure_offer(offer_data)
            .map_err(|e| e.to_string())
    }

    pub fn join_secure_connection(&self, offer_data: String, answer_sdp: Option<String>) -> Result<String, String> {
        crate::webrtc::join_secure_connection(
            self.offer_state.clone(),
            self.session_keys.clone(),
            offer_data,
            answer_sdp
        )
        .map_err(|e| e.to_string())
    }

    pub fn handle_secure_answer(&self, answer_data: String) -> Result<String, String> {
        crate::webrtc::handle_secure_answer(
            self.offer_state.clone(),
            self.session_keys.clone(),
            answer_data
        )
        .map_err(|e| e.to_string())
    }

    // Session methods
    pub fn encrypt_enhanced_message(&self, message: String, message_id: String, sequence_number: u64) -> Result<String, String> {
        let result = crate::session::encrypt_enhanced_message(
            self.session_keys.clone(),
            message,
            message_id,
            sequence_number
        )?;
        serde_json::to_string(&result).map_err(|e| e.to_string())
    }

    pub fn decrypt_enhanced_message(&self, encrypted_message: String) -> Result<String, String> {
        let message_data: serde_json::Value = serde_json::from_str(&encrypted_message)
            .map_err(|e| format!("Failed to parse encrypted message: {}", e))?;
        let result = crate::session::decrypt_enhanced_message(
            self.session_keys.clone(),
            message_data
        )?;
        serde_json::to_string(&result).map_err(|e| e.to_string())
    }
}

impl Default for Core {
    fn default() -> Self {
        Self::new()
    }
}

