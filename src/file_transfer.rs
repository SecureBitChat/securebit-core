// Platform-agnostic secure file transfer — web-compatible ("SBWT") wire format.
//
// This module owns the *protocol* of sending and receiving files over an
// already-established secure channel. It is deliberately free of any I/O or
// transport: the platform layer (Tauri webview, native mobile, ...) picks,
// reads and saves files, and moves the JSON protocol messages produced here
// over the WebRTC data channel.
//
// # Wire compatibility
//
// The message shapes below are a *contract* with the SecureBit web client
// (`EnhancedSecureFileTransfer.js`) and with the desktop client, which speaks
// the same protocol from its webview. Do not rename or restructure anything
// here to suit a platform: a field that differs by one character makes this
// peer unable to exchange files with every existing client.
//
// The wrappers travel as PLAINTEXT JSON on the data channel — only the chunk
// payload is encrypted. That is what the web does, and matching it is why an
// iOS peer is indistinguishable from a browser peer on the wire.
//
// Per-file key (see [`crate::file_crypto`], which is verified against reference
// vectors produced by the browser's WebCrypto):
//
//   fileKey = SHA-256( utf8(keyFingerprint) ‖ sessionSalt ‖ fileSalt(32) ‖ utf8(fileId) )
//
// Every chunk is AES-256-GCM under that key with a fresh random 12-byte nonce.
// Deriving per file — rather than using the session key directly — means a
// single leaked file key never exposes the chat or any other transfer.
//
// Protocol messages (all JSON, camelCase to match the JS side):
//   file_transfer_start    { fileId, fileName, fileSize, fileType, fileHash,
//                            totalChunks, chunkSize, salt[32], timestamp,
//                            version, isVoice?, voice? }
//   file_transfer_response { fileId, accepted, error?, timestamp }
//   file_chunk             { fileId, chunkIndex, totalChunks, nonce[12],
//                            encryptedDataB64, chunkSize, timestamp }
//   chunk_confirmation     { fileId, chunkIndex, timestamp }
//   file_chunk_request     { fileId, missing[], timestamp }   (loss recovery)
//   file_transfer_complete { fileId, success, error?, timestamp }
//   file_transfer_error    { fileId, error, timestamp }

use crate::file_crypto::{decrypt_chunk, derive_file_key, encrypt_chunk};
use base64::{engine::general_purpose, Engine as _};
use rand::Rng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Instant;

/// Raw bytes per chunk before encryption. 16 KB matches the web's `CHUNK_SIZE`
/// and keeps the on-the-wire (AES-GCM + Base64) message near 22 KB, well under
/// the 64 KB SCTP message-size floor some peers enforce.
pub const CHUNK_SIZE: usize = 16 * 1024;

/// Largest chunk we will *accept*. Older peers may use a bigger chunk than we
/// send, so the receive path is deliberately more permissive than the send path.
pub const MAX_RECEIVE_CHUNK: usize = 64 * 1024;

/// Hard ceiling on a single file, matching the web client.
pub const MAX_FILE_SIZE: usize = 100 * 1024 * 1024;

/// Concurrency caps, matching the web client.
pub const MAX_CONCURRENT_TRANSFERS: usize = 3;
pub const MAX_PENDING_INCOMING: usize = 3;

/// Protocol version stamped on `file_transfer_start`.
pub const PROTOCOL_VERSION: &str = "2.0";

/// Most chunks a receiver will name in one `file_chunk_request`, and most a
/// sender will honour from one. Bounds the work a peer can ask for per message.
const MAX_MISSING_PER_REQUEST: usize = 256;
const MAX_RETRANSMIT_PER_REQUEST: usize = 512;

// ---------------------------------------------------------------------------
// key material
// ---------------------------------------------------------------------------

/// The session-derived inputs every per-file key is built from.
///
/// Both values come from the completed handshake: the caller reads them off the
/// session rather than the wire, so a peer cannot steer our key derivation.
#[derive(Clone)]
pub struct TransferCrypto {
    /// Colon-hex "safety number" both peers computed independently.
    pub key_fingerprint: String,
    /// The 64-byte session salt agreed during the handshake.
    pub session_salt: Vec<u8>,
}

impl TransferCrypto {
    pub fn new(key_fingerprint: String, session_salt: Vec<u8>) -> Result<Self, String> {
        if key_fingerprint.is_empty() {
            return Err("Session crypto not ready (no key fingerprint)".to_string());
        }
        if session_salt.is_empty() {
            return Err("Session crypto not ready (no session salt)".to_string());
        }
        Ok(Self { key_fingerprint, session_salt })
    }

    fn file_key(&self, file_salt: &[u8], file_id: &str) -> [u8; 32] {
        derive_file_key(&self.key_fingerprint, &self.session_salt, file_salt, file_id)
    }
}

// ---------------------------------------------------------------------------
// file-type policy (byte-for-byte the web's FILE_TYPE_RESTRICTIONS)
// ---------------------------------------------------------------------------

/// One allow-listed category. The *extension* is the security boundary; MIME is
/// advisory, because browsers and operating systems disagree on it and it is
/// frequently absent.
struct TypeRule {
    extensions: &'static [&'static str],
    mime_types: &'static [&'static str],
    max_size: usize,
    category: &'static str,
    description: &'static str,
}

const TYPE_RULES: &[TypeRule] = &[
    TypeRule {
        extensions: &[".pdf"],
        mime_types: &["application/pdf", "application/x-pdf", "application/acrobat"],
        max_size: 50 * 1024 * 1024,
        category: "PDF",
        description: "PDF",
    },
    TypeRule {
        extensions: &[".txt"],
        mime_types: &["text/plain", "application/txt"],
        max_size: 10 * 1024 * 1024,
        category: "Plain text",
        description: "TXT",
    },
    TypeRule {
        extensions: &[".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".ico"],
        mime_types: &[
            "image/jpeg", "image/jpg", "image/pjpeg", "image/png", "image/gif",
            "image/webp", "image/bmp", "image/x-windows-bmp", "image/x-icon",
            "image/vnd.microsoft.icon",
        ],
        max_size: 25 * 1024 * 1024,
        category: "Images",
        description: "JPG, JPEG, PNG, GIF, WEBP, BMP, ICO",
    },
    TypeRule {
        extensions: &[".zip"],
        mime_types: &[
            "application/zip", "application/x-zip", "application/x-zip-compressed",
            "multipart/x-zip",
        ],
        max_size: 100 * 1024 * 1024,
        category: "Archives",
        description: "ZIP",
    },
    TypeRule {
        extensions: &[".webm", ".ogg", ".oga", ".opus", ".m4a", ".mp4", ".mp3", ".wav"],
        mime_types: &[
            "audio/webm", "audio/ogg", "audio/opus", "audio/mp4", "audio/mpeg",
            "audio/mp3", "audio/wav", "audio/x-m4a", "audio/aac",
        ],
        max_size: 20 * 1024 * 1024,
        category: "Voice",
        description: "Voice messages",
    },
];

/// Extensions refused outright, regardless of category. Executable and
/// active-content formats: delivering one to a peer's disk is the payload half
/// of most social-engineering attacks.
const BLOCKED_EXTENSIONS: &[&str] = &[
    ".exe", ".bat", ".cmd", ".sh", ".js", ".msi", ".dmg", ".app", ".jar", ".scr",
    ".ps1", ".vbs", ".html", ".svg",
];

/// MIME values that carry no information, so they never count as a mismatch.
const GENERIC_MIME: &[&str] = &["application/octet-stream", "application/binary"];

const UNSUPPORTED_DESCRIPTION: &str =
    "Allowed: JPG, JPEG, PNG, GIF, WEBP, BMP, ICO, PDF, TXT, ZIP";

/// The lowercase extension of `name`, including the dot ("" when there is none).
fn extension_of(name: &str) -> String {
    let lower = name.to_lowercase();
    match lower.rfind('.') {
        Some(index) => lower[index..].to_string(),
        None => String::new(),
    }
}

struct ResolvedType {
    max_size: usize,
    category: &'static str,
    description: &'static str,
    allowed: bool,
    extension: String,
}

/// Resolve a file to its allow-list category, mirroring the web's `getFileType`.
///
/// A blatantly foreign MIME is treated as a spoofing signal and rejected, but an
/// absent or generic one is tolerated — that is the common, honest case.
fn resolve_type(name: &str, mime: &str) -> ResolvedType {
    let extension = extension_of(name);
    let mime = mime.to_lowercase();
    let known_mime: bool = TYPE_RULES
        .iter()
        .any(|rule| rule.mime_types.contains(&mime.as_str()));

    for rule in TYPE_RULES {
        if !rule.extensions.contains(&extension.as_str()) {
            continue;
        }
        if mime.is_empty() || GENERIC_MIME.contains(&mime.as_str()) || known_mime {
            return ResolvedType {
                max_size: rule.max_size,
                category: rule.category,
                description: rule.description,
                allowed: true,
                extension,
            };
        }
    }

    ResolvedType {
        max_size: MAX_FILE_SIZE,
        category: "Unsupported",
        description: UNSUPPORTED_DESCRIPTION,
        allowed: false,
        extension,
    }
}

fn format_size(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

/// Validate a file against the allow-list. Applied to *both* directions so a
/// file we accept locally is never rejected by the peer, and vice versa.
fn validate_file(name: &str, size: usize, mime: &str) -> Result<(), String> {
    let resolved = resolve_type(name, mime);
    let mut errors: Vec<String> = Vec::new();

    if BLOCKED_EXTENSIONS.contains(&resolved.extension.as_str()) {
        errors.push(format!(
            "File rejected: {} files are not allowed for security reasons.",
            resolved.extension
        ));
    }
    if size > resolved.max_size {
        errors.push(format!(
            "File size ({}) exceeds maximum allowed for {} ({})",
            format_size(size),
            resolved.category,
            format_size(resolved.max_size)
        ));
    }
    if !resolved.allowed && !BLOCKED_EXTENSIONS.contains(&resolved.extension.as_str()) {
        errors.push(format!(
            "File rejected: unsupported file type. Supported types: {}",
            resolved.description
        ));
    }
    if size > MAX_FILE_SIZE {
        errors.push(format!(
            "File size ({}) exceeds general limit ({})",
            format_size(size),
            format_size(MAX_FILE_SIZE)
        ));
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join(". "))
    }
}

/// True for C0 control characters and DEL — never legitimate in a file name and
/// the classic way to disguise one in a UI.
fn has_control_chars(text: &str) -> bool {
    text.chars().any(|c| (c as u32) < 0x20 || (c as u32) == 0x7F)
}

/// Reduce a peer-supplied name to something safe to display and to write.
///
/// Note: the web additionally applies Unicode NFKC here. We deliberately do not
/// pull in a normalisation crate for it — the security-relevant cases (control
/// characters, path separators, empty and dot names) are rejected outright by
/// [`validate_incoming_name`], and NFKC beyond that is a display nicety.
fn normalise_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .filter(|c| (*c as u32) >= 0x20 && (*c as u32) != 0x7F)
        .map(|c| if c == '\\' || c == '/' { '_' } else { c })
        .collect();
    cleaned.trim().chars().take(255).collect()
}

/// Reject a peer-supplied name that is dangerous rather than merely ugly, and
/// return the display form of a safe one.
fn validate_incoming_name(raw: &str) -> Result<String, String> {
    let display = normalise_name(raw);
    let dangerous = raw.is_empty()
        || raw != raw.trim()
        || has_control_chars(raw)
        || raw.contains('\\')
        || raw.contains('/')
        || raw == "."
        || raw == ".."
        || display.is_empty();

    if dangerous {
        Err("Dangerous file name".to_string())
    } else {
        Ok(display)
    }
}

// ---------------------------------------------------------------------------
// rate limiting (web RateLimiter, same windows)
// ---------------------------------------------------------------------------

/// Sliding-window counter. Bounds how fast a peer can make us do expensive work
/// (offers that allocate state, chunks that cost a decryption each).
struct RateLimiter {
    hits: Vec<Instant>,
    max_requests: usize,
    window_ms: u128,
}

impl RateLimiter {
    fn new(max_requests: usize, window_ms: u128) -> Self {
        Self { hits: Vec::new(), max_requests, window_ms }
    }

    fn allow(&mut self) -> bool {
        let now = Instant::now();
        let window = self.window_ms;
        self.hits
            .retain(|hit| now.duration_since(*hit).as_millis() < window);
        if self.hits.len() >= self.max_requests {
            return false;
        }
        self.hits.push(now);
        true
    }
}

// ---------------------------------------------------------------------------
// transfer state
// ---------------------------------------------------------------------------

/// Outgoing (sender) transfer state.
struct SendingState {
    data: Vec<u8>,
    file_key: [u8; 32],
    total_chunks: usize,
    next_chunk: usize,
    accepted: bool,
    confirmed_chunks: usize,
}

/// An incoming offer that has passed validation and is waiting for the local
/// user's consent. Kept apart from `receiving` so no chunk is ever stored — let
/// alone decrypted — before a human agreed to the transfer.
struct PendingOffer {
    file_name: String,
    file_type: String,
    file_size: usize,
    total_chunks: usize,
    file_hash: String,
    file_salt: Vec<u8>,
    is_voice: bool,
    voice: Option<Value>,
}

/// Incoming (receiver) transfer state.
struct ReceivingState {
    file_name: String,
    file_type: String,
    file_size: usize,
    total_chunks: usize,
    file_hash: String,
    file_key: [u8; 32],
    chunks: HashMap<usize, Vec<u8>>,
    received_count: usize,
    is_voice: bool,
    voice: Option<Value>,
    /// Guards assembly so a received file is delivered exactly once.
    assembled: bool,
    /// Per-transfer chunk budget, on top of the manager-wide one.
    chunk_limiter: RateLimiter,
}

/// A file that finished assembling and is waiting to be collected.
///
/// The bytes are handed over by [`FileTransferManager::take_assembled`] rather
/// than embedded in the completion event: at up to 100 MB, base64-ing a file
/// into a JSON event would cost several multiples of its size in peak memory.
pub struct AssembledFile {
    pub file_name: String,
    pub file_type: String,
    pub is_voice: bool,
    pub voice: Option<Value>,
    pub data: Vec<u8>,
}

/// Owns all in-flight transfers in both directions.
pub struct FileTransferManager {
    sending: HashMap<String, SendingState>,
    receiving: HashMap<String, ReceivingState>,
    pending: HashMap<String, PendingOffer>,
    assembled: HashMap<String, AssembledFile>,
    send_limiter: RateLimiter,
    offer_limiter: RateLimiter,
    chunk_limiter: RateLimiter,
}

impl FileTransferManager {
    pub fn new() -> Self {
        Self {
            sending: HashMap::new(),
            receiving: HashMap::new(),
            pending: HashMap::new(),
            assembled: HashMap::new(),
            // Windows copied from the web client.
            send_limiter: RateLimiter::new(10, 60_000),      // outgoing files / min
            offer_limiter: RateLimiter::new(5, 60_000),      // incoming offers / min
            chunk_limiter: RateLimiter::new(60_000, 60_000), // all chunks (~16 MB/s)
        }
    }

    /// Drop all transfer state (e.g. on disconnect).
    pub fn clear(&mut self) {
        self.sending.clear();
        self.receiving.clear();
        self.pending.clear();
        self.assembled.clear();
    }

    // ---- Sender ---------------------------------------------------------

    /// Register an outgoing file and produce the `file_transfer_start` message
    /// the platform should send to the peer. No chunk is produced until the peer
    /// accepts (see [`next_chunk`]).
    ///
    /// `voice` carries the web's `{ dur, bars }` descriptor for a voice note; it
    /// is passed through untouched so the peer can draw the waveform before the
    /// audio has finished arriving.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_outgoing(
        &mut self,
        file_id: String,
        file_name: String,
        file_type: String,
        data: Vec<u8>,
        is_voice: bool,
        voice: Option<Value>,
        crypto: &TransferCrypto,
    ) -> Result<Value, String> {
        if data.is_empty() {
            return Err("Cannot send an empty file".to_string());
        }
        if self.sending.len() >= MAX_CONCURRENT_TRANSFERS {
            return Err("Maximum concurrent transfers reached".to_string());
        }
        if self.sending.contains_key(&file_id) {
            return Err("A transfer with this id is already in flight".to_string());
        }
        if !self.send_limiter.allow() {
            return Err(
                "Rate limit exceeded. Please wait before sending another file.".to_string()
            );
        }
        // Hold ourselves to the same policy we enforce on the peer, so we never
        // offer a file the other side is obliged to refuse.
        validate_file(&file_name, data.len(), &file_type)?;

        let mut file_salt = [0u8; 32];
        rand::thread_rng().fill(&mut file_salt);
        let file_key = crypto.file_key(&file_salt, &file_id);

        let total_chunks = data.len().div_ceil(CHUNK_SIZE).max(1);
        let file_hash = hex::encode(Sha256::digest(&data));

        let mut start = json!({
            "type": "file_transfer_start",
            "fileId": file_id,
            "fileName": file_name,
            "fileSize": data.len(),
            "fileType": file_type,
            "fileHash": file_hash,
            "totalChunks": total_chunks,
            "chunkSize": CHUNK_SIZE,
            "salt": file_salt.to_vec(),
            "timestamp": now_ms(),
            "version": PROTOCOL_VERSION,
        });
        if is_voice {
            start["isVoice"] = json!(true);
            if let Some(descriptor) = voice {
                start["voice"] = descriptor;
            }
        }

        self.sending.insert(
            file_id,
            SendingState {
                data,
                file_key,
                total_chunks,
                next_chunk: 0,
                accepted: false,
                confirmed_chunks: 0,
            },
        );

        Ok(start)
    }

    /// Produce the next `file_chunk` message for an accepted outgoing transfer.
    /// Returns `Ok(None)` once there is nothing left to send.
    ///
    /// A transfer that has *disappeared* also yields `Ok(None)` rather than an
    /// error, because that is a normal race rather than a fault: the receiver
    /// confirms the last chunk with `file_transfer_complete`, which drops the
    /// send state, and that reply can land while the caller's pump loop is still
    /// going. The web client bails out of its pump the same way. Callers stop
    /// either way, so nothing is sent that should not be — this only decides
    /// whether the user is shown a spurious failure.
    pub fn next_chunk(&mut self, file_id: &str) -> Result<Option<Value>, String> {
        let index = {
            let Some(state) = self.sending.get(file_id) else {
                return Ok(None);
            };
            if !state.accepted {
                return Err("Transfer not accepted by peer yet".to_string());
            }
            if state.next_chunk >= state.total_chunks {
                return Ok(None);
            }
            state.next_chunk
        };

        let message = self.build_chunk(file_id, index)?;
        if let Some(state) = self.sending.get_mut(file_id) {
            state.next_chunk = index + 1;
        }
        Ok(Some(message))
    }

    /// Re-encrypt and re-emit one chunk the receiver said it never got.
    ///
    /// Each retransmission gets a *fresh* nonce: reusing a nonce with the same
    /// key is the one mistake that breaks AES-GCM outright.
    pub fn chunk_at(&mut self, file_id: &str, index: usize) -> Result<Option<Value>, String> {
        let known = match self.sending.get(file_id) {
            Some(state) => {
                if !state.accepted || index >= state.total_chunks {
                    return Ok(None);
                }
                true
            }
            None => false,
        };
        if !known {
            return Ok(None);
        }
        self.build_chunk(file_id, index).map(Some)
    }

    fn build_chunk(&mut self, file_id: &str, index: usize) -> Result<Value, String> {
        let state = self
            .sending
            .get(file_id)
            .ok_or_else(|| "Unknown outgoing transfer".to_string())?;

        let start = index * CHUNK_SIZE;
        let end = ((index + 1) * CHUNK_SIZE).min(state.data.len());
        let plaintext = &state.data[start..end];

        let mut nonce = [0u8; 12];
        rand::thread_rng().fill(&mut nonce);
        let ciphertext = encrypt_chunk(&state.file_key, &nonce, plaintext)?;

        Ok(json!({
            "type": "file_chunk",
            "fileId": file_id,
            "chunkIndex": index,
            "totalChunks": state.total_chunks,
            "nonce": nonce.to_vec(),
            "encryptedDataB64": general_purpose::STANDARD.encode(&ciphertext),
            "chunkSize": plaintext.len(),
            "timestamp": now_ms(),
        }))
    }

    /// How many chunks of an outgoing transfer have been produced so far.
    pub fn send_progress(&self, file_id: &str) -> Option<(usize, usize, usize)> {
        self.sending
            .get(file_id)
            .map(|s| (s.next_chunk, s.confirmed_chunks, s.total_chunks))
    }

    // ---- Receiver consent ----------------------------------------------

    /// Accept an incoming offer: derive the per-file key, start receiving, and
    /// return the `file_transfer_response` to send so the sender starts
    /// streaming.
    pub fn accept(&mut self, file_id: &str, crypto: &TransferCrypto) -> Result<Value, String> {
        let offer = self
            .pending
            .remove(file_id)
            .ok_or_else(|| "Unknown incoming transfer".to_string())?;

        let file_key = crypto.file_key(&offer.file_salt, file_id);
        self.receiving.insert(
            file_id.to_string(),
            ReceivingState {
                file_name: offer.file_name,
                file_type: offer.file_type,
                file_size: offer.file_size,
                total_chunks: offer.total_chunks,
                file_hash: offer.file_hash,
                file_key,
                chunks: HashMap::new(),
                received_count: 0,
                is_voice: offer.is_voice,
                voice: offer.voice,
                assembled: false,
                // ~8 MB/s per transfer, matching the web.
                chunk_limiter: RateLimiter::new(30_000, 60_000),
            },
        );

        Ok(json!({
            "type": "file_transfer_response",
            "fileId": file_id,
            "accepted": true,
            "timestamp": now_ms(),
        }))
    }

    /// Reject an incoming offer. Returns the `file_transfer_response` to send
    /// back, and forgets the transfer.
    pub fn reject(&mut self, file_id: &str, reason: &str) -> Result<Value, String> {
        self.pending.remove(file_id);
        self.receiving.remove(file_id);
        Ok(json!({
            "type": "file_transfer_response",
            "fileId": file_id,
            "accepted": false,
            "error": reason,
            "timestamp": now_ms(),
        }))
    }

    /// Forget any state for a transfer (cancel/cleanup), either direction.
    pub fn cancel(&mut self, file_id: &str) {
        self.sending.remove(file_id);
        self.receiving.remove(file_id);
        self.pending.remove(file_id);
        self.assembled.remove(file_id);
    }

    /// Take the assembled bytes of a completed incoming transfer, exactly once.
    pub fn take_assembled(&mut self, file_id: &str) -> Option<AssembledFile> {
        self.assembled.remove(file_id)
    }

    // ---- Loss recovery --------------------------------------------------

    /// Chunk indices an in-flight incoming transfer is still missing, capped so
    /// one request never names an unbounded list.
    pub fn missing_chunks(&self, file_id: &str) -> Vec<usize> {
        let Some(state) = self.receiving.get(file_id) else {
            return Vec::new();
        };
        let mut missing = Vec::new();
        for index in 0..state.total_chunks {
            if missing.len() >= MAX_MISSING_PER_REQUEST {
                break;
            }
            if !state.chunks.contains_key(&index) {
                missing.push(index);
            }
        }
        missing
    }

    /// Build the `file_chunk_request` for whatever an incoming transfer still
    /// lacks. `None` when nothing is missing (or the transfer is unknown).
    ///
    /// This is what makes a transfer survive a connection blip: without it, a
    /// single dropped chunk leaves the receiver waiting forever.
    pub fn request_missing(&self, file_id: &str) -> Option<Value> {
        let missing = self.missing_chunks(file_id);
        if missing.is_empty() {
            return None;
        }
        Some(json!({
            "type": "file_chunk_request",
            "fileId": file_id,
            "missing": missing,
            "timestamp": now_ms(),
        }))
    }

    /// Build a `file_transfer_error` to tell the peer we are giving up.
    pub fn error_message(file_id: &str, reason: &str) -> Value {
        json!({
            "type": "file_transfer_error",
            "fileId": file_id,
            "error": reason,
            "timestamp": now_ms(),
        })
    }

    // ---- Unified incoming message handler ------------------------------

    /// Process any incoming file-protocol message (both directions).
    ///
    /// Returns a JSON object describing what happened, with these `kind`s:
    ///   "request"     offer awaiting consent  { fileId, fileName, fileSize, fileType, isVoice, voice, autoAccept }
    ///   "response"    peer accepted/rejected  { fileId, accepted, error? }
    ///   "progress"    a chunk was received    { fileId, received, total }
    ///   "complete"    file received+verified  { fileId, fileName, fileType, fileSize, isVoice, voice }
    ///   "ack"         peer confirmed a chunk  { fileId, confirmed, total }
    ///   "retransmit"  peer wants chunks back  { fileId, missing }
    ///   "sent"        peer finished receiving { fileId, success, error? }
    ///   "error"       transfer failed         { fileId, message }
    ///   "ignored"     duplicate/irrelevant    { fileId }
    ///
    /// Any result may carry a `"send"` array of messages the platform must
    /// transmit back to the peer, and a `"take"` flag meaning the assembled file
    /// is ready to be collected with [`take_assembled`].
    ///
    /// No session crypto is needed here: an incoming transfer's key is derived
    /// once, at [`accept`], and held in the transfer's own state.
    pub fn handle_incoming(&mut self, message: &Value) -> Result<Value, String> {
        let msg_type = message
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Message missing 'type'".to_string())?;

        match msg_type {
            "file_transfer_start" => self.on_start(message),
            "file_transfer_response" => self.on_response(message),
            "file_chunk" => self.on_chunk(message),
            "chunk_confirmation" => self.on_chunk_confirmation(message),
            "file_chunk_request" => self.on_chunk_request(message),
            "file_transfer_complete" => self.on_transfer_complete(message),
            "file_transfer_error" => self.on_transfer_error(message),
            other => Err(format!("Unknown file message type: {}", other)),
        }
    }

    fn on_start(&mut self, message: &Value) -> Result<Value, String> {
        let file_id = get_str(message, "fileId")?;

        // Duplicate offer for a transfer we already know about: ignore.
        if self.receiving.contains_key(&file_id) || self.pending.contains_key(&file_id) {
            return Ok(json!({ "kind": "ignored", "fileId": file_id }));
        }
        if !self.offer_limiter.allow() {
            return Err("Incoming file request rate limit exceeded".to_string());
        }
        if self.pending.len() >= MAX_PENDING_INCOMING {
            return Err("Too many pending incoming file requests".to_string());
        }

        // Everything below is peer-controlled, so validate before allocating.
        let refuse = |reason: &str| -> Value {
            json!({
                "kind": "error",
                "fileId": file_id,
                "message": reason,
                "send": [json!({
                    "type": "file_transfer_response",
                    "fileId": file_id,
                    "accepted": false,
                    "error": reason,
                    "timestamp": now_ms(),
                })],
            })
        };

        let file_size = get_usize(message, "fileSize")?;
        let total_chunks = get_usize(message, "totalChunks")?;
        let chunk_size = get_usize(message, "chunkSize")?;
        let file_hash = get_str(message, "fileHash")?;
        let file_type = message
            .get("fileType")
            .and_then(|v| v.as_str())
            .unwrap_or("application/octet-stream")
            .to_string();

        if file_size == 0 || file_size > MAX_FILE_SIZE {
            return Ok(refuse("Invalid file size"));
        }
        if total_chunks == 0 {
            return Ok(refuse("Invalid chunk count"));
        }
        if chunk_size == 0 || chunk_size > MAX_RECEIVE_CHUNK {
            return Ok(refuse("Invalid chunk size"));
        }

        let file_salt = get_byte_array(message, "salt")?;
        if file_salt.len() != 32 {
            return Ok(refuse("Invalid salt"));
        }

        let raw_name = message
            .get("fileName")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let file_name = match validate_incoming_name(raw_name) {
            Ok(name) => name,
            Err(reason) => return Ok(refuse(&reason)),
        };
        if let Err(reason) = validate_file(&file_name, file_size, &file_type) {
            return Ok(refuse(&reason));
        }

        let is_voice = message
            .get("isVoice")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let voice = message.get("voice").cloned();

        // Voice notes auto-accept and play inline, exactly like the web: a
        // consent card for every spoken reply would make the feature unusable.
        let auto_accept = is_voice || file_type.starts_with("audio/");

        self.pending.insert(
            file_id.clone(),
            PendingOffer {
                file_name: file_name.clone(),
                file_type: file_type.clone(),
                file_size,
                total_chunks,
                file_hash,
                file_salt,
                is_voice,
                voice: voice.clone(),
            },
        );

        Ok(json!({
            "kind": "request",
            "fileId": file_id,
            "fileName": file_name,
            "fileSize": file_size,
            "fileType": file_type,
            "isVoice": is_voice,
            "voice": voice,
            "autoAccept": auto_accept,
        }))
    }

    fn on_response(&mut self, message: &Value) -> Result<Value, String> {
        let file_id = get_str(message, "fileId")?;
        let accepted = message
            .get("accepted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let error = message.get("error").and_then(|v| v.as_str()).map(str::to_owned);

        if let Some(state) = self.sending.get_mut(&file_id) {
            state.accepted = accepted;
            if !accepted {
                self.sending.remove(&file_id);
            }
        }

        Ok(json!({
            "kind": "response",
            "fileId": file_id,
            "accepted": accepted,
            "error": error,
        }))
    }

    fn on_chunk(&mut self, message: &Value) -> Result<Value, String> {
        let file_id = get_str(message, "fileId")?;
        let chunk_index = get_usize(message, "chunkIndex")?;
        let declared_size = get_usize(message, "chunkSize")?;
        let nonce = get_byte_array(message, "nonce")?;

        // The web sends base64; much older peers sent a raw byte array. Accept
        // both so an upgrade on one side never strands the other.
        let ciphertext = match message.get("encryptedDataB64").and_then(|v| v.as_str()) {
            Some(b64) => general_purpose::STANDARD
                .decode(b64)
                .map_err(|_| "Invalid chunk data encoding".to_string())?,
            None => get_byte_array(message, "encryptedData")
                .map_err(|_| "Missing encrypted data".to_string())?,
        };

        // A missing receiving state means the transfer already completed, was
        // cancelled, or has not been consented to. A late chunk is benign.
        let Some(state) = self.receiving.get_mut(&file_id) else {
            return Ok(json!({ "kind": "ignored", "fileId": file_id }));
        };
        if state.assembled {
            return Ok(json!({ "kind": "ignored", "fileId": file_id }));
        }
        if chunk_index >= state.total_chunks {
            return Err(format!("Chunk index {} out of range", chunk_index));
        }
        // Idempotent: a re-sent chunk is acknowledged but not re-stored.
        if state.chunks.contains_key(&chunk_index) {
            return Ok(json!({
                "kind": "ignored",
                "fileId": file_id,
                "send": [confirmation(&file_id, chunk_index)],
            }));
        }
        if nonce.len() != 12 {
            return Err("Invalid nonce length".to_string());
        }
        if declared_size > MAX_RECEIVE_CHUNK {
            return Err("Chunk exceeds maximum size".to_string());
        }

        if !state.chunk_limiter.allow() || !self.chunk_limiter.allow() {
            self.receiving.remove(&file_id);
            return Ok(json!({
                "kind": "error",
                "fileId": file_id,
                "message": "Incoming chunk rate limit exceeded",
            }));
        }

        let state = self
            .receiving
            .get_mut(&file_id)
            .ok_or_else(|| "Unknown incoming transfer".to_string())?;

        let mut nonce12 = [0u8; 12];
        nonce12.copy_from_slice(&nonce);
        let plaintext = decrypt_chunk(&state.file_key, &nonce12, &ciphertext)?;
        if plaintext.len() != declared_size {
            return Err(format!(
                "Chunk size mismatch: expected {}, got {}",
                declared_size,
                plaintext.len()
            ));
        }

        state.chunks.insert(chunk_index, plaintext);
        state.received_count += 1;

        if state.received_count < state.total_chunks {
            return Ok(json!({
                "kind": "progress",
                "fileId": file_id,
                "received": state.received_count,
                "total": state.total_chunks,
                "send": [confirmation(&file_id, chunk_index)],
            }));
        }

        // All chunks present — assemble exactly once.
        state.assembled = true;
        match assemble(state) {
            Ok(data) => {
                let file_name = state.file_name.clone();
                let file_type = state.file_type.clone();
                let is_voice = state.is_voice;
                let voice = state.voice.clone();
                let file_size = data.len();
                self.receiving.remove(&file_id);
                self.assembled.insert(
                    file_id.clone(),
                    AssembledFile {
                        file_name: file_name.clone(),
                        file_type: file_type.clone(),
                        is_voice,
                        voice: voice.clone(),
                        data,
                    },
                );

                Ok(json!({
                    "kind": "complete",
                    "fileId": file_id,
                    "fileName": file_name,
                    "fileType": file_type,
                    "fileSize": file_size,
                    "isVoice": is_voice,
                    "voice": voice,
                    "take": true,
                    "send": [
                        confirmation(&file_id, chunk_index),
                        json!({
                            "type": "file_transfer_complete",
                            "fileId": file_id,
                            "success": true,
                            "timestamp": now_ms(),
                        }),
                    ],
                }))
            }
            Err(reason) => {
                self.receiving.remove(&file_id);
                Ok(json!({
                    "kind": "error",
                    "fileId": file_id,
                    "message": reason,
                    "send": [json!({
                        "type": "file_transfer_complete",
                        "fileId": file_id,
                        "success": false,
                        "error": reason,
                        "timestamp": now_ms(),
                    })],
                }))
            }
        }
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

    /// The receiver is missing chunks. Report which ones the platform should
    /// pump back out (via [`chunk_at`]); building them all here could mean
    /// megabytes of JSON in a single event.
    fn on_chunk_request(&mut self, message: &Value) -> Result<Value, String> {
        let file_id = get_str(message, "fileId")?;
        let Some(state) = self.sending.get(&file_id) else {
            return Ok(json!({ "kind": "ignored", "fileId": file_id }));
        };
        let total = state.total_chunks;

        let missing: Vec<usize> = message
            .get("missing")
            .and_then(|v| v.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|v| v.as_u64())
                    .map(|n| n as usize)
                    .filter(|index| *index < total)
                    .take(MAX_RETRANSMIT_PER_REQUEST)
                    .collect()
            })
            .unwrap_or_default();

        if missing.is_empty() {
            return Ok(json!({ "kind": "ignored", "fileId": file_id }));
        }
        Ok(json!({ "kind": "retransmit", "fileId": file_id, "missing": missing }))
    }

    fn on_transfer_complete(&mut self, message: &Value) -> Result<Value, String> {
        let file_id = get_str(message, "fileId")?;
        let success = message
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let error = message.get("error").and_then(|v| v.as_str()).map(str::to_owned);
        self.sending.remove(&file_id);
        Ok(json!({
            "kind": "sent",
            "fileId": file_id,
            "success": success,
            "error": error,
        }))
    }

    fn on_transfer_error(&mut self, message: &Value) -> Result<Value, String> {
        let file_id = get_str(message, "fileId")?;
        let reason = message
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("File transfer failed")
            .to_string();
        self.cancel(&file_id);
        Ok(json!({ "kind": "error", "fileId": file_id, "message": reason }))
    }
}

impl Default for FileTransferManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn confirmation(file_id: &str, chunk_index: usize) -> Value {
    json!({
        "type": "chunk_confirmation",
        "fileId": file_id,
        "chunkIndex": chunk_index,
        "timestamp": now_ms(),
    })
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

    // The hash is the end-to-end integrity check: chunk-level GCM tags prove
    // each piece is authentic, only this proves the whole file is the one the
    // sender announced.
    if !state.file_hash.is_empty() {
        let actual = hex::encode(Sha256::digest(&data));
        if actual != state.file_hash.to_lowercase() {
            return Err("File integrity check failed - hash mismatch".to_string());
        }
    }

    Ok(data)
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

/// Read a JSON array of byte-sized integers — the shape the web uses for
/// `salt` and `nonce`.
fn get_byte_array(message: &Value, field: &str) -> Result<Vec<u8>, String> {
    let items = message
        .get(field)
        .and_then(|v| v.as_array())
        .ok_or_else(|| format!("Missing or invalid '{}'", field))?;
    items
        .iter()
        .map(|v| {
            v.as_u64()
                .filter(|n| *n <= 255)
                .map(|n| n as u8)
                .ok_or_else(|| format!("Invalid byte in '{}'", field))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crypto() -> TransferCrypto {
        TransferCrypto::new(
            "71:2e:1c:da:b7:cc:05:7c:78:cf:31:45".to_string(),
            (0u8..64).collect(),
        )
        .unwrap()
    }

    fn accept_offer(receiver: &mut FileTransferManager, start: &Value, c: &TransferCrypto) -> Value {
        let event = receiver.handle_incoming(start).unwrap();
        assert_eq!(event["kind"], "request", "unexpected: {}", event);
        receiver.accept(event["fileId"].as_str().unwrap(), c).unwrap()
    }

    /// Drive a full sender -> receiver round trip and check the bytes survive.
    #[test]
    fn full_round_trip() {
        let c = crypto();
        let mut sender = FileTransferManager::new();
        let mut receiver = FileTransferManager::new();

        // A multi-chunk payload (just over 2 chunks).
        let original: Vec<u8> = (0..(CHUNK_SIZE * 2 + 123)).map(|i| (i % 251) as u8).collect();

        let start = sender
            .prepare_outgoing(
                "file-1".into(),
                "photo.png".into(),
                "image/png".into(),
                original.clone(),
                false,
                None,
                &c,
            )
            .unwrap();
        assert_eq!(start["totalChunks"], 3);
        assert_eq!(start["version"], PROTOCOL_VERSION);
        assert_eq!(start["salt"].as_array().unwrap().len(), 32);

        let response = accept_offer(&mut receiver, &start, &c);
        let resp_event = sender.handle_incoming(&response).unwrap();
        assert_eq!(resp_event["kind"], "response");
        assert_eq!(resp_event["accepted"], true);

        let mut completed = false;
        while let Some(chunk) = sender.next_chunk("file-1").unwrap() {
            // Wire-shape assertions: these are the fields the web peer reads.
            assert_eq!(chunk["nonce"].as_array().unwrap().len(), 12);
            assert!(chunk["encryptedDataB64"].is_string());

            let event = receiver.handle_incoming(&chunk).unwrap();
            match event["kind"].as_str().unwrap() {
                "progress" => {}
                "complete" => completed = true,
                other => panic!("unexpected event: {} ({})", other, event),
            }
        }

        assert!(completed);
        let file = receiver.take_assembled("file-1").unwrap();
        assert_eq!(file.data, original);
        assert_eq!(file.file_name, "photo.png");
        // Collected exactly once.
        assert!(receiver.take_assembled("file-1").is_none());
    }

    #[test]
    fn rejection_stops_transfer() {
        let c = crypto();
        let mut sender = FileTransferManager::new();
        let mut receiver = FileTransferManager::new();

        let start = sender
            .prepare_outgoing("f".into(), "a.txt".into(), "text/plain".into(), vec![1, 2, 3], false, None, &c)
            .unwrap();
        receiver.handle_incoming(&start).unwrap();
        let rejection = receiver.reject("f", "not now").unwrap();
        let event = sender.handle_incoming(&rejection).unwrap();
        assert_eq!(event["accepted"], false);

        // No chunk may be produced after rejection: the transfer is gone, so the
        // pump is told there is nothing to send rather than being handed data.
        assert_eq!(sender.next_chunk("f").unwrap(), None);
        assert_eq!(sender.chunk_at("f", 0).unwrap(), None);
    }

    /// The receiver's completion reply can reach the sender while its pump loop
    /// is still running. That race must end the pump quietly, not raise an error
    /// the user would see after a transfer that actually succeeded.
    #[test]
    fn completion_racing_the_pump_is_not_an_error() {
        let c = crypto();
        let mut sender = FileTransferManager::new();
        let mut receiver = FileTransferManager::new();

        let original: Vec<u8> = (0..(CHUNK_SIZE + 10)).map(|i| (i % 97) as u8).collect();
        let start = sender
            .prepare_outgoing("f".into(), "a.zip".into(), "application/zip".into(), original, false, None, &c)
            .unwrap();
        let response = accept_offer(&mut receiver, &start, &c);
        sender.handle_incoming(&response).unwrap();

        // Relay each of the receiver's replies immediately, as a platform does.
        loop {
            let Some(chunk) = sender.next_chunk("f").unwrap() else { break };
            let event = receiver.handle_incoming(&chunk).unwrap();
            if let Some(frames) = event["send"].as_array() {
                for frame in frames {
                    sender.handle_incoming(frame).unwrap();
                }
            }
        }
        // Reaching here without an error is the assertion.
        assert!(receiver.take_assembled("f").is_some());
    }

    #[test]
    fn chunks_are_refused_before_consent() {
        let c = crypto();
        let mut sender = FileTransferManager::new();
        let mut receiver = FileTransferManager::new();

        let start = sender
            .prepare_outgoing("f".into(), "a.txt".into(), "text/plain".into(), vec![9u8; 40], false, None, &c)
            .unwrap();
        receiver.handle_incoming(&start).unwrap(); // offer pending, NOT accepted

        // Force a chunk out of the sender without waiting for consent.
        sender.sending.get_mut("f").unwrap().accepted = true;
        let chunk = sender.next_chunk("f").unwrap().unwrap();

        // The receiver must not store or decrypt it while consent is pending.
        let event = receiver.handle_incoming(&chunk).unwrap();
        assert_eq!(event["kind"], "ignored");
        assert!(receiver.take_assembled("f").is_none());
    }

    #[test]
    fn duplicate_chunk_is_idempotent() {
        let c = crypto();
        let mut sender = FileTransferManager::new();
        let mut receiver = FileTransferManager::new();

        let original = vec![9u8; 100];
        let start = sender
            .prepare_outgoing("f".into(), "a.zip".into(), "application/zip".into(), original.clone(), false, None, &c)
            .unwrap();
        let response = accept_offer(&mut receiver, &start, &c);
        sender.handle_incoming(&response).unwrap();

        let chunk = sender.next_chunk("f").unwrap().unwrap();
        let first = receiver.handle_incoming(&chunk).unwrap();
        assert_eq!(first["kind"], "complete");
        // Re-delivering the same (and only) chunk must not produce a second file.
        let second = receiver.handle_incoming(&chunk).unwrap();
        assert_eq!(second["kind"], "ignored");
    }

    #[test]
    fn corrupted_chunk_fails_decryption() {
        let c = crypto();
        let mut sender = FileTransferManager::new();
        let mut receiver = FileTransferManager::new();

        let start = sender
            .prepare_outgoing("f".into(), "a.zip".into(), "application/zip".into(), vec![5u8; 50], false, None, &c)
            .unwrap();
        let response = accept_offer(&mut receiver, &start, &c);
        sender.handle_incoming(&response).unwrap();

        let mut chunk = sender.next_chunk("f").unwrap().unwrap();
        chunk["encryptedDataB64"] = json!("AAAAAAAAAAAAAAAAAAAAAA==");
        assert!(receiver.handle_incoming(&chunk).is_err());
    }

    /// A transfer that loses chunks must recover through file_chunk_request
    /// rather than stalling forever.
    #[test]
    fn missing_chunks_are_recovered() {
        let c = crypto();
        let mut sender = FileTransferManager::new();
        let mut receiver = FileTransferManager::new();

        let original: Vec<u8> = (0..(CHUNK_SIZE * 3)).map(|i| (i % 253) as u8).collect();
        let start = sender
            .prepare_outgoing("f".into(), "big.zip".into(), "application/zip".into(), original.clone(), false, None, &c)
            .unwrap();
        let response = accept_offer(&mut receiver, &start, &c);
        sender.handle_incoming(&response).unwrap();

        // Deliver every chunk except index 1 — simulating a dropped packet.
        let mut dropped = Vec::new();
        while let Some(chunk) = sender.next_chunk("f").unwrap() {
            if chunk["chunkIndex"] == 1 {
                dropped.push(chunk);
                continue;
            }
            receiver.handle_incoming(&chunk).unwrap();
        }
        assert!(receiver.take_assembled("f").is_none(), "must not complete yet");

        // The receiver notices and asks for it back.
        let request = receiver.request_missing("f").unwrap();
        assert_eq!(request["missing"], json!([1]));

        let event = sender.handle_incoming(&request).unwrap();
        assert_eq!(event["kind"], "retransmit");
        assert_eq!(event["missing"], json!([1]));

        // The sender re-encrypts it (fresh nonce) and the file completes.
        let resent = sender.chunk_at("f", 1).unwrap().unwrap();
        assert_ne!(resent["nonce"], dropped[0]["nonce"], "nonce must not be reused");

        let event = receiver.handle_incoming(&resent).unwrap();
        assert_eq!(event["kind"], "complete");
        assert_eq!(receiver.take_assembled("f").unwrap().data, original);
    }

    #[test]
    fn voice_metadata_survives_and_auto_accepts() {
        let c = crypto();
        let mut sender = FileTransferManager::new();
        let mut receiver = FileTransferManager::new();

        let voice = json!({ "dur": 3.5, "bars": [1, 2, 3, 4] });
        let start = sender
            .prepare_outgoing(
                "v".into(), "note.wav".into(), "audio/wav".into(),
                vec![1u8; 64], true, Some(voice.clone()), &c,
            )
            .unwrap();
        assert_eq!(start["isVoice"], true);
        assert_eq!(start["voice"], voice);

        let event = receiver.handle_incoming(&start).unwrap();
        assert_eq!(event["kind"], "request");
        assert_eq!(event["isVoice"], true);
        assert_eq!(event["voice"], voice);
        assert_eq!(event["autoAccept"], true, "voice notes must not need a consent card");
    }

    #[test]
    fn dangerous_names_and_types_are_refused() {
        let c = crypto();
        let mut receiver = FileTransferManager::new();

        // A path-traversal name must never reach the platform's save path.
        let mut offer = json!({
            "type": "file_transfer_start",
            "fileId": "bad-1", "fileName": "../../etc/passwd",
            "fileSize": 10, "fileType": "text/plain", "fileHash": "",
            "totalChunks": 1, "chunkSize": CHUNK_SIZE,
            "salt": vec![0u8; 32], "timestamp": 0, "version": "2.0",
        });
        let event = receiver.handle_incoming(&offer).unwrap();
        assert_eq!(event["kind"], "error");
        assert_eq!(event["send"][0]["accepted"], false);

        // An executable is refused by extension even with an innocent MIME.
        offer["fileId"] = json!("bad-2");
        offer["fileName"] = json!("payload.exe");
        let event = receiver.handle_incoming(&offer).unwrap();
        assert_eq!(event["kind"], "error");
        assert!(event["message"].as_str().unwrap().contains(".exe"));

        // An unlisted type is refused too.
        offer["fileId"] = json!("bad-3");
        offer["fileName"] = json!("archive.tar.gz");
        let event = receiver.handle_incoming(&offer).unwrap();
        assert_eq!(event["kind"], "error");
    }

    #[test]
    fn oversized_and_malformed_offers_are_refused() {
        let c = crypto();
        let mut receiver = FileTransferManager::new();

        let base = |id: &str| {
            json!({
                "type": "file_transfer_start",
                "fileId": id, "fileName": "a.zip",
                "fileSize": 100, "fileType": "application/zip", "fileHash": "",
                "totalChunks": 1, "chunkSize": CHUNK_SIZE,
                "salt": vec![0u8; 32], "timestamp": 0, "version": "2.0",
            })
        };

        let mut offer = base("o1");
        offer["fileSize"] = json!(MAX_FILE_SIZE + 1);
        assert_eq!(receiver.handle_incoming(&offer).unwrap()["kind"], "error");

        let mut offer = base("o2");
        offer["salt"] = json!(vec![0u8; 16]); // wrong salt length
        assert_eq!(receiver.handle_incoming(&offer).unwrap()["kind"], "error");

        let mut offer = base("o3");
        offer["chunkSize"] = json!(MAX_RECEIVE_CHUNK + 1);
        assert_eq!(receiver.handle_incoming(&offer).unwrap()["kind"], "error");
    }

    /// A peer that lies about the hash must not have its file accepted.
    #[test]
    fn hash_mismatch_is_rejected() {
        let c = crypto();
        let mut sender = FileTransferManager::new();
        let mut receiver = FileTransferManager::new();

        let mut start = sender
            .prepare_outgoing("f".into(), "a.zip".into(), "application/zip".into(), vec![7u8; 80], false, None, &c)
            .unwrap();
        start["fileHash"] = json!("00".repeat(32));

        let response = accept_offer(&mut receiver, &start, &c);
        sender.handle_incoming(&response).unwrap();

        let chunk = sender.next_chunk("f").unwrap().unwrap();
        let event = receiver.handle_incoming(&chunk).unwrap();
        assert_eq!(event["kind"], "error");
        assert!(event["message"].as_str().unwrap().contains("integrity"));
        assert_eq!(event["send"][0]["success"], false);
        assert!(receiver.take_assembled("f").is_none());
    }

    /// A different session (different fingerprint/salt) must not be able to
    /// decrypt the chunks — the per-file key is bound to the session.
    #[test]
    fn wrong_session_cannot_decrypt() {
        let c = crypto();
        let other = TransferCrypto::new("aa:bb:cc".to_string(), (10u8..74).collect()).unwrap();
        let mut sender = FileTransferManager::new();
        let mut receiver = FileTransferManager::new();

        let start = sender
            .prepare_outgoing("f".into(), "a.zip".into(), "application/zip".into(), vec![3u8; 64], false, None, &c)
            .unwrap();
        // The receiver derives its key from the *wrong* session material.
        let response = accept_offer(&mut receiver, &start, &other);
        sender.handle_incoming(&response).unwrap();

        let chunk = sender.next_chunk("f").unwrap().unwrap();
        assert!(receiver.handle_incoming(&chunk).is_err());
    }

    #[test]
    fn concurrent_transfer_cap_is_enforced() {
        let c = crypto();
        let mut sender = FileTransferManager::new();
        for i in 0..MAX_CONCURRENT_TRANSFERS {
            sender
                .prepare_outgoing(format!("f{}", i), "a.zip".into(), "application/zip".into(), vec![1u8; 10], false, None, &c)
                .unwrap();
        }
        let err = sender
            .prepare_outgoing("overflow".into(), "a.zip".into(), "application/zip".into(), vec![1u8; 10], false, None, &c)
            .unwrap_err();
        assert!(err.contains("concurrent"));
    }

    /// Read a transfer whose frames are hand-built in the *desktop/web* JSON
    /// shape rather than produced by our own sender.
    ///
    /// The other tests prove Rust talks to Rust. This one pins the field names
    /// and encodings a browser peer actually puts on the wire — `salt` and
    /// `nonce` as integer arrays, `encryptedDataB64` as base64 — so renaming any
    /// of them fails here instead of in the field. The ciphertext is built with
    /// `file_crypto`, which is itself verified against real WebCrypto output.
    #[test]
    fn reads_frames_in_the_web_wire_shape() {
        let c = crypto();
        let mut receiver = FileTransferManager::new();

        let file_id = "file_1730000000000_abc123xyz"; // web genFileId() shape
        let payload = b"the quick brown fox jumps over the lazy dog".to_vec();
        let file_salt: Vec<u8> = (0u8..32).map(|i| i.wrapping_mul(7)).collect();

        let start = json!({
            "type": "file_transfer_start",
            "fileId": file_id,
            "fileName": "report.pdf",
            "fileSize": payload.len(),
            "fileType": "application/pdf",
            "fileHash": hex::encode(Sha256::digest(&payload)),
            "totalChunks": 1,
            "chunkSize": 16384,
            "salt": file_salt,
            "timestamp": 1730000000000i64,
            "version": "2.0",
        });

        let event = receiver.handle_incoming(&start).unwrap();
        assert_eq!(event["kind"], "request");
        assert_eq!(event["autoAccept"], false, "a PDF must ask for consent");
        receiver.accept(file_id, &c).unwrap();

        // Encrypt exactly as the web does: per-file key from the same inputs,
        // AES-256-GCM with a 12-byte nonce, ciphertext‖tag base64-encoded.
        let file_key = derive_file_key(&c.key_fingerprint, &c.session_salt, &file_salt, file_id);
        let nonce: [u8; 12] = [9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 11, 12];
        let ciphertext = encrypt_chunk(&file_key, &nonce, &payload).unwrap();

        let chunk = json!({
            "type": "file_chunk",
            "fileId": file_id,
            "chunkIndex": 0,
            "totalChunks": 1,
            "nonce": nonce.to_vec(),
            "encryptedDataB64": general_purpose::STANDARD.encode(&ciphertext),
            "chunkSize": payload.len(),
            "timestamp": 1730000000001i64,
        });

        let event = receiver.handle_incoming(&chunk).unwrap();
        assert_eq!(event["kind"], "complete", "unexpected: {}", event);
        assert_eq!(receiver.take_assembled(file_id).unwrap().data, payload);

        // And the frames we send back are the ones the web peer expects.
        assert_eq!(event["send"][0]["type"], "chunk_confirmation");
        assert_eq!(event["send"][1]["type"], "file_transfer_complete");
        assert_eq!(event["send"][1]["success"], true);
    }

    /// Much older peers sent the ciphertext as a raw byte array instead of
    /// base64; the desktop still accepts that, so we must too.
    #[test]
    fn accepts_legacy_encrypted_data_array() {
        let c = crypto();
        let mut receiver = FileTransferManager::new();

        let file_id = "legacy-1";
        let payload = b"legacy peer payload".to_vec();
        let file_salt: Vec<u8> = vec![3u8; 32];

        let start = json!({
            "type": "file_transfer_start",
            "fileId": file_id, "fileName": "note.txt",
            "fileSize": payload.len(), "fileType": "text/plain",
            "fileHash": hex::encode(Sha256::digest(&payload)),
            "totalChunks": 1, "chunkSize": 16384,
            "salt": file_salt, "timestamp": 0, "version": "2.0",
        });
        receiver.handle_incoming(&start).unwrap();
        receiver.accept(file_id, &c).unwrap();

        let file_key = derive_file_key(&c.key_fingerprint, &c.session_salt, &file_salt, file_id);
        let nonce = [1u8; 12];
        let ciphertext = encrypt_chunk(&file_key, &nonce, &payload).unwrap();

        let chunk = json!({
            "type": "file_chunk", "fileId": file_id,
            "chunkIndex": 0, "totalChunks": 1,
            "nonce": nonce.to_vec(),
            "encryptedData": ciphertext,  // legacy: raw byte array, no base64
            "chunkSize": payload.len(), "timestamp": 0,
        });

        let event = receiver.handle_incoming(&chunk).unwrap();
        assert_eq!(event["kind"], "complete", "unexpected: {}", event);
        assert_eq!(receiver.take_assembled(file_id).unwrap().data, payload);
    }

    /// The sender applies the same allow-list it enforces on the peer, so we
    /// never offer a file the other side is required to refuse.
    #[test]
    fn sender_refuses_blocked_types() {
        let c = crypto();
        let mut sender = FileTransferManager::new();
        let err = sender
            .prepare_outgoing("f".into(), "virus.exe".into(), "application/octet-stream".into(), vec![1u8; 10], false, None, &c)
            .unwrap_err();
        assert!(err.contains(".exe"));
    }
}
