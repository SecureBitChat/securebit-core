// Error types for securebit_core
// All errors are deterministic and platform-agnostic
// No internal details are leaked

/// Core error types for cryptographic operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    /// Invalid input data (malformed, missing required fields, etc.)
    InvalidInput(String),
    /// Cryptographic operation failed
    CryptoFailure(String),
    /// Protocol violation (version mismatch, missing fields, etc.)
    ProtocolViolation(String),
    /// State error (missing state, invalid state transition, etc.)
    StateError(String),
    /// Internal error (should not occur in normal operation)
    InternalError(String),
}

impl CoreError {
    /// Create an InvalidInput error
    pub fn invalid_input(msg: impl Into<String>) -> Self {
        Self::InvalidInput(msg.into())
    }

    /// Create a CryptoFailure error
    pub fn crypto_failure(msg: impl Into<String>) -> Self {
        Self::CryptoFailure(msg.into())
    }

    /// Create a ProtocolViolation error
    pub fn protocol_violation(msg: impl Into<String>) -> Self {
        Self::ProtocolViolation(msg.into())
    }

    /// Create a StateError error
    pub fn state_error(msg: impl Into<String>) -> Self {
        Self::StateError(msg.into())
    }

    /// Create an InternalError error
    pub fn internal_error(msg: impl Into<String>) -> Self {
        Self::InternalError(msg.into())
    }
}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoreError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            CoreError::CryptoFailure(msg) => write!(f, "Cryptographic operation failed: {}", msg),
            CoreError::ProtocolViolation(msg) => write!(f, "Protocol violation: {}", msg),
            CoreError::StateError(msg) => write!(f, "State error: {}", msg),
            CoreError::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for CoreError {}

// Conversion from CoreError to String for backward compatibility
// This allows existing Result<String, String> APIs to work unchanged
impl From<CoreError> for String {
    fn from(err: CoreError) -> String {
        err.to_string()
    }
}

