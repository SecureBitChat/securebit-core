// Logger trait for securebit_core
// Default implementation is no-op (never logs)
// This ensures no secrets are ever logged, even in debug builds

/// Logger trait for optional logging
/// Default implementation MUST be no-op
/// Logging MUST NEVER include secret material
pub trait Logger: Send + Sync {
    /// Log a debug message (non-secret information only)
    fn debug(&self, _msg: &str) {
        // Default: no-op
    }
    
    /// Log an error message (non-secret information only)
    fn error(&self, _msg: &str) {
        // Default: no-op
    }
    
    /// Log a warning message (non-secret information only)
    fn warn(&self, _msg: &str) {
        // Default: no-op
    }
}

/// No-op logger implementation (default)
pub struct NoOpLogger;

impl Logger for NoOpLogger {
    // All methods are no-op by default
}

impl Default for NoOpLogger {
    fn default() -> Self {
        NoOpLogger
    }
}

