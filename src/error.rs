//! Error taxonomy for sync internals and the storage seam.
//!
//! [`SyncError`] is the single error type of the network engines; storage
//! failures arrive wrapped as [`StoreError`] via the [`crate::store::MailStore`]
//! trait. `Display` strings are stable identifiers suitable for logging and
//! test assertions.

/// Errors internal to the sync engines.
#[derive(Clone, Debug, thiserror::Error)]
pub enum SyncError {
    /// Transport/auth/storage failure surfaced by the store seam.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Connection lost / IO error / timeout.
    #[error("transport: {detail}")]
    Transport {
        /// Human-readable failure detail.
        detail: String,
    },
    /// TLS handshake failure.
    #[error("tls handshake: {detail}")]
    Tls {
        /// Human-readable failure detail.
        detail: String,
    },
    /// Server rejected the credentials.
    #[error("credentials rejected")]
    CredentialsRejected,
    /// SASL exchange failed locally (malformed challenge).
    #[error("sasl: {0}")]
    Sasl(String),
    /// Server lacks a capability required for the operation.
    #[error("capability missing: {0}")]
    CapabilityMissing(String),
    /// Protocol-level misuse detected locally.
    #[error("protocol: {0}")]
    Protocol(String),
    /// Transient 4xx SMTP failure; retry with backoff.
    #[error("smtp transient {code}")]
    SmtpTransient {
        /// The 4xx status code.
        code: u16,
    },
    /// Server permanently rejected the message.
    #[error("message rejected: {detail}")]
    MessageRejected {
        /// Human-readable failure detail.
        detail: String,
    },
    /// Draft/envelope failed validation; user must fix.
    #[error("draft invalid: {detail}")]
    DraftInvalid {
        /// Human-readable failure detail.
        detail: String,
    },
    /// Retry budget exhausted; the message is preserved for inspection.
    #[error("retry exhausted after {attempts} attempts")]
    RetryExhausted {
        /// Number of attempts made.
        attempts: u32,
    },
}

/// Storage-seam error returned by [`crate::store::MailStore`] methods.
#[derive(Clone, Debug, thiserror::Error)]
pub enum StoreError {
    /// Requested entity does not exist.
    #[error("not found: {0}")]
    NotFound(String),
    /// Blob referenced but absent in the content store.
    #[error("blob missing: {0}")]
    BlobMissing(String),
    /// Any other storage failure (IO, integrity, quota).
    #[error("storage failure: {0}")]
    Failed(String),
}

/// Result alias for sync internals.
pub type SyncResult<T> = Result<T, SyncError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_strings_are_stable() {
        let e = SyncError::Transport {
            detail: "closed".into(),
        };
        assert_eq!(e.to_string(), "transport: closed");
        assert_eq!(
            SyncError::CredentialsRejected.to_string(),
            "credentials rejected"
        );
        assert_eq!(
            SyncError::SmtpTransient { code: 421 }.to_string(),
            "smtp transient 421"
        );
        let s = StoreError::BlobMissing("ab/cd".into());
        let wrapped = SyncError::from(s);
        assert_eq!(wrapped.to_string(), "blob missing: ab/cd");
    }
}
