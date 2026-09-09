//! SASL vocabulary: mechanisms and the step-wise session seam. Mechanism
//! *implementations* are injected by the host (via
//! [`crate::session::SaslFactory`]); this crate only consumes the seam.

/// Supported mechanisms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaslMechanism {
    /// RFC 4616.
    Plain,
    /// Legacy LOGIN.
    Login,
    /// RFC 7677.
    ScramSha256,
    /// RFC 7628 (`OAuth2`).
    Xoauth2,
}

impl SaslMechanism {
    /// Wire name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Plain => "PLAIN",
            Self::Login => "LOGIN",
            Self::ScramSha256 => "SCRAM-SHA-256",
            Self::Xoauth2 => "XOAUTH2",
        }
    }
}

/// A step-wise SASL exchange (implementation injected by the host).
pub trait SaslSession {
    /// Initial response bytes (SASL IR), when the mechanism supports one.
    fn initial_response(&mut self) -> Option<Vec<u8>>;

    /// Feeds a server challenge, producing the next response.
    ///
    /// # Errors
    /// Mechanism-specific failure (malformed challenge).
    fn respond(&mut self, challenge: &[u8]) -> Result<Vec<u8>, String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mechanism_wire_names() {
        assert_eq!(SaslMechanism::Plain.name(), "PLAIN");
        assert_eq!(SaslMechanism::Login.name(), "LOGIN");
        assert_eq!(SaslMechanism::ScramSha256.name(), "SCRAM-SHA-256");
        assert_eq!(SaslMechanism::Xoauth2.name(), "XOAUTH2");
    }
}
