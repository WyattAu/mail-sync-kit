//! Zeroized secret carrier: secrets never appear in `Debug` output or logs.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A zeroized-on-drop secret string.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretString(String);

impl SecretString {
    /// Wraps an owned secret.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Reveals the secret.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretString(***)")
    }
}

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_leaks() {
        let s = SecretString::new("hunter2".into());
        assert_eq!(format!("{s:?}"), "SecretString(***)");
        assert_eq!(s.expose(), "hunter2");
    }
}
