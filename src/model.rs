//! Typed identifiers and shared value objects crossing the sync seam.
//!
//! All entity IDs are UUIDs stored as text and carried as newtypes — no raw
//! strings or `u64` cross trait boundaries. [`BlobHash`] is a SHA-256
//! digest carried in lowercase hex form.

use std::fmt;

use serde::{Deserialize, Serialize};

macro_rules! typed_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(uuid::Uuid);

        impl $name {
            /// Wraps an existing UUID.
            #[must_use]
            pub const fn from_uuid(id: uuid::Uuid) -> Self {
                Self(id)
            }

            /// Returns the underlying UUID.
            #[must_use]
            pub const fn as_uuid(&self) -> uuid::Uuid {
                self.0
            }

            /// Parses a textual (UUID) form.
            #[must_use]
            pub fn parse(s: &str) -> Option<Self> {
                s.parse::<uuid::Uuid>().ok().map(Self)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0.hyphenated())
            }
        }
    };
}

typed_id!(
    /// Account identity.
    AccountId
);
typed_id!(
    /// Folder identity.
    FolderId
);
typed_id!(
    /// Message identity.
    MessageId
);
typed_id!(
    /// Outbox entry identity.
    OutboxId
);

/// SHA-256 content hash of a blob in the content-addressed store,
/// carried as lowercase hex.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BlobHash(String);

impl BlobHash {
    /// Wraps a raw 32-byte digest.
    #[must_use]
    pub fn from_digest(digest: &[u8; 32]) -> Self {
        Self(Self::encode_hex(digest))
    }

    /// Parses a 64-char lowercase-or-uppercase hex digest.
    #[must_use]
    pub fn parse_hex(s: &str) -> Option<Self> {
        let bytes = Self::decode_hex(s)?;
        let digest: [u8; 32] = bytes.try_into().ok()?;
        Some(Self::from_digest(&digest))
    }

    /// Lowercase hex form (the on-disk representation).
    #[must_use]
    pub fn to_hex(&self) -> &str {
        &self.0
    }

    /// Two-level shard prefix (`ab/cd`) used by content-store layouts.
    #[must_use]
    pub fn shard_prefix(&self) -> String {
        format!("{}/{}", &self.0[0..2], &self.0[2..4])
    }

    fn encode_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(HEX[usize::from(b >> 4)] as char);
            out.push(HEX[usize::from(b & 0x0f)] as char);
        }
        out
    }

    fn decode_hex(s: &str) -> Option<Vec<u8>> {
        let hex = s.as_bytes();
        if hex.len() % 2 != 0 {
            return None;
        }
        let nibble = |c: u8| -> Option<u8> {
            match c {
                b'0'..=b'9' => Some(c - b'0'),
                b'a'..=b'f' => Some(c - b'a' + 10),
                b'A'..=b'F' => Some(c - b'A' + 10),
                _ => None,
            }
        };
        hex.chunks(2)
            .map(|pair| Some(nibble(pair[0])? << 4 | nibble(pair[1])?))
            .collect()
    }
}

impl fmt::Display for BlobHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for BlobHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlobHash({})", self.0)
    }
}

/// IMAP-style flag.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Flag {
    /// `\Seen`
    Seen,
    /// `\Answered`
    Answered,
    /// `\Flagged`
    Flagged,
    /// `\Deleted`
    Deleted,
    /// `\Draft`
    Draft,
    /// Custom keyword.
    Custom(String),
}

/// Account connection state machine states.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    /// No connection attempt active.
    Disconnected,
    /// TCP/TLS handshake in progress.
    Connecting,
    /// Credentials being exchanged.
    Authenticating,
    /// Hierarchy/delta sync running.
    Syncing,
    /// IDLE loop waiting for pushes.
    Idle,
    /// User-requested offline mode.
    OfflineMode,
}

/// Recognized folder roles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FolderRole {
    /// Inbox.
    Inbox,
    /// Sent mail.
    Sent,
    /// Drafts.
    Drafts,
    /// Trash.
    Trash,
    /// Archive.
    Archive,
    /// Junk/spam.
    Junk,
}

/// Folder delta delivered with [`crate::event::EngineEvent::MailArrived`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FolderDelta {
    /// New messages.
    pub new: u32,
    /// Total after the change.
    pub total: u64,
    /// Unread after the change.
    pub unread: u64,
}

/// Folder summary for listings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderSummary {
    /// Folder id.
    pub id: FolderId,
    /// Owning account.
    pub account: AccountId,
    /// Server-side name (e.g. `INBOX/Sent`).
    pub remote_name: String,
    /// Canonical role, if recognized.
    pub role: Option<FolderRole>,
    /// Hierarchy delimiter.
    pub delimiter: String,
    /// Unread count, maintained locally.
    pub unread: u64,
    /// Total messages, maintained locally.
    pub total: u64,
}

/// Email address with optional display name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Address {
    /// Display name, if any.
    pub name: Option<String>,
    /// Bare address (`local@domain`).
    pub email: String,
}

impl Address {
    /// Builds an address with no display name.
    #[must_use]
    pub fn bare(email: impl Into<String>) -> Self {
        Self {
            name: None,
            email: email.into(),
        }
    }
}

/// Window into a sorted result set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Window {
    /// Zero-based index of the first row.
    pub offset: u64,
    /// Maximum rows returned.
    pub limit: u64,
}

impl Default for Window {
    fn default() -> Self {
        Self {
            offset: 0,
            limit: 50,
        }
    }
}

/// Sort specification for message listings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SortSpec {
    /// Field to sort by.
    pub field: SortField,
    /// Direction.
    pub dir: SortDir,
}

impl Default for SortSpec {
    fn default() -> Self {
        Self {
            field: SortField::Date,
            dir: SortDir::Desc,
        }
    }
}

/// Sortable message fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SortField {
    /// `internal_date`.
    Date,
    /// Subject text.
    Subject,
    /// First from-address.
    Sender,
    /// IMAP UID.
    Uid,
}

/// Sort direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SortDir {
    /// Ascending.
    Asc,
    /// Descending.
    Desc,
}

/// Message metadata as returned by [`crate::store::MailStore::list_messages`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageSummary {
    /// Message id.
    pub id: MessageId,
    /// Owning folder.
    pub folder: FolderId,
    /// IMAP UID.
    pub uid: u32,
    /// `internal_date`, unix ms.
    pub internal_date: i64,
    /// Server flags.
    pub flags: Vec<Flag>,
    /// Subject.
    pub subject: Option<String>,
    /// First from-address.
    pub from: Option<Address>,
    /// Raw size in bytes.
    pub size: u64,
    /// `\Seen` shortcut.
    pub is_read: bool,
    /// `\Flagged` shortcut.
    pub is_flagged: bool,
    /// `\Answered` shortcut.
    pub is_answered: bool,
}

/// One page of messages plus the total result count.
#[derive(Clone, Debug, Default)]
pub struct MessagePage {
    /// Rows in this window.
    pub items: Vec<MessageSummary>,
    /// Total rows matching the query (before windowing).
    pub total: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_hash_hex_roundtrip_and_shard() {
        let digest = [0xab_u8; 32];
        let h = BlobHash::from_digest(&digest);
        assert_eq!(h.to_hex().len(), 64);
        assert_eq!(BlobHash::parse_hex(h.to_hex()), Some(h.clone()));
        assert_eq!(h.shard_prefix(), "ab/ab");
        assert_eq!(BlobHash::parse_hex(h.to_hex().to_uppercase()), Some(h));
        assert_eq!(BlobHash::parse_hex("zz"), None);
        assert_eq!(BlobHash::parse_hex("abc"), None);
    }

    #[test]
    fn distinct_id_types_do_not_mix() {
        fn assert_distinct(_: &AccountId, _: &MessageId) {}
        let u = uuid::Uuid::now_v7();
        assert_distinct(&AccountId::from_uuid(u), &MessageId::from_uuid(u));
        let id = AccountId::from_uuid(u);
        assert_eq!(AccountId::parse(&id.to_string()), Some(id));
    }

    #[test]
    fn flag_serializes_tagged() {
        let json = serde_json::to_string(&Flag::Seen).unwrap();
        assert!(json.contains("seen"));
        let back: Flag = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Flag::Seen);
    }
}
