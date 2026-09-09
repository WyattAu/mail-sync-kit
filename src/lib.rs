//! `mail-sync-kit` — self-contained mail sync engines.
//!
//! IMAP state machine on `imap-next` (Disconnected → Connecting → Auth →
//! Hierarchy → Delta → IDLE, with QRESYNC/CONDSTORE support), JMAP sync
//! (RFC 8620/8621), SMTP submission via `lettre` (XOAUTH2/PLAIN/LOGIN),
//! and the outbox queue with exponential backoff.
//!
//! # Decoupling model
//!
//! The crate owns its entire vocabulary — [`store::MailStore`],
//! [`event::EngineEvent`], [`clock::Clock`], [`config::SyncConfig`] — so it
//! depends on no application core. Storage is injected through the
//! [`store::MailStore`] trait; the parsed-message type is a
//! [`store::MailStore::Parsed`] associated type, letting hosts keep their
//! own MIME model. The SASL mechanism implementations are injected as
//! callbacks ([`session::SaslFactory`]); only the step-wise session seam
//! ([`sasl::SaslSession`]) is defined here.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, missing_docs))]

pub mod clock;
pub mod config;
pub mod error;
pub mod event;
pub mod jmap;
pub mod jmap_sync;
pub mod model;
pub mod outbox_service;
pub mod sanitize;
pub mod sasl;
pub mod secrets;
pub mod session;
pub mod smtp;
pub mod store;
pub mod sync;

pub use clock::{Clock, FakeClock, SystemClock};
pub use config::SyncConfig;
pub use error::{StoreError, SyncError, SyncResult};
pub use event::EngineEvent;
pub use jmap_sync::JmapSyncService;
pub use model::{
    AccountId, BlobHash, ConnectionState, Flag, FolderDelta, FolderId, FolderRole, MessageId,
    OutboxId,
};
pub use outbox_service::OutboxService;
pub use secrets::SecretString;
pub use session::{CommandOutcome, ConnectParams, ImapSession, SaslFactory, Security, Unsolicited};
pub use smtp::{SmtpParams, SmtpSecurity, submit_envelope};
pub use store::{MailStore, NewFolder};
pub use sync::SyncService;
