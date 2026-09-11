//! `mail-sync-kit` — self-contained mail sync engines.
//!
//! IMAP state machine on `imap-next` (Disconnected → Connecting → Auth →
//! Hierarchy → Delta → IDLE, with CONDSTORE support), JMAP sync
//! (RFC 8620/8621), SMTP submission via `lettre` (XOAUTH2/PLAIN/LOGIN),
//! and the outbox queue with a documented retry schedule.
//!
//! # Decoupling model
//!
//! The crate owns its entire vocabulary — [`store::MailStore`],
//! [`event::EngineEvent`], [`clock::SyncClock`], [`config::SyncConfig`] — so
//! it depends on no application core. Storage is injected through the
//! [`store::MailStore`] trait; the parsed-message type is a
//! [`store::MailStore::Parsed`] associated type, letting hosts keep their
//! own MIME model (the engines build it through a [`sync::ParseFn`]
//! callback and never inspect it). SASL mechanism implementations are
//! injected as callbacks ([`session::SaslFactory`]); only the step-wise
//! session seam ([`sasl::SaslSession`]) is defined here.
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
pub mod tls;

pub use clock::{FakeClock, SyncClock, SystemClock};
pub use config::SyncConfig;
pub use error::{StoreError, SyncError, SyncResult};
pub use event::EngineEvent;
pub use jmap_sync::JmapSyncService;
pub use model::{
    AccountId, Address, BlobHash, ConnectionState, Flag, FolderDelta, FolderId, FolderRole,
    FolderSummary, MessageId, MessagePage, MessageSummary, OutboxId, SortDir, SortField, SortSpec,
    Window,
};
pub use outbox_service::{backoff_for, OutboxService};
pub use sasl::{SaslMechanism, SaslSession};
pub use secrets::SecretString;
pub use session::{CommandOutcome, ConnectParams, ImapSession, SaslFactory, Security, Unsolicited};
pub use smtp::{submit_envelope, SmtpParams, SmtpSecurity};
pub use store::{
    FolderRow, IngestBatch, IngestMessage, IngestStats, MailStore, NewFolder, OutboxEnvelope,
    OutboxRow,
};
pub use sync::{ParseFn, SyncService};
pub use tls::webpki_connector;
