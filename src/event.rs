//! Events broadcast by the sync engines on the host-provided bus (an
//! `mpsc::Sender<EngineEvent>`). Events are hints, never source of truth.

use std::time::Duration;

use crate::{
    error::SyncError,
    model::{AccountId, FolderDelta, FolderId, MessageId, OutboxId},
};

/// Events emitted by the sync engines.
#[derive(Clone, Debug)]
pub enum EngineEvent {
    /// Connection state machine transition.
    AccountConnection {
        /// Account.
        account: AccountId,
        /// New state.
        state: crate::model::ConnectionState,
    },
    /// New mail arrived.
    MailArrived {
        /// Account.
        account: AccountId,
        /// Folder.
        folder: FolderId,
        /// Delta summary.
        summary: FolderDelta,
    },
    /// Messages changed/removed in a folder.
    MessagesChanged {
        /// Folder.
        folder: FolderId,
        /// Changed count.
        changed: u32,
        /// Removed count.
        removed: u32,
    },
    /// Flags changed on messages.
    FlagsChanged {
        /// Affected messages.
        messages: Vec<MessageId>,
    },
    /// Folder tree changed (LIST/Mailbox-get result differs).
    FolderTreeChanged {
        /// Account.
        account: AccountId,
    },
    /// A send attempt failed; retry scheduled.
    OutboxRetry {
        /// Outbox entry.
        id: OutboxId,
        /// Attempt number (1-based).
        attempt: u32,
        /// Delay until next attempt.
        next_in: Duration,
        /// Last error summary (no secrets).
        last_error: String,
    },
    /// Message sent and filed to Sent.
    MailSent {
        /// Outbox entry.
        id: OutboxId,
        /// Resulting message id.
        message: MessageId,
    },
    /// Sending failed.
    MailFailed {
        /// Outbox entry.
        id: OutboxId,
        /// Failure.
        error: SyncError,
        /// `true` = will not be retried.
        permanent: bool,
    },
}
