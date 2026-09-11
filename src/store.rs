//! Storage vocabulary: the DTOs and the [`MailStore`] trait that the sync
//! engines consume. Implementations are injected by the host — the engines
//! never touch a concrete storage backend.

use async_trait::async_trait;

use crate::{
    error::StoreError,
    model::{
        AccountId, BlobHash, ConnectionState, Flag, FolderId, FolderRole, FolderSummary,
        MessagePage, OutboxId, SortSpec, Window,
    },
};

/// New-folder payload.
#[derive(Clone, Debug)]
pub struct NewFolder {
    /// Owning account (must exist in the host's store).
    pub account: AccountId,
    /// Server name.
    pub remote_name: String,
    /// Attributes (e.g. `\\HasNoChildren`).
    pub attributes: Vec<String>,
    /// Canonical role, if recognized.
    pub role: Option<FolderRole>,
    /// Hierarchy delimiter.
    pub delimiter: String,
    /// `UIDVALIDITY` (0 when not yet selected).
    pub uid_validity: u32,
    /// `HIGHESTMODSEQ` (0 when unknown).
    pub highest_modseq: u64,
}

/// Folder row as stored.
#[derive(Clone, Debug)]
pub struct FolderRow {
    /// Folder id.
    pub id: FolderId,
    /// Owning account.
    pub account: AccountId,
    /// Server name.
    pub remote_name: String,
    /// Attributes.
    pub attributes: Vec<String>,
    /// Canonical role.
    pub role: Option<FolderRole>,
    /// Hierarchy delimiter.
    pub delimiter: String,
    /// IMAP `UIDVALIDITY` cursor.
    pub uid_validity: u32,
    /// CONDSTORE `HIGHESTMODSEQ` cursor.
    pub highest_modseq: u64,
}

/// One message ready for ingestion.
///
/// `P` is the host's parsed-message model ([`MailStore::Parsed`]); the
/// engines construct it through the injected parser seam and never inspect
/// it.
#[derive(Clone, Debug)]
pub struct IngestMessage<P> {
    /// Destination folder.
    pub folder: FolderId,
    /// IMAP UID.
    pub uid: u32,
    /// `INTERNALDATE` (unix ms).
    pub internal_date: i64,
    /// Server flags.
    pub flags: Vec<Flag>,
    /// Parsed message (host-defined MIME model).
    pub parsed: P,
    /// Raw message blob (already in the content store; hash only).
    pub raw_blob: Option<BlobHash>,
    /// Raw size in bytes.
    pub raw_size: u64,
}

/// Ingestion batch: applied in one transaction.
#[derive(Clone, Debug, Default)]
pub struct IngestBatch<P> {
    /// Messages.
    pub messages: Vec<IngestMessage<P>>,
}

/// Ingestion outcome counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IngestStats {
    /// New rows.
    pub inserted: u64,
    /// Updated rows.
    pub updated: u64,
}

/// Envelope persisted beside the outbox raw blob.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct OutboxEnvelope {
    /// From.
    pub from: crate::model::Address,
    /// To.
    pub to: Vec<crate::model::Address>,
    /// Cc.
    pub cc: Vec<crate::model::Address>,
    /// Bcc.
    pub bcc: Vec<crate::model::Address>,
    /// Subject.
    pub subject: String,
}

/// Outbox row as returned to the outbox service.
#[derive(Clone, Debug)]
pub struct OutboxRow {
    /// Entry id.
    pub id: OutboxId,
    /// Owning account.
    pub account: AccountId,
    /// Content-store hash of the raw RFC 5322 bytes.
    pub raw_blob: BlobHash,
    /// Envelope.
    pub envelope: OutboxEnvelope,
    /// Retry counter.
    pub retry_count: u32,
    /// Last error summary.
    pub last_error: Option<String>,
    /// Creation time.
    pub created_at: i64,
}

/// The storage seam consumed by the sync engines; implemented and injected
/// by the host.
///
/// `Parsed` is the host's parsed-message model. The engines build it via a
/// parser callback ([`crate::sync::SyncService::new`]) and hand it back
/// through [`MailStore::ingest_batch`] without inspecting it.
#[async_trait]
pub trait MailStore: Send + Sync {
    /// The parsed-message model this store ingests.
    type Parsed: Clone + Send + Sync + 'static;

    /// Upsert a folder by (account, remote name).
    ///
    /// # Errors
    /// Storage failure.
    async fn upsert_folder(&self, folder: &NewFolder) -> Result<FolderId, StoreError>;

    /// List folder summaries for an account.
    ///
    /// # Errors
    /// Storage failure.
    async fn list_folders(&self, account: AccountId) -> Result<Vec<FolderSummary>, StoreError>;

    /// Fetch one folder row.
    ///
    /// # Errors
    /// Storage failure or unknown id.
    async fn get_folder(&self, id: FolderId) -> Result<FolderRow, StoreError>;

    /// Apply an ingestion batch in one transaction.
    ///
    /// # Errors
    /// Storage failure.
    async fn ingest_batch(
        &self,
        batch: IngestBatch<Self::Parsed>,
    ) -> Result<IngestStats, StoreError>;

    /// List a window of messages in a folder.
    ///
    /// # Errors
    /// Storage failure.
    async fn list_messages(
        &self,
        folder: FolderId,
        window: Window,
        sort: SortSpec,
    ) -> Result<MessagePage, StoreError>;

    /// Remove all messages of a folder; returns the removed count
    /// (`UIDVALIDITY` reconciliation).
    ///
    /// # Errors
    /// Storage failure.
    async fn purge_folder(&self, folder: FolderId) -> Result<u64, StoreError>;

    /// Update the sync cursors of a folder.
    ///
    /// # Errors
    /// Storage failure.
    async fn update_sync_cursors(
        &self,
        folder: FolderId,
        uid_validity: u32,
        highest_modseq: Option<u64>,
    ) -> Result<(), StoreError>;

    /// Highest stored UID of a folder.
    ///
    /// # Errors
    /// Storage failure.
    async fn max_uid(&self, folder: FolderId) -> Result<Option<u32>, StoreError>;

    /// All due outbox entries.
    ///
    /// # Errors
    /// Storage failure.
    async fn outbox_due(&self) -> Result<Vec<OutboxRow>, StoreError>;

    /// Mark an outbox entry for retry.
    ///
    /// # Errors
    /// Storage failure.
    async fn outbox_mark_retry(
        &self,
        id: OutboxId,
        retry_count: u32,
        next_attempt_at: i64,
        last_error: &str,
    ) -> Result<(), StoreError>;

    /// Mark an outbox entry as sent.
    ///
    /// # Errors
    /// Storage failure.
    async fn outbox_mark_sent(&self, id: OutboxId, sent_at: i64) -> Result<(), StoreError>;

    /// Read a blob from the content store.
    ///
    /// # Errors
    /// Storage failure or missing blob.
    async fn read_blob(&self, hash: &BlobHash) -> Result<Vec<u8>, StoreError>;

    /// Write a blob to the content store, returning its hash.
    ///
    /// # Errors
    /// Storage failure.
    async fn write_blob(&self, bytes: Vec<u8>) -> Result<BlobHash, StoreError>;

    /// Persist the account connection state.
    ///
    /// # Errors
    /// Storage failure.
    async fn set_account_state(
        &self,
        id: AccountId,
        state: ConnectionState,
    ) -> Result<(), StoreError>;
}
