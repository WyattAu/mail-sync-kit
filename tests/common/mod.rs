//! Shared test fixtures: an in-memory [`MailStore`] implementation and a
//! PLAIN SASL session, proving both seams are implementable from outside
//! the crate.

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::sync::Mutex;

use async_trait::async_trait;
use base64::Engine as _;
use mail_sync_kit::{
    BlobHash, ConnectionState, Flag, FolderId, FolderRole, FolderSummary, MailStore, MessagePage,
    MessageSummary, OutboxRow, SaslSession, SortSpec, StoreError, Window,
};

#[derive(Clone)]
pub struct MockMessage {
    pub id: mail_sync_kit::MessageId,
    pub folder: FolderId,
    pub uid: u32,
    pub internal_date: i64,
    pub flags: Vec<Flag>,
}

struct State {
    folders: Vec<mail_sync_kit::FolderRow>,
    messages: Vec<MockMessage>,
    blobs: Vec<(String, Vec<u8>)>,
    outbox: Vec<OutboxRow>,
    account_states: Vec<(mail_sync_kit::AccountId, ConnectionState)>,
    ingest_inserted: u64,
}

/// In-memory [`MailStore`]. `Parsed` is the raw RFC 5322 bytes — the mock
/// stores what it is given.
pub struct MockStore {
    state: Mutex<State>,
}

impl MockStore {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State {
                folders: Vec::new(),
                messages: Vec::new(),
                blobs: Vec::new(),
                outbox: Vec::new(),
                account_states: Vec::new(),
                ingest_inserted: 0,
            }),
        }
    }

    pub fn ingest_inserted(&self) -> u64 {
        self.state.lock().unwrap().ingest_inserted
    }

    pub fn blob_count(&self) -> usize {
        self.state.lock().unwrap().blobs.len()
    }

    pub fn account_states(&self) -> Vec<(mail_sync_kit::AccountId, ConnectionState)> {
        self.state.lock().unwrap().account_states.clone()
    }

    /// Queues an outbox entry (flush tests).
    pub fn push_outbox(&self, row: OutboxRow) {
        self.state.lock().unwrap().outbox.push(row);
    }
}

impl Default for MockStore {
    fn default() -> Self {
        Self::new()
    }
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut h);
    let word = h.finish().to_le_bytes();
    let mut out = [0u8; 32];
    for (i, chunk) in out.chunks_mut(8).enumerate() {
        for (j, b) in chunk.iter_mut().enumerate() {
            *b = word[(i + j) % 8];
        }
    }
    out
}

#[async_trait]
impl MailStore for MockStore {
    type Parsed = Vec<u8>;

    async fn upsert_folder(
        &self,
        folder: &mail_sync_kit::NewFolder,
    ) -> Result<FolderId, StoreError> {
        let mut st = self.state.lock().unwrap();
        if let Some(existing) = st
            .folders
            .iter_mut()
            .find(|f| f.account == folder.account && f.remote_name == folder.remote_name)
        {
            existing.attributes.clone_from(&folder.attributes);
            existing.role = folder.role;
            existing.delimiter.clone_from(&folder.delimiter);
            return Ok(existing.id);
        }
        let id = FolderId::from_uuid(uuid::Uuid::now_v7());
        st.folders.push(mail_sync_kit::FolderRow {
            id,
            account: folder.account,
            remote_name: folder.remote_name.clone(),
            attributes: folder.attributes.clone(),
            role: folder.role,
            delimiter: folder.delimiter.clone(),
            uid_validity: folder.uid_validity,
            highest_modseq: folder.highest_modseq,
        });
        Ok(id)
    }

    async fn list_folders(
        &self,
        account: mail_sync_kit::AccountId,
    ) -> Result<Vec<FolderSummary>, StoreError> {
        let st = self.state.lock().unwrap();
        let rows: Vec<FolderSummary> = st
            .folders
            .iter()
            .filter(|f| f.account == account)
            .map(|f| {
                let (unread, total) = if f.role == Some(FolderRole::Sent) {
                    (0, 0)
                } else {
                    (
                        u64::try_from(
                            st.messages
                                .iter()
                                .filter(|m| m.folder == f.id && !m.flags.contains(&Flag::Seen))
                                .count(),
                        )
                        .unwrap_or(0),
                        u64::try_from(st.messages.iter().filter(|m| m.folder == f.id).count())
                            .unwrap_or(0),
                    )
                };
                FolderSummary {
                    id: f.id,
                    account: f.account,
                    remote_name: f.remote_name.clone(),
                    role: f.role,
                    delimiter: f.delimiter.clone(),
                    unread,
                    total,
                }
            })
            .collect();
        Ok(rows)
    }

    async fn get_folder(&self, id: FolderId) -> Result<mail_sync_kit::FolderRow, StoreError> {
        let st = self.state.lock().unwrap();
        st.folders
            .iter()
            .find(|f| f.id == id)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(format!("folder {id}")))
    }

    async fn ingest_batch(
        &self,
        batch: mail_sync_kit::IngestBatch<Vec<u8>>,
    ) -> Result<mail_sync_kit::IngestStats, StoreError> {
        let mut st = self.state.lock().unwrap();
        let mut inserted = 0u64;
        let mut updated = 0u64;
        for msg in batch.messages {
            if let Some(existing) = st
                .messages
                .iter_mut()
                .find(|m| m.folder == msg.folder && m.uid == msg.uid)
            {
                existing.flags = msg.flags;
                existing.internal_date = msg.internal_date;
                updated += 1;
            } else {
                st.messages.push(MockMessage {
                    id: mail_sync_kit::MessageId::from_uuid(uuid::Uuid::now_v7()),
                    folder: msg.folder,
                    uid: msg.uid,
                    internal_date: msg.internal_date,
                    flags: msg.flags,
                });
                inserted += 1;
            }
        }
        st.ingest_inserted += inserted;
        Ok(mail_sync_kit::IngestStats { inserted, updated })
    }

    async fn list_messages(
        &self,
        folder: FolderId,
        window: Window,
        sort: SortSpec,
    ) -> Result<MessagePage, StoreError> {
        let st = self.state.lock().unwrap();
        let mut rows: Vec<&MockMessage> =
            st.messages.iter().filter(|m| m.folder == folder).collect();
        match sort.field {
            mail_sync_kit::SortField::Uid => rows.sort_by_key(|m| m.uid),
            _ => rows.sort_by_key(|m| m.internal_date),
        }
        if sort.dir == mail_sync_kit::SortDir::Desc {
            rows.reverse();
        }
        let total = u64::try_from(rows.len()).unwrap_or(0);
        let items = rows
            .iter()
            .skip(usize::try_from(window.offset).unwrap_or(0))
            .take(usize::try_from(window.limit).unwrap_or(0))
            .map(|m| MessageSummary {
                id: m.id,
                folder: m.folder,
                uid: m.uid,
                internal_date: m.internal_date,
                flags: m.flags.clone(),
                subject: None,
                from: None,
                size: 0,
                is_read: m.flags.contains(&Flag::Seen),
                is_flagged: m.flags.contains(&Flag::Flagged),
                is_answered: m.flags.contains(&Flag::Answered),
            })
            .collect();
        Ok(MessagePage { items, total })
    }

    async fn purge_folder(&self, folder: FolderId) -> Result<u64, StoreError> {
        let mut st = self.state.lock().unwrap();
        let before = st.messages.len();
        st.messages.retain(|m| m.folder != folder);
        Ok(u64::try_from(before - st.messages.len()).unwrap_or(0))
    }

    async fn update_sync_cursors(
        &self,
        folder: FolderId,
        uid_validity: u32,
        highest_modseq: Option<u64>,
    ) -> Result<(), StoreError> {
        let mut st = self.state.lock().unwrap();
        let f = st
            .folders
            .iter_mut()
            .find(|f| f.id == folder)
            .ok_or_else(|| StoreError::NotFound(format!("folder {folder}")))?;
        f.uid_validity = uid_validity;
        if let Some(seq) = highest_modseq {
            f.highest_modseq = seq;
        }
        Ok(())
    }

    async fn max_uid(&self, folder: FolderId) -> Result<Option<u32>, StoreError> {
        let st = self.state.lock().unwrap();
        Ok(st
            .messages
            .iter()
            .filter(|m| m.folder == folder)
            .map(|m| m.uid)
            .max())
    }

    async fn outbox_due(&self) -> Result<Vec<OutboxRow>, StoreError> {
        let st = self.state.lock().unwrap();
        Ok(st.outbox.clone())
    }

    async fn outbox_mark_retry(
        &self,
        id: mail_sync_kit::OutboxId,
        retry_count: u32,
        next_attempt_at: i64,
        last_error: &str,
    ) -> Result<(), StoreError> {
        let mut st = self.state.lock().unwrap();
        let row = st
            .outbox
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or_else(|| StoreError::NotFound(format!("outbox {id}")))?;
        row.retry_count = retry_count;
        row.created_at = next_attempt_at;
        row.last_error = Some(last_error.to_string());
        Ok(())
    }

    async fn outbox_mark_sent(
        &self,
        id: mail_sync_kit::OutboxId,
        _sent_at: i64,
    ) -> Result<(), StoreError> {
        let mut st = self.state.lock().unwrap();
        st.outbox.retain(|r| r.id != id);
        Ok(())
    }

    async fn read_blob(&self, hash: &BlobHash) -> Result<Vec<u8>, StoreError> {
        let st = self.state.lock().unwrap();
        st.blobs
            .iter()
            .find(|(h, _)| h == hash.to_hex())
            .map(|(_, bytes)| bytes.clone())
            .ok_or_else(|| StoreError::BlobMissing(hash.to_hex().to_string()))
    }

    async fn write_blob(&self, bytes: Vec<u8>) -> Result<BlobHash, StoreError> {
        let hash = BlobHash::from_digest(&digest(&bytes));
        let mut st = self.state.lock().unwrap();
        if !st.blobs.iter().any(|(h, _)| h == hash.to_hex()) {
            st.blobs.push((hash.to_hex().to_string(), bytes));
        }
        Ok(hash)
    }

    async fn set_account_state(
        &self,
        id: mail_sync_kit::AccountId,
        state: ConnectionState,
    ) -> Result<(), StoreError> {
        let mut st = self.state.lock().unwrap();
        if let Some(slot) = st.account_states.iter_mut().find(|(a, _)| *a == id) {
            slot.1 = state;
        } else {
            st.account_states.push((id, state));
        }
        Ok(())
    }
}

/// PLAIN SASL session (RFC 4616): sends `\0user\0secret` as the initial
/// response; never expects a server challenge.
pub struct PlainSession {
    username: String,
    secret: String,
}

impl PlainSession {
    pub fn new(username: &str, secret: &str) -> Self {
        Self {
            username: username.to_string(),
            secret: secret.to_string(),
        }
    }
}

impl SaslSession for PlainSession {
    fn initial_response(&mut self) -> Option<Vec<u8>> {
        Some(
            base64::engine::general_purpose::STANDARD
                .encode(format!("\0{}\0{}", self.username, self.secret))
                .into_bytes(),
        )
    }

    fn respond(&mut self, _challenge: &[u8]) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }
}
