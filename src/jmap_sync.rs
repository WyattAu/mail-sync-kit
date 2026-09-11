//! `JmapSyncService` (per account): JMAP analogue of the IMAP
//! [`SyncService`](crate::sync::SyncService) state machine. Discovers the
//! JMAP session, syncs the folder hierarchy via `Mailbox/get`, ingests
//! messages via `Email/query` + `Email/get`, and supports delta sync
//! through JMAP state tokens.

use std::{sync::Arc, time::Duration};

use tokio_util::sync::CancellationToken;

use crate::{
    error::{SyncError, SyncResult},
    event::EngineEvent,
    jmap::JmapClient,
    model::{AccountId, ConnectionState, Flag as CoreFlag, FolderDelta, FolderRole},
    sanitize::sanitize_terminal_text,
    secrets::SecretString,
    store::{FolderRow, IngestBatch, IngestMessage, MailStore, NewFolder},
    sync::ParseFn,
};

/// JMAP sync service (one instance per account).
pub struct JmapSyncService<S: MailStore + ?Sized> {
    account: AccountId,
    host: String,
    token: SecretString,
    storage: Arc<S>,
    parse: ParseFn<S::Parsed>,
    clock: Arc<dyn crate::clock::SyncClock>,
    bus: tokio::sync::mpsc::Sender<EngineEvent>,
}

impl<S: MailStore + ?Sized> JmapSyncService<S> {
    /// Creates the service.
    pub fn new(
        account: AccountId,
        host: String,
        token: SecretString,
        storage: Arc<S>,
        parse: ParseFn<S::Parsed>,
        clock: Arc<dyn crate::clock::SyncClock>,
        bus: tokio::sync::mpsc::Sender<EngineEvent>,
    ) -> Self {
        Self {
            account,
            host,
            token,
            storage,
            parse,
            clock,
            bus,
        }
    }

    /// Spawns the service as a tokio task, returning its join handle.
    // Argument count mirrors `new` (full injection surface).
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        account: AccountId,
        host: String,
        token: SecretString,
        storage: Arc<S>,
        parse: ParseFn<S::Parsed>,
        clock: Arc<dyn crate::clock::SyncClock>,
        bus: tokio::sync::mpsc::Sender<EngineEvent>,
        cancel: CancellationToken,
    ) -> tokio::task::JoinHandle<()>
    where
        S: 'static,
    {
        let svc = Self::new(account, host, token, storage, parse, clock, bus);
        tokio::spawn(async move { svc.run(cancel).await })
    }

    /// Runs the state machine until cancellation, reconnecting with
    /// exponential backoff (250 ms doubling to 5 min; reset on success).
    #[tracing::instrument(skip_all, fields(account = %self.account))]
    pub async fn run(&self, cancel: CancellationToken) {
        let mut backoff = Duration::from_millis(250);
        loop {
            if cancel.is_cancelled() {
                return;
            }
            match self.run_one_cycle(&cancel).await {
                Ok(()) => {
                    backoff = Duration::from_millis(250);
                }
                Err(e) => {
                    tracing::warn!(account = %self.account, error = %e, "jmap sync cycle failed");
                    self.emit_state(ConnectionState::Disconnected).await;
                    let wait = backoff;
                    tokio::select! {
                        () = cancel.cancelled() => return,
                        () = tokio::time::sleep(wait) => {}
                    }
                    backoff = std::cmp::min(backoff.mul_f64(2.0), Duration::from_secs(300));
                }
            }
        }
    }

    async fn emit_state(&self, state: ConnectionState) {
        let _ = self.storage.set_account_state(self.account, state).await;
        let _ = self
            .bus
            .send(EngineEvent::AccountConnection {
                account: self.account,
                state,
            })
            .await;
    }

    /// One full cycle: discover → folders → delta sync → poll.
    async fn run_one_cycle(&self, cancel: &CancellationToken) -> SyncResult<()> {
        self.emit_state(ConnectionState::Connecting).await;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| SyncError::Protocol(format!("http client: {e}")))?;
        let client = JmapClient::discover(http, &self.host, &self.token).await?;
        self.emit_state(ConnectionState::Authenticating).await;
        self.emit_state(ConnectionState::Syncing).await;

        // Hierarchy sync.
        let folders = self.sync_hierarchy(&client).await?;
        self.bus
            .send(EngineEvent::FolderTreeChanged {
                account: self.account,
            })
            .await
            .map_err(|_| SyncError::Protocol("bus closed".into()))?;

        // Delta pass over every folder.
        for folder in &folders {
            if cancel.is_cancelled() {
                return Ok(());
            }
            self.sync_folder(&client, folder).await?;
        }

        // Polling loop (JMAP has no IDLE; poll with state tokens).
        loop {
            let interval = Duration::from_secs(300);
            tokio::select! {
                () = cancel.cancelled() => return Ok(()),
                () = tokio::time::sleep(interval) => {}
            }
            self.emit_state(ConnectionState::Syncing).await;
            let folders = self.list_stored_folders().await;
            for folder in &folders {
                if cancel.is_cancelled() {
                    return Ok(());
                }
                self.sync_folder(&client, folder).await?;
            }
        }
    }

    /// `Mailbox/get` → folder upsert; returns the refreshed folder rows.
    async fn sync_hierarchy(&self, client: &JmapClient) -> SyncResult<Vec<FolderRow>> {
        let resp = client.get_mailboxes().await?;
        let mailboxes = parse_mailbox_get(&resp)?;
        for mb in mailboxes {
            let role = role_from_jmap(&mb.name);
            if let Err(e) = self
                .storage
                .upsert_folder(&NewFolder {
                    account: self.account,
                    remote_name: mb.name.clone(),
                    attributes: mb.attributes(),
                    role,
                    delimiter: "/".to_string(),
                    uid_validity: 0,
                    highest_modseq: 0,
                })
                .await
            {
                tracing::warn!(error = %e, "jmap folder upsert failed");
            }
        }
        Ok(self.list_stored_folders().await)
    }

    async fn list_stored_folders(&self) -> Vec<FolderRow> {
        let Ok(summaries) = self.storage.list_folders(self.account).await else {
            return Vec::new();
        };
        let mut rows = Vec::with_capacity(summaries.len());
        for s in summaries {
            if let Ok(row) = self.storage.get_folder(s.id).await {
                rows.push(row);
            }
        }
        rows
    }

    /// Delta sync for one folder using JMAP state tokens.
    async fn sync_folder(&self, client: &JmapClient, folder: &FolderRow) -> SyncResult<()> {
        // The folder's highest_modseq carries the JMAP state-token cursor;
        // it is passed as `sinceState` on Email/query.
        let since_state = if folder.highest_modseq > 0 {
            Some(folder.highest_modseq.to_string())
        } else {
            None
        };

        let mailbox_id = folder.remote_name.clone();
        let resp = client
            .query_emails(vec![mailbox_id], since_state, 256)
            .await?;
        self.ingest_email_response(folder, &resp).await
    }

    /// Parse `Email/query` + `Email/get` responses and ingest into storage.
    async fn ingest_email_response(
        &self,
        folder: &FolderRow,
        resp: &crate::jmap::JmapResponse,
    ) -> SyncResult<()> {
        let emails = parse_email_get(resp)?;
        if emails.is_empty() {
            return Ok(());
        }

        let mut messages: Vec<IngestMessage<S::Parsed>> = Vec::new();
        for email in &emails {
            let uid = email.jmap_id_hash();
            let internal_date = email.received_at_ms(self.clock.as_ref());
            let flags = email.flags();
            let size = email.size.unwrap_or(0);

            // Reconstruct a header-only view for the parse pipeline.
            let raw_head = email.to_header(uid);
            let parsed = (self.parse)(raw_head.as_bytes());
            messages.push(IngestMessage {
                folder: folder.id,
                uid,
                internal_date,
                flags,
                parsed,
                raw_blob: None,
                raw_size: size,
            });
        }

        let new_count = u32::try_from(messages.len()).unwrap_or(u32::MAX);
        let stats = self
            .storage
            .ingest_batch(IngestBatch { messages })
            .await
            .map_err(SyncError::from)?;
        if stats.inserted > 0 {
            let summaries = self
                .storage
                .list_folders(self.account)
                .await
                .unwrap_or_default();
            let summary = summaries.iter().find(|f| f.id == folder.id).cloned();
            let _ = self
                .bus
                .send(EngineEvent::MailArrived {
                    account: self.account,
                    folder: folder.id,
                    summary: FolderDelta {
                        new: new_count,
                        total: summary.as_ref().map_or(0, |s| s.total),
                        unread: summary.as_ref().map_or(0, |s| s.unread),
                    },
                })
                .await;
        }

        // Update the state-token cursor if a new state was returned.
        if let Some(new_state) = &resp.new_state {
            if let Ok(cursor) = new_state.parse::<u64>() {
                let _ = self
                    .storage
                    .update_sync_cursors(folder.id, 0, Some(cursor))
                    .await;
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// JMAP response parsing helpers
// ---------------------------------------------------------------------------

/// Parsed mailbox from a `Mailbox/get` response.
struct ParsedMailbox {
    name: String,
    role: Option<String>,
    /// The JMAP id for use in `Email/query` filters.
    #[allow(dead_code)]
    id: String,
}

impl ParsedMailbox {
    fn attributes(&self) -> Vec<String> {
        let mut attrs = Vec::new();
        if let Some(role) = &self.role {
            attrs.push(format!("role:{role}"));
        }
        attrs
    }
}

/// Extract mailbox list from a `Mailbox/get` response.
fn parse_mailbox_get(resp: &crate::jmap::JmapResponse) -> SyncResult<Vec<ParsedMailbox>> {
    for item in &resp.method_responses {
        let arr = item
            .as_array()
            .ok_or_else(|| SyncError::Protocol("Mailbox/get: not an array".into()))?;
        if arr.len() < 2 {
            continue;
        }
        let name = arr[0].as_str().unwrap_or_default().to_string();
        if name != "Mailbox/get" {
            continue;
        }
        let data = &arr[1];
        let list = data
            .get("list")
            .and_then(|v| v.as_array())
            .ok_or_else(|| SyncError::Protocol("Mailbox/get: missing list".into()))?;
        return list
            .iter()
            .map(|m| {
                let n = m
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let r = m.get("role").and_then(|v| v.as_str()).map(String::from);
                let id = m
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                Ok(ParsedMailbox {
                    name: n,
                    role: r,
                    id,
                })
            })
            .collect::<SyncResult<Vec<_>>>();
    }
    Err(SyncError::Protocol(
        "Mailbox/get: no method response found".into(),
    ))
}

/// A parsed email from `Email/get`.
struct ParsedEmail {
    #[allow(dead_code)]
    id: String,
    subject: Option<String>,
    from: Vec<ParsedAddress>,
    to: Vec<ParsedAddress>,
    received_at: Option<String>,
    size: Option<u64>,
    keywords: Vec<String>,
    #[allow(dead_code)]
    mailbox_ids: Vec<String>,
}

#[derive(Clone)]
struct ParsedAddress {
    name: Option<String>,
    email: String,
}

impl ParsedEmail {
    /// Deterministic UID from the JMAP email id (stable across sync runs;
    /// collisions fold into the same row, which JMAP ids make rare).
    fn jmap_id_hash(&self) -> u32 {
        use std::{
            collections::hash_map::DefaultHasher,
            hash::{Hash, Hasher},
        };
        let mut h = DefaultHasher::new();
        self.id.hash(&mut h);
        u32::try_from(h.finish() % u64::from(u32::MAX) + 1).unwrap_or(1)
    }

    fn received_at_ms(&self, clock: &dyn crate::clock::SyncClock) -> i64 {
        self.received_at
            .as_deref()
            .and_then(parse_rfc3339_ms)
            .unwrap_or_else(|| clock.now_unix_ms())
    }

    fn flags(&self) -> Vec<CoreFlag> {
        let mut flags = Vec::new();
        if self.keywords.iter().any(|k| k == "$seen") {
            flags.push(CoreFlag::Seen);
        }
        if self.keywords.iter().any(|k| k == "$answered") {
            flags.push(CoreFlag::Answered);
        }
        if self.keywords.iter().any(|k| k == "$flagged") {
            flags.push(CoreFlag::Flagged);
        }
        if self.keywords.iter().any(|k| k == "$draft") {
            flags.push(CoreFlag::Draft);
        }
        flags
    }

    /// Reconstruct a header-only RFC 822 view for the parse pipeline.
    fn to_header(&self, uid: u32) -> String {
        let fmt_addr = |a: &ParsedAddress| match &a.name {
            Some(n) if !n.is_empty() => format!("{n} <{}>", a.email),
            _ => a.email.clone(),
        };
        let from = self
            .from
            .iter()
            .map(fmt_addr)
            .collect::<Vec<_>>()
            .join(", ");
        let to = self.to.iter().map(fmt_addr).collect::<Vec<_>>().join(", ");
        let subject = self.subject.as_deref().unwrap_or("");
        format!("From: {from}\r\nTo: {to}\r\nSubject: {subject}\r\nX-Sync-UID: {uid}\r\n\r\n")
    }
}

/// Extract email list from an `Email/get` response.
fn parse_email_get(resp: &crate::jmap::JmapResponse) -> SyncResult<Vec<ParsedEmail>> {
    for item in &resp.method_responses {
        let arr = item
            .as_array()
            .ok_or_else(|| SyncError::Protocol("Email/get: not an array".into()))?;
        if arr.len() < 2 {
            continue;
        }
        let name = arr[0].as_str().unwrap_or_default();
        if name != "Email/get" {
            continue;
        }
        let data = &arr[1];
        let list = data
            .get("list")
            .and_then(|v| v.as_array())
            .ok_or_else(|| SyncError::Protocol("Email/get: missing list".into()))?;
        return list
            .iter()
            .map(|m| {
                let id = m
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let subject = m.get("subject").and_then(|v| v.as_str()).map(String::from);
                let from = parse_address_list(m.get("from"));
                let to = parse_address_list(m.get("to"));
                let received_at = m
                    .get("receivedAt")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let size = m.get("size").and_then(serde_json::Value::as_u64);
                let keywords = m
                    .get("keywords")
                    .and_then(|v| v.as_object())
                    .map(|obj| obj.keys().cloned().collect())
                    .unwrap_or_default();
                let mailbox_ids = m
                    .get("mailboxIds")
                    .and_then(|v| v.as_object())
                    .map(|obj| obj.keys().cloned().collect())
                    .unwrap_or_default();
                Ok(ParsedEmail {
                    id,
                    subject,
                    from,
                    to,
                    received_at,
                    size,
                    keywords,
                    mailbox_ids,
                })
            })
            .collect::<SyncResult<Vec<_>>>();
    }
    Ok(Vec::new())
}

/// Parse a JMAP address list from a JSON value.
fn parse_address_list(val: Option<&serde_json::Value>) -> Vec<ParsedAddress> {
    let Some(arr) = val.and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|a| {
            let email = a.get("email")?.as_str()?.to_string();
            let name = a.get("name").and_then(|v| v.as_str()).map(String::from);
            Some(ParsedAddress { name, email })
        })
        .collect()
}

/// Parse an RFC 3339 timestamp to unix milliseconds.
fn parse_rfc3339_ms(s: &str) -> Option<i64> {
    let dt = chrono::DateTime::parse_from_rfc3339(s).ok()?;
    Some(dt.timestamp_millis())
}

/// Map a JMAP mailbox name/role to a [`FolderRole`].
fn role_from_jmap(name: &str) -> Option<FolderRole> {
    let normalized = sanitize_terminal_text(name).trim_end().to_lowercase();
    let last = normalized.rsplit(['/', '.']).next().unwrap_or_default();
    if last == "inbox" || normalized.is_empty() {
        Some(FolderRole::Inbox)
    } else if last == "sent" || last.starts_with("sent messages") {
        Some(FolderRole::Sent)
    } else if last == "drafts" {
        Some(FolderRole::Drafts)
    } else if last == "trash" || last == "deleted messages" {
        Some(FolderRole::Trash)
    } else if last == "junk" || last == "spam" {
        Some(FolderRole::Junk)
    } else if last == "archive" || last == "all mail" {
        Some(FolderRole::Archive)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jmap_request_mailbox_get_serializes() {
        let req = crate::jmap::JmapRequest {
            using: vec![
                "urn:ietf:params:jmap:core".into(),
                "urn:ietf:params:jmap:mail".into(),
            ],
            method_calls: vec![serde_json::json!([
                "Mailbox/get",
                { "accountId": null, "ids": null },
                "c1"
            ])],
            since_state: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["using"].as_array().unwrap().len(), 2);
        let calls = json["methodCalls"].as_array().unwrap();
        assert_eq!(calls[0][0], "Mailbox/get");
    }

    #[test]
    fn jmap_request_email_query_serializes() {
        let req = crate::jmap::JmapRequest {
            using: vec![
                "urn:ietf:params:jmap:core".into(),
                "urn:ietf:params:jmap:mail".into(),
            ],
            method_calls: vec![
                serde_json::json!([
                    "Email/query",
                    {
                        "accountId": null,
                        "filter": { "inMailbox": "mb1" },
                        "limit": 256,
                        "sort": [{ "property": "receivedAt", "isAscending": false }]
                    },
                    "q1"
                ]),
                serde_json::json!([
                    "Email/get",
                    {
                        "accountId": null,
                        "#ids": { "resultOf": "q1", "name": "Email/query", "path": "/ids" },
                        "properties": ["id", "subject", "from", "to", "receivedAt"]
                    },
                    "g1"
                ]),
            ],
            since_state: Some("42".into()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["sinceState"], "42");
        let calls = json["methodCalls"].as_array().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0][0], "Email/query");
        assert_eq!(calls[1][0], "Email/get");
    }

    #[test]
    fn jmap_request_with_state_omits_when_none() {
        let req = crate::jmap::JmapRequest {
            using: vec![],
            method_calls: vec![],
            since_state: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert!(json.get("sinceState").is_none());
    }

    #[test]
    fn parse_mailbox_get_response() {
        let resp = crate::jmap::JmapResponse {
            method_responses: vec![serde_json::json!([
                "Mailbox/get",
                {
                    "list": [
                        { "id": "mb1", "name": "INBOX", "role": "inbox" },
                        { "id": "mb2", "name": "Sent", "role": "sent" }
                    ]
                },
                "c1"
            ])],
            new_state: None,
        };
        let mailboxes = parse_mailbox_get(&resp).unwrap();
        assert_eq!(mailboxes.len(), 2);
        assert_eq!(mailboxes[0].name, "INBOX");
        assert_eq!(mailboxes[0].role.as_deref(), Some("inbox"));
        assert_eq!(mailboxes[1].name, "Sent");
    }

    #[test]
    fn parse_email_get_response() {
        let resp = crate::jmap::JmapResponse {
            method_responses: vec![serde_json::json!([
                "Email/get",
                {
                    "list": [
                        {
                            "id": "em1",
                            "subject": "Hello",
                            "from": [{ "name": "Alice", "email": "alice@example.com" }],
                            "to": [{ "email": "bob@example.com" }],
                            "receivedAt": "2025-01-15T10:30:00Z",
                            "size": 1234,
                            "keywords": { "$seen": true },
                            "mailboxIds": { "mb1": true }
                        }
                    ]
                },
                "g1"
            ])],
            new_state: Some("99".into()),
        };
        let emails = parse_email_get(&resp).unwrap();
        assert_eq!(emails.len(), 1);
        assert_eq!(emails[0].subject.as_deref(), Some("Hello"));
        assert_eq!(emails[0].from[0].email, "alice@example.com");
        assert_eq!(emails[0].from[0].name.as_deref(), Some("Alice"));
        assert_eq!(emails[0].size, Some(1234));
        assert!(emails[0].keywords.contains(&"$seen".to_string()));
    }

    #[test]
    fn parse_email_get_empty_on_no_match() {
        let resp = crate::jmap::JmapResponse {
            method_responses: vec![serde_json::json!([
                "Email/query",
                { "total": 0 },
                "q1"
            ])],
            new_state: None,
        };
        let emails = parse_email_get(&resp).unwrap();
        assert!(emails.is_empty());
    }

    #[test]
    fn role_from_jmap_names() {
        assert_eq!(role_from_jmap("INBOX"), Some(FolderRole::Inbox));
        assert_eq!(role_from_jmap("Sent"), Some(FolderRole::Sent));
        assert_eq!(role_from_jmap("Drafts"), Some(FolderRole::Drafts));
        assert_eq!(role_from_jmap("Trash"), Some(FolderRole::Trash));
        assert_eq!(role_from_jmap("Junk"), Some(FolderRole::Junk));
        assert_eq!(role_from_jmap("Archive"), Some(FolderRole::Archive));
        assert_eq!(role_from_jmap("Custom Folder"), None);
    }

    #[test]
    fn parsed_email_uid_is_deterministic() {
        let email = ParsedEmail {
            id: "em123".into(),
            subject: None,
            from: vec![],
            to: vec![],
            received_at: None,
            size: None,
            keywords: vec![],
            mailbox_ids: vec![],
        };
        let uid1 = email.jmap_id_hash();
        let uid2 = email.jmap_id_hash();
        assert_eq!(uid1, uid2);
        assert!(uid1 > 0);
    }

    #[test]
    fn parsed_email_flags_from_keywords() {
        let email = ParsedEmail {
            id: "x".into(),
            subject: None,
            from: vec![],
            to: vec![],
            received_at: None,
            size: None,
            keywords: vec!["$seen".into(), "$flagged".into()],
            mailbox_ids: vec![],
        };
        let flags = email.flags();
        assert!(flags.contains(&CoreFlag::Seen));
        assert!(flags.contains(&CoreFlag::Flagged));
        assert!(!flags.contains(&CoreFlag::Answered));
    }

    #[test]
    fn parse_rfc3339_to_unix_ms() {
        let ms = parse_rfc3339_ms("2025-01-15T10:30:00Z").unwrap();
        assert!(ms > 0);
    }

    #[test]
    fn jmap_request_batch_serializes_method_calls() {
        let req = crate::jmap::JmapRequest {
            using: vec![
                "urn:ietf:params:jmap:core".into(),
                "urn:ietf:params:jmap:mail".into(),
            ],
            method_calls: vec![
                serde_json::json!(["Email/query", {}, "q1"]),
                serde_json::json!(["Email/get", {}, "g1"]),
            ],
            since_state: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        let calls = json["methodCalls"].as_array().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0][0], "Email/query");
        assert_eq!(calls[1][0], "Email/get");
    }

    #[test]
    fn email_header_view_carries_addresses_and_uid() {
        let email = ParsedEmail {
            id: "em9".into(),
            subject: Some("Sub".into()),
            from: vec![ParsedAddress {
                name: Some("A".into()),
                email: "a@x".into(),
            }],
            to: vec![ParsedAddress {
                name: None,
                email: "b@y".into(),
            }],
            received_at: None,
            size: None,
            keywords: vec![],
            mailbox_ids: vec![],
        };
        let head = email.to_header(7);
        assert!(head.contains("From: A <a@x>\r\n"));
        assert!(head.contains("To: b@y\r\n"));
        assert!(head.contains("Subject: Sub\r\n"));
        assert!(head.contains("X-Sync-UID: 7\r\n"));
    }
}
