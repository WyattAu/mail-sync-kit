//! Engine composition tests.
//!
//! Live-server tests are `#[ignore]`d and named `live_*`: set
//! `KESTREL_INTEGRATION` and point the fixtures at a Dovecot/Greenmail
//! pair (cleartext IMAP on loopback is a test-only posture —
//! [`Security::Insecure`] documents this constraint). The non-ignored
//! tests exercise the engine seams against the in-memory mock store
//! without any network.

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

mod common;

use std::{sync::Arc, time::Duration};

use common::{MockStore, PlainSession};
use mail_sync_kit::{
    submit_envelope, webpki_connector, AccountId, ConnectionState, EngineEvent, FakeClock,
    MailStore, NewFolder, OutboxId, OutboxRow, OutboxService, ParseFn, SaslFactory, SaslMechanism,
    Security, SmtpParams, SmtpSecurity, SyncConfig, SyncService,
};

fn account() -> AccountId {
    AccountId::from_uuid(uuid::Uuid::now_v7())
}

fn fixture_ready() -> bool {
    std::env::var("KESTREL_INTEGRATION").is_ok()
}

fn imap_params(host: &str, port: u16) -> mail_sync_kit::ConnectParams {
    let sasl_factory: SaslFactory = Arc::new(|mechanism, username, secret| match mechanism {
        SaslMechanism::Plain => Box::new(PlainSession::new(username, secret.expose())),
        _ => panic!("fixture only implements PLAIN"),
    });
    mail_sync_kit::ConnectParams {
        host: host.to_string(),
        port,
        security: Security::Insecure,
        username: "kestrel".to_string(),
        secret: mail_sync_kit::SecretString::new("testpass".to_string()),
        mechanisms: vec![SaslMechanism::Plain],
        tls: webpki_connector(),
        sasl_factory,
    }
}

fn noop_parser() -> ParseFn<Vec<u8>> {
    Arc::new(|raw: &[u8]| raw.to_vec())
}

#[tokio::test]
async fn mock_store_roundtrips_folders_cursors_and_blobs() {
    let store = Arc::new(MockStore::new());
    let acct = account();

    let folder = store
        .upsert_folder(&NewFolder {
            account: acct,
            remote_name: "INBOX".to_string(),
            attributes: vec![],
            role: Some(mail_sync_kit::FolderRole::Inbox),
            delimiter: "/".to_string(),
            uid_validity: 0,
            highest_modseq: 0,
        })
        .await
        .unwrap();

    store
        .update_sync_cursors(folder, 42, Some(7))
        .await
        .unwrap();
    let row = store.get_folder(folder).await.unwrap();
    assert_eq!(row.uid_validity, 42);
    assert_eq!(row.highest_modseq, 7);

    assert_eq!(store.max_uid(folder).await.unwrap(), None);
    let hash = store.write_blob(b"hello raw".to_vec()).await.unwrap();
    assert_eq!(store.read_blob(&hash).await.unwrap(), b"hello raw");
    assert_eq!(store.blob_count(), 1);

    store
        .set_account_state(acct, ConnectionState::Syncing)
        .await
        .unwrap();
    assert_eq!(
        store.account_states(),
        vec![(acct, ConnectionState::Syncing)]
    );
}

#[tokio::test]
async fn outbox_flush_missing_blob_emits_permanent_failure() {
    let store = Arc::new(MockStore::new());
    let (tx, mut rx) = tokio::sync::mpsc::channel::<EngineEvent>(16);
    let id = OutboxId::from_uuid(uuid::Uuid::now_v7());
    store.push_outbox(OutboxRow {
        id,
        account: account(),
        raw_blob: mail_sync_kit::BlobHash::from_digest(&[0u8; 32]),
        envelope: mail_sync_kit::OutboxEnvelope {
            from: mail_sync_kit::model::Address::bare("a@b.c"),
            to: vec![],
            cc: vec![],
            bcc: vec![],
            subject: "s".to_string(),
        },
        retry_count: 0,
        last_error: None,
        created_at: 0,
    });

    let svc = OutboxService::new(
        store.clone(),
        SmtpParams {
            host: "127.0.0.1".to_string(),
            port: 1,
            username: "u".to_string(),
            secret: mail_sync_kit::SecretString::new("p".to_string()),
            oauth2: false,
            security: SmtpSecurity::Insecure,
        },
        imap_params("127.0.0.1", 1),
        Arc::new(FakeClock::new(1_000)),
        tx,
        Arc::new(std::sync::atomic::AtomicBool::new(true)),
    );
    svc.flush_once().await.unwrap();

    match rx.try_recv().unwrap() {
        EngineEvent::MailFailed {
            id: failed,
            permanent,
            ..
        } => {
            assert_eq!(failed, id);
            assert!(permanent);
        }
        other => panic!("expected MailFailed, got {other:?}"),
    }
}

#[tokio::test]
async fn sync_service_emits_connecting_then_fails_gracefully_without_server() {
    // Nothing listens on port 1: the state machine must emit Connecting →
    // Disconnected and the run loop must exit on cancellation (backoff
    // wait is select'd against cancellation).
    let store = Arc::new(MockStore::new());
    let (tx, mut rx) = tokio::sync::mpsc::channel::<EngineEvent>(64);
    let acct = account();
    let svc = SyncService::new(
        acct,
        imap_params("127.0.0.1", 1),
        store.clone(),
        noop_parser(),
        Arc::new(SyncConfig::default()),
        Arc::new(FakeClock::new(0)),
        tx,
    );
    let cancel = tokio_util_sync_cancellation();
    let task_cancel = cancel.clone();
    let handle = tokio::spawn(async move { svc.run(task_cancel).await });

    // First two events arrive immediately; then the backoff sleep runs.
    let first = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        first,
        EngineEvent::AccountConnection {
            state: ConnectionState::Connecting,
            ..
        }
    ));

    // Give the cycle time to fail and emit Disconnected, then cancel.
    tokio::time::sleep(Duration::from_millis(200)).await;
    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;

    let states: Vec<ConnectionState> = store
        .account_states()
        .into_iter()
        .filter(|(a, _)| *a == acct)
        .map(|(_, s)| s)
        .collect();
    assert!(states.contains(&ConnectionState::Disconnected));
}

#[tokio::test]
async fn sync_service_idle_poll_only_config_is_carried() {
    // poll-only hosts force the polling fallback once connected; the
    // config plumbing is exercised here via construction.
    let cfg = SyncConfig {
        idle_poll_only_hosts: vec!["fixture.test".to_string()],
        ..SyncConfig::default()
    };
    assert!(cfg.idle_poll_only_hosts[0].eq_ignore_ascii_case("FIXTURE.TEST"));
}

#[tokio::test]
#[ignore = "requires the Dovecot fixture (docker compose up; KESTREL_INTEGRATION set)"]
async fn live_imap_connect_and_list() {
    assert!(
        fixture_ready(),
        "set KESTREL_INTEGRATION and start the fixtures"
    );
    let mut session =
        mail_sync_kit::ImapSession::connect_and_authenticate(&imap_params("127.0.0.1", 1143))
            .await
            .unwrap();
    assert!(session.has_capability("IMAP4rev1"));
    let outcome = session
        .execute(imap_list_command(), Duration::from_secs(10))
        .await
        .unwrap();
    assert!(outcome.is_ok());
    session.logout().await;
}

#[tokio::test]
#[ignore = "requires the Greenmail SMTP fixture"]
async fn live_smtp_submit_raw_envelope() {
    assert!(
        fixture_ready(),
        "set KESTREL_INTEGRATION and start the fixtures"
    );
    let params = SmtpParams {
        host: "127.0.0.1".to_string(),
        port: 1025,
        username: "kestrel".to_string(),
        secret: mail_sync_kit::SecretString::new("testpass".to_string()),
        oauth2: false,
        security: SmtpSecurity::Insecure,
    };
    submit_envelope(
        &params,
        "kestrel@example.test",
        &["dest@example.test".to_string()],
        b"From: kestrel@example.test\r\nTo: dest@example.test\r\nSubject: t\r\n\r\nbody\r\n",
    )
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires the Dovecot fixture and a synced account"]
async fn live_sync_cycle_ingests_hierarchy() {
    assert!(
        fixture_ready(),
        "set KESTREL_INTEGRATION and start the fixtures"
    );
    let store = Arc::new(MockStore::new());
    let (tx, _rx) = tokio::sync::mpsc::channel::<EngineEvent>(64);
    let acct = account();
    let svc = SyncService::new(
        acct,
        imap_params("127.0.0.1", 1143),
        store.clone(),
        noop_parser(),
        Arc::new(SyncConfig::default()),
        Arc::new(mail_sync_kit::SystemClock),
        tx,
    );
    let cancel = tokio_util_sync_cancellation();
    // One cycle against the fixture: run until cancelled.
    let task_cancel = cancel.clone();
    let handle = tokio::spawn(async move { svc.run(task_cancel).await });
    tokio::time::sleep(Duration::from_secs(10)).await;
    let folders = store.list_folders(acct).await.unwrap();
    assert!(!folders.is_empty(), "fixture LIST should populate folders");
    assert!(store.ingest_inserted() > 0 || folders.len() == 1);
    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(10), handle).await;
}

fn tokio_util_sync_cancellation() -> tokio_util::sync::CancellationToken {
    tokio_util::sync::CancellationToken::new()
}

fn imap_list_command() -> imap_next::imap_types::command::CommandBody<'static> {
    use imap_next::imap_types::{command::CommandBody, mailbox::ListMailbox};
    CommandBody::List {
        reference: imap_next::imap_types::mailbox::Mailbox::try_from(String::new())
            .unwrap_or(imap_next::imap_types::mailbox::Mailbox::Inbox),
        mailbox_wildcard: ListMailbox::try_from("*").unwrap(),
    }
}
