//! Config-knob behavior matrix for mail-sync-kit.
//!
//! Every public tuning knob must OBSERVABLY change behavior:
//!
//! * [`SyncConfig`] (4 knobs: `poll_interval_secs`, `idle_timeout_mins`,
//!   `body_prefetch_recent`, `idle_poll_only_hosts`) — proven through the
//!   [`SyncService`] accessor seam (`should_poll`, `poll_interval`,
//!   `idle_timeout`, `prefetch_limit`), which is the exact decision point
//!   `run_one_cycle` / `prefetch_recent` branch on.
//! * [`ConnectParams::mechanisms`] — proven end-to-end against a loopback
//!   fake IMAP server: with `mechanisms = [Plain]` and `AUTH=PLAIN`
//!   advertised the client sends `AUTHENTICATE`; with `mechanisms = []` it
//!   falls back to `LOGIN`. This is the regression test for the dead-knob
//!   incident where capabilities were stored as `Debug` strings
//!   (`Auth(Plain)` — never matching the `AUTH=PLAIN` wire check), which
//!   silently pinned every account to the LOGIN fallback.
//!
//! Fast/deterministic: loopback TCP only, no sleeps, 10 s timeout guards.

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]
// Shared fixtures (`tests/common`) carry helpers used by other targets.
#![allow(dead_code)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{MockStore, PlainSession};
use mail_sync_kit::{
    ConnectParams, FakeClock, SaslFactory, SaslMechanism, SecretString, Security, SyncConfig,
    SyncService,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

fn test_account() -> mail_sync_kit::AccountId {
    mail_sync_kit::AccountId::from_uuid(uuid::Uuid::now_v7())
}

fn params_for(host: &str, port: u16, mechanisms: Vec<SaslMechanism>) -> ConnectParams {
    let factory: SaslFactory = Arc::new(|mechanism, username, secret| match mechanism {
        SaslMechanism::Plain => Box::new(PlainSession::new(username, secret.expose())),
        _ => panic!("matrix fixture only implements PLAIN"),
    });
    ConnectParams {
        host: host.to_string(),
        port,
        security: Security::Insecure,
        username: "matrix".to_string(),
        secret: SecretString::new("testpass".to_string()),
        mechanisms,
        tls: mail_sync_kit::webpki_connector(),
        sasl_factory: factory,
    }
}

fn service_with(host: &str, config: SyncConfig) -> SyncService<MockStore> {
    let store = Arc::new(MockStore::new());
    let (bus, _rx) = tokio::sync::mpsc::channel(16);
    SyncService::new(
        test_account(),
        params_for(host, 1143, vec![SaslMechanism::Plain]),
        store,
        Arc::new(|raw: &[u8]| raw.to_vec()),
        Arc::new(config),
        Arc::new(FakeClock::new(0)),
        bus,
    )
}

// --- SyncConfig defaults ---------------------------------------------------

#[test]
fn defaults_match_documented_values() {
    let config = SyncConfig::default();
    assert_eq!(config.poll_interval_secs, 120);
    assert_eq!(config.idle_timeout_mins, 29);
    assert!(config.idle_timeout_mins < 30);
    assert_eq!(config.body_prefetch_recent, 200);
    assert!(config.idle_poll_only_hosts.is_empty());
}

// --- idle_poll_only_hosts → should_poll ------------------------------------

#[test]
fn should_poll_idle_supported_and_unlisted_host_idles() {
    let service = service_with("imap.example.com", SyncConfig::default());
    assert!(!service.should_poll(true));
}

#[test]
fn should_poll_denied_host_polls_despite_idle() {
    let config = SyncConfig {
        idle_poll_only_hosts: vec!["broken.example.com".to_string()],
        ..SyncConfig::default()
    };
    let service = service_with("broken.example.com", config);
    assert!(service.should_poll(true));
}

#[test]
fn should_poll_denylist_matches_case_insensitively() {
    let config = SyncConfig {
        idle_poll_only_hosts: vec!["BROKEN.Example.COM".to_string()],
        ..SyncConfig::default()
    };
    let service = service_with("broken.example.com", config);
    assert!(service.should_poll(true));
}

#[test]
fn should_poll_without_idle_capability_always_polls() {
    let listed = SyncConfig {
        idle_poll_only_hosts: vec!["other.example.com".to_string()],
        ..SyncConfig::default()
    };
    assert!(service_with("imap.example.com", SyncConfig::default()).should_poll(false));
    assert!(service_with("imap.example.com", listed).should_poll(false));
}

// --- idle_timeout_mins → idle_timeout --------------------------------------

#[test]
fn idle_timeout_derives_from_config_minutes() {
    let service = service_with("imap.example.com", SyncConfig::default());
    assert_eq!(service.idle_timeout(), Duration::from_secs(29 * 60));

    let config = SyncConfig {
        idle_timeout_mins: 10,
        ..SyncConfig::default()
    };
    assert_eq!(
        service_with("imap.example.com", config).idle_timeout(),
        Duration::from_secs(600)
    );
}

// --- poll_interval_secs → poll_interval ------------------------------------

#[test]
fn poll_interval_derives_from_config_seconds() {
    let service = service_with("imap.example.com", SyncConfig::default());
    assert_eq!(service.poll_interval(), Duration::from_secs(120));

    let config = SyncConfig {
        poll_interval_secs: 7,
        ..SyncConfig::default()
    };
    assert_eq!(
        service_with("imap.example.com", config).poll_interval(),
        Duration::from_secs(7)
    );
}

// --- body_prefetch_recent → prefetch_limit ---------------------------------

#[test]
fn prefetch_limit_derives_from_config() {
    let service = service_with("imap.example.com", SyncConfig::default());
    assert_eq!(service.prefetch_limit(), 200);

    let config = SyncConfig {
        body_prefetch_recent: 5,
        ..SyncConfig::default()
    };
    assert_eq!(service_with("imap.example.com", config).prefetch_limit(), 5);
}

// --- mechanisms knob: fake-server auth selection ----------------------------

/// Minimal scripted IMAP server: greeting advertises `AUTH=PLAIN` + `IDLE`,
/// then answers the AUTHENTICATE/LOGIN + CAPABILITY handshake the client
/// performs in `connect_and_authenticate`. Every client line is recorded so
/// tests can assert which auth path the `mechanisms` knob selected.
struct FakeImap {
    addr: std::net::SocketAddr,
    recorded: Arc<Mutex<Vec<String>>>,
}

impl FakeImap {
    async fn spawn() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&recorded);
        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let (read_half, mut write_half) = stream.into_split();
            let mut reader = BufReader::new(read_half);
            write_half
                .write_all(b"* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN IDLE] fake ready\r\n")
                .await
                .unwrap();
            let mut line = String::new();
            loop {
                line.clear();
                let Ok(n) = reader.read_line(&mut line).await else {
                    break;
                };
                if n == 0 {
                    break;
                }
                let trimmed = line.trim_end().to_string();
                seen.lock().await.push(trimmed.clone());
                let mut parts = trimmed.splitn(3, ' ');
                let tag = parts.next().unwrap_or("K0").to_string();
                let command = parts.next().unwrap_or("").to_ascii_uppercase();
                let rest = parts.next().unwrap_or("").to_string();
                match command.as_str() {
                    "AUTHENTICATE" => {
                        // SASL-IR (initial response inline) needs no
                        // continuation; otherwise challenge once.
                        if rest.split_whitespace().count() < 2 {
                            write_half.write_all(b"+ \r\n").await.unwrap();
                            line.clear();
                            let Ok(n) = reader.read_line(&mut line).await else {
                                break;
                            };
                            if n == 0 {
                                break;
                            }
                            seen.lock().await.push(line.trim_end().to_string());
                        }
                        write_half
                            .write_all(format!("{tag} OK authenticated\r\n").as_bytes())
                            .await
                            .unwrap();
                    }
                    "LOGIN" => {
                        write_half
                            .write_all(format!("{tag} OK logged in\r\n").as_bytes())
                            .await
                            .unwrap();
                    }
                    "CAPABILITY" => {
                        write_half
                            .write_all(
                                format!(
                                    "* CAPABILITY IMAP4rev1 AUTH=PLAIN IDLE\r\n{tag} OK done\r\n"
                                )
                                .as_bytes(),
                            )
                            .await
                            .unwrap();
                    }
                    "LOGOUT" => {
                        write_half
                            .write_all(format!("* BYE bye\r\n{tag} OK logout\r\n").as_bytes())
                            .await
                            .unwrap();
                        break;
                    }
                    _ => {
                        write_half
                            .write_all(format!("{tag} OK noop\r\n").as_bytes())
                            .await
                            .unwrap();
                    }
                }
            }
        });
        Self { addr, recorded }
    }
}

async fn connect(params: &ConnectParams) -> mail_sync_kit::ImapSession {
    tokio::time::timeout(
        Duration::from_secs(10),
        mail_sync_kit::ImapSession::connect_and_authenticate(params),
    )
    .await
    .expect("fake-server handshake must complete quickly")
    .expect("fake-server handshake must succeed")
}

/// `mechanisms = [Plain]` + `AUTH=PLAIN` advertised → the client sends
/// `AUTHENTICATE PLAIN`, and the session exposes the wire-name
/// capabilities (the `Debug`-string regression deaded exactly this path).
#[tokio::test]
async fn mechanisms_plain_selects_authenticate_when_advertised() {
    let server = FakeImap::spawn().await;
    let params = params_for("127.0.0.1", server.addr.port(), vec![SaslMechanism::Plain]);
    let session = connect(&params).await;

    assert!(
        session.has_capability("AUTH=PLAIN"),
        "capabilities must be wire names, got: {:?}",
        session.capabilities()
    );
    assert!(session.has_capability("IDLE"));
    assert!(session.has_capability("idle"), "match is case-insensitive");
    assert!(!session.has_capability("AUTH=XOAUTH2"));

    let recorded = server.recorded.lock().await;
    assert!(
        recorded.iter().any(|l| l.contains("AUTHENTICATE")),
        "expected AUTHENTICATE, saw: {recorded:?}"
    );
    assert!(
        !recorded.iter().any(|l| l.contains("LOGIN")),
        "must not fall back to LOGIN, saw: {recorded:?}"
    );
}

/// `mechanisms = []` → the client falls back to `LOGIN` even though the
/// server advertises SASL mechanisms. Toggling the knob flips the wire
/// behavior.
#[tokio::test]
async fn empty_mechanisms_falls_back_to_login() {
    let server = FakeImap::spawn().await;
    let params = params_for("127.0.0.1", server.addr.port(), vec![]);
    let session = connect(&params).await;

    assert!(session.has_capability("AUTH=PLAIN"));
    let recorded = server.recorded.lock().await;
    assert!(
        recorded.iter().any(|l| l.contains("LOGIN")),
        "expected LOGIN fallback, saw: {recorded:?}"
    );
    assert!(
        !recorded.iter().any(|l| l.contains("AUTHENTICATE")),
        "no mechanisms configured, must not AUTHENTICATE: {recorded:?}"
    );
}
