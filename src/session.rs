//! IMAP session driver over `imap-next`: owns the TCP/TLS transport,
//! drives the sans-I/O client, correlates tagged statuses by tag, collects
//! untagged data per in-flight command, handles AUTHENTICATE continuation
//! rounds and IDLE, and performs the STARTTLS upgrade.
//!
//! Commands execute strictly sequentially — the sync state machine is
//! step-wise, and single-flight correlation keeps response attribution
//! unambiguous.

use std::{
    collections::HashSet,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use base64::Engine as _;
use imap_next::{
    client::{Client, Event, Options},
    imap_types::{
        auth::{AuthMechanism, AuthenticateData},
        command::{Command, CommandBody},
        core::{AString, Tag},
        fetch::{Macro, MacroOrMessageDataItemNames, MessageDataItem},
        flag::{Flag, FlagFetch},
        response::{Code, Data, Status, StatusKind},
        secret::Secret,
    },
    Interrupt, Io, State as _,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;

use crate::{
    error::{SyncError, SyncResult},
    sasl::{SaslMechanism, SaslSession},
    secrets::SecretString,
};

/// Connection security mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Security {
    /// Implicit TLS (port 993).
    Tls,
    /// Cleartext + STARTTLS upgrade (port 143).
    StartTls,
    /// Cleartext (integration fixtures only; never valid for production).
    Insecure,
}

/// SASL session factory injected by the host: mechanism implementations
/// live outside this crate and are injected as callbacks.
pub type SaslFactory =
    Arc<dyn Fn(SaslMechanism, &str, &SecretString) -> Box<dyn SaslSession + Send> + Send + Sync>;

/// Connection parameters for one account.
#[derive(Clone)]
pub struct ConnectParams {
    /// Host name.
    pub host: String,
    /// Port.
    pub port: u16,
    /// Security mode.
    pub security: Security,
    /// Username.
    pub username: String,
    /// Password / token (mechanism-dependent).
    pub secret: SecretString,
    /// Preferred SASL mechanisms, in order (server-advertised intersected).
    pub mechanisms: Vec<SaslMechanism>,
    /// TLS connector.
    pub tls: TlsConnector,
    /// SASL session factory (host-provided).
    pub sasl_factory: SaslFactory,
}

/// Untagged server data routed to the sync engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unsolicited {
    /// `EXISTS` — mailbox size changed.
    Exists(u32),
    /// `RECENT`.
    Recent(u32),
    /// `EXPUNGE` (sequence number).
    Expunge(u32),
    /// `FETCH` flag change by UID.
    FetchFlags {
        /// UID.
        uid: u32,
        /// Flags.
        flags: Vec<String>,
    },
    /// `VANISHED` UIDs (QRESYNC).
    Vanished(Vec<u32>),
    /// Anything else (logged, not acted on).
    Other(String),
}

impl Unsolicited {
    /// Parses from an untagged data response.
    ///
    /// # Panics
    /// Never: bounded `u32::MAX` conversion uses a checked fallback.
    #[must_use]
    pub fn from_data(data: &Data<'_>) -> Vec<Self> {
        match data {
            Data::Exists(n) => vec![Self::Exists(*n)],
            Data::Recent(n) => vec![Self::Recent(*n)],
            Data::Expunge(n) => vec![Self::Expunge(u32::from(*n))],
            Data::Vanished { known_uids, .. } => {
                // Expand the sequence set against u32::MAX (VANISHED
                // carries explicit/range UIDs; bounds are finite).
                let largest =
                    std::num::NonZeroU32::new(u32::MAX).unwrap_or(std::num::NonZeroU32::MIN);
                let uids: Vec<u32> = known_uids.iter(largest).map(u32::from).collect();
                vec![Self::Vanished(uids)]
            }
            Data::Fetch { items, .. } => {
                let mut uid = None;
                let mut flags = None;
                for item in items.as_ref() {
                    if let MessageDataItem::Uid(u) = item {
                        uid = Some(u.get());
                    }
                    if let MessageDataItem::Flags(f) = item {
                        flags = Some(
                            f.iter()
                                .map(|ff: &FlagFetch<'_>| match ff {
                                    FlagFetch::Flag(Flag::Seen) => "\\Seen".to_string(),
                                    FlagFetch::Flag(Flag::Answered) => "\\Answered".to_string(),
                                    FlagFetch::Flag(Flag::Flagged) => "\\Flagged".to_string(),
                                    FlagFetch::Flag(Flag::Deleted) => "\\Deleted".to_string(),
                                    FlagFetch::Flag(Flag::Draft) => "\\Draft".to_string(),
                                    FlagFetch::Recent => "\\Recent".to_string(),
                                    FlagFetch::Flag(other) => format!("{other:?}"),
                                })
                                .collect(),
                        );
                    }
                }
                match (uid, flags) {
                    (Some(uid), Some(flags)) => vec![Self::FetchFlags { uid, flags }],
                    _ => Vec::new(),
                }
            }
            other => vec![Self::Other(format!("{other:?}"))],
        }
    }
}

/// Outcome of one executed command.
#[derive(Debug)]
pub struct CommandOutcome {
    /// The tagged status.
    pub status: Status<'static>,
    /// Untagged data received during the command.
    pub data: Vec<Data<'static>>,
    /// Untagged statuses received during the command (SELECT codes etc.).
    pub untagged: Vec<Status<'static>>,
}

impl CommandOutcome {
    /// `true` when the tagged status is `OK`.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        matches!(
            &self.status,
            Status::Tagged(t) if matches!(t.body.kind, StatusKind::Ok)
        )
    }

    /// Compact status summary for error messages.
    #[must_use]
    pub fn status_summary(&self) -> String {
        format!("{:?}", self.status)
    }
}

/// Single owned transport: plain TCP or TLS-over-TCP. Kept unsplit so the
/// STARTTLS upgrade can take the socket back by value; boxed to keep the
/// enum small (the `large_enum_variant` lint).
enum Transport {
    /// Cleartext.
    Plain(TcpStream),
    /// TLS.
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for Transport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Transport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

const READ_CHUNK: usize = 16 * 1024;
const CMD_TIMEOUT: Duration = Duration::from_secs(60);

/// A driven IMAP session.
pub struct ImapSession {
    transport: Transport,
    client: Client,
    tag_counter: u64,
    capabilities: HashSet<String>,
}

impl ImapSession {
    /// Connects (TCP + TLS per `params.security`), consumes the greeting,
    /// authenticates via the first mutually-supported SASL mechanism, and
    /// refreshes capabilities.
    ///
    /// # Errors
    /// Mapped transport/auth failures ([`SyncError`]).
    pub async fn connect_and_authenticate(params: &ConnectParams) -> SyncResult<Self> {
        let mut session = Box::pin(Self::connect_transport(params)).await?;
        Box::pin(session.authenticate(params)).await?;
        Box::pin(session.refresh_capabilities()).await?;
        Ok(session)
    }

    async fn connect_transport(params: &ConnectParams) -> SyncResult<Self> {
        let tcp = tokio::time::timeout(
            Duration::from_secs(30),
            TcpStream::connect((params.host.as_str(), params.port)),
        )
        .await
        .map_err(|_| SyncError::Transport {
            detail: format!("connect timeout {}:{}", params.host, params.port),
        })?
        .map_err(|e| SyncError::Transport {
            detail: e.to_string(),
        })?;

        match params.security {
            Security::Tls => {
                let mut session = Self::from_transport(Transport::Tls(Box::new(
                    tls_connect(&params.tls, &params.host, tcp).await?,
                )));
                Box::pin(session.drive_until_greeting()).await?;
                Ok(session)
            }
            Security::Insecure => {
                let mut session = Self::from_transport(Transport::Plain(tcp));
                Box::pin(session.drive_until_greeting()).await?;
                Ok(session)
            }
            Security::StartTls => {
                let mut plain = Self::from_transport(Transport::Plain(tcp));
                Box::pin(plain.drive_until_greeting()).await?;
                let outcome =
                    Box::pin(plain.execute(CommandBody::StartTLS, Duration::from_secs(30))).await?;
                if !outcome.is_ok() {
                    return Err(SyncError::CapabilityMissing(
                        "STARTTLS refused by server".into(),
                    ));
                }
                // Sans-I/O: protocol state survives the transport upgrade.
                let Self {
                    transport,
                    client,
                    tag_counter,
                    capabilities,
                } = plain;
                let Transport::Plain(tcp) = transport else {
                    return Err(SyncError::Protocol("expected plain transport".into()));
                };
                let mut session = Self {
                    transport: Transport::Tls(Box::new(
                        tls_connect(&params.tls, &params.host, tcp).await?,
                    )),
                    client,
                    tag_counter,
                    capabilities,
                };
                Box::pin(session.drive_until_greeting()).await?;
                Ok(session)
            }
        }
    }

    fn from_transport(transport: Transport) -> Self {
        Self {
            transport,
            client: Client::new(Options::default()),
            tag_counter: 0,
            capabilities: HashSet::new(),
        }
    }

    /// Advertised capabilities.
    #[must_use]
    pub fn capabilities(&self) -> &HashSet<String> {
        &self.capabilities
    }

    /// Capability presence by wire name.
    #[must_use]
    pub fn has_capability(&self, needle: &str) -> bool {
        self.capabilities
            .iter()
            .any(|c| c.eq_ignore_ascii_case(needle))
    }

    fn next_tag(&mut self) -> SyncResult<Tag<'static>> {
        self.tag_counter += 1;
        Tag::try_from(format!("K{}", self.tag_counter))
            .map_err(|e| SyncError::Protocol(format!("tag build: {e:?}")))
    }

    /// Pumps the state machine until the next event, servicing IO
    /// interrupts.
    async fn pump(&mut self) -> SyncResult<Event> {
        loop {
            match self.client.next() {
                Ok(event) => return Ok(event),
                Err(Interrupt::Io(Io::NeedMoreInput)) => {
                    let mut chunk = [0u8; READ_CHUNK];
                    let n = self.transport.read(&mut chunk).await.map_err(|e| {
                        SyncError::Transport {
                            detail: e.to_string(),
                        }
                    })?;
                    if n == 0 {
                        return Err(SyncError::Transport {
                            detail: "server closed connection".into(),
                        });
                    }
                    self.client.enqueue_input(&chunk[..n]);
                }
                Err(Interrupt::Io(Io::Output(bytes))) => {
                    futures_write(&mut self.transport, &bytes)
                        .await
                        .map_err(|e| SyncError::Transport {
                            detail: e.to_string(),
                        })?;
                }
                Err(Interrupt::Error(e)) => {
                    return Err(SyncError::Protocol(format!("decode: {e:?}")));
                }
            }
        }
    }

    async fn drive_until_greeting(&mut self) -> SyncResult<()> {
        loop {
            let event = Box::pin(self.pump()).await?;
            if let Event::GreetingReceived { greeting } = event {
                if let Some(Code::Capability(caps)) = &greeting.code {
                    for c in caps.as_ref() {
                        self.capabilities.insert(format!("{c:?}"));
                    }
                    return Ok(());
                }
            }
        }
    }

    /// Executes one command sequentially, collecting untagged data until
    /// its tagged status arrives.
    ///
    /// # Errors
    /// Connection/protocol failures.
    pub async fn execute(
        &mut self,
        body: CommandBody<'static>,
        timeout: Duration,
    ) -> SyncResult<CommandOutcome> {
        let tag = self.next_tag()?;
        let expected = tag.clone();
        let handle = self.client.enqueue_command(Command { tag, body });
        let mut data = Vec::new();
        let mut untagged = Vec::new();
        loop {
            let event = Box::pin(tokio::time::timeout(timeout, self.pump()))
                .await
                .map_err(|_| SyncError::Transport {
                    detail: format!("command timeout after {timeout:?}"),
                })??;
            match event {
                Event::CommandSent { handle: h, .. } if h == handle => {}
                Event::CommandRejected {
                    handle: h, status, ..
                } if h == handle => {
                    return Ok(CommandOutcome {
                        status,
                        data,
                        untagged,
                    });
                }
                Event::DataReceived { data: d } => {
                    self.absorb_capabilities(&d);
                    data.push(d);
                }
                Event::StatusReceived { status } => {
                    if status.tag() == Some(&expected) {
                        return Ok(CommandOutcome {
                            status,
                            data,
                            untagged,
                        });
                    }
                    // Untagged statuses carry SELECT codes (UIDVALIDITY,
                    // UIDNEXT, HIGHESTMODSEQ).
                    untagged.push(status);
                }
                Event::ContinuationRequestReceived { .. } => {
                    return Err(SyncError::Protocol(
                        "continuation during plain command".into(),
                    ));
                }
                other => {
                    tracing::debug!(?other, "unexpected event during command");
                }
            }
        }
    }

    fn absorb_capabilities(&mut self, data: &Data<'_>) {
        if let Data::Capability(caps) = data {
            for c in caps.as_ref() {
                self.capabilities.insert(format!("{c:?}"));
            }
        }
    }

    async fn refresh_capabilities(&mut self) -> SyncResult<()> {
        let outcome = self
            .execute(CommandBody::Capability, Duration::from_secs(30))
            .await?;
        if !outcome.is_ok() {
            return Err(SyncError::Protocol(format!(
                "CAPABILITY failed: {}",
                outcome.status_summary()
            )));
        }
        Ok(())
    }

    /// UID FETCH with the given item names over a UID range string
    /// (e.g. `1:100`).
    ///
    /// # Errors
    /// Connection/protocol failures.
    pub async fn uid_fetch(
        &mut self,
        uid_range: &str,
        items: MacroOrMessageDataItemNames<'static>,
    ) -> SyncResult<CommandOutcome> {
        let sequence = imap_next::imap_types::sequence::SequenceSet::try_from(uid_range)
            .map_err(|e| SyncError::Protocol(format!("bad uid range {uid_range:?}: {e:?}")))?;
        self.execute(
            CommandBody::Fetch {
                sequence_set: sequence,
                macro_or_item_names: items,
                uid: true,
                modifiers: Vec::new(),
            },
            CMD_TIMEOUT,
        )
        .await
    }

    /// Envelope pass: `UID FETCH <range> ALL`.
    ///
    /// # Errors
    /// Connection/protocol failures.
    pub async fn fetch_envelopes(&mut self, uid_range: &str) -> SyncResult<CommandOutcome> {
        self.uid_fetch(uid_range, MacroOrMessageDataItemNames::Macro(Macro::All))
            .await
    }

    /// Raw body pass: `UID FETCH <uid> RFC822`. Item name choice (peek or
    /// not) is the caller's.
    ///
    /// # Errors
    /// Connection/protocol failures.
    pub async fn fetch_raw(&mut self, uid: u32) -> SyncResult<CommandOutcome> {
        let items = MacroOrMessageDataItemNames::MessageDataItemNames(vec![
            imap_next::imap_types::fetch::MessageDataItemName::Rfc822,
        ]);
        self.uid_fetch(&uid.to_string(), items).await
    }

    /// Authenticates with the first server-supported preferred mechanism,
    /// falling back to LOGIN.
    async fn authenticate(&mut self, params: &ConnectParams) -> SyncResult<()> {
        let username = params.username.clone();
        let mechanisms = params.mechanisms.clone();
        let secret = params.secret.clone();
        let factory = Arc::clone(&params.sasl_factory);
        for mechanism in mechanisms {
            let advertised = self.has_capability(&format!("AUTH={}", mechanism.name()));
            if !advertised {
                continue;
            }
            let mut session = factory(mechanism, &username, &secret);
            let initial = session.initial_response();
            let body = CommandBody::Authenticate {
                mechanism: match mechanism {
                    SaslMechanism::Plain => AuthMechanism::Plain,
                    SaslMechanism::Login => AuthMechanism::Login,
                    SaslMechanism::ScramSha256 => AuthMechanism::ScramSha256,
                    SaslMechanism::Xoauth2 => AuthMechanism::XOAuth2,
                },
                initial_response: initial.map(|b| Secret::new(std::borrow::Cow::Owned(b))),
            };
            return Box::pin(self.run_authenticate(body, &mut session)).await;
        }
        // LOGIN fallback (TLS transports only, enforced by callers).
        let outcome = self
            .execute(
                CommandBody::Login {
                    username: AString::try_from(username.clone())
                        .map_err(|e| SyncError::Protocol(format!("username: {e:?}")))?,
                    password: Secret::new(
                        AString::try_from(secret.expose().to_owned())
                            .map_err(|e| SyncError::Protocol(format!("password: {e:?}")))?,
                    ),
                },
                Duration::from_secs(30),
            )
            .await?;
        if outcome.is_ok() {
            Ok(())
        } else {
            Err(SyncError::CredentialsRejected)
        }
    }

    async fn run_authenticate(
        &mut self,
        body: CommandBody<'static>,
        session: &mut Box<dyn SaslSession + Send>,
    ) -> SyncResult<()> {
        let tag = self.next_tag()?;
        let _handle = self.client.enqueue_command(Command { tag, body });
        loop {
            let event = Box::pin(tokio::time::timeout(Duration::from_secs(30), self.pump()))
                .await
                .map_err(|_| SyncError::Transport {
                    detail: "auth timeout".into(),
                })??;
            match event {
                Event::AuthenticateStarted { .. } => {}
                Event::AuthenticateContinuationRequestReceived {
                    continuation_request,
                    ..
                } => {
                    let challenge = continuation_request_data(&continuation_request);
                    let answer = session.respond(&challenge).map_err(SyncError::Sasl)?;
                    let data =
                        AuthenticateData::Continue(Secret::new(std::borrow::Cow::Owned(answer)));
                    if self.client.set_authenticate_data(data).is_err() {
                        return Err(SyncError::Protocol("auth continuation out of sync".into()));
                    }
                }
                Event::AuthenticateStatusReceived { status, .. } => {
                    if matches!(
                        &status,
                        Status::Tagged(t) if matches!(t.body.kind, StatusKind::Ok)
                    ) {
                        return Ok(());
                    }
                    return Err(SyncError::CredentialsRejected);
                }
                Event::DataReceived { data } => self.absorb_capabilities(&data),
                other => {
                    tracing::debug!(?other, "unexpected during auth");
                }
            }
        }
    }

    /// Enters IDLE, returning collected unsolicited data as soon as any
    /// arrives or `max_wait` elapses (DONE is sent either way).
    ///
    /// # Errors
    /// Connection/protocol failures.
    pub async fn idle(&mut self, max_wait: Duration) -> SyncResult<Vec<Unsolicited>> {
        let tag = self.next_tag()?;
        let _handle = self.client.enqueue_command(Command {
            tag,
            body: CommandBody::Idle,
        });
        let mut unsolicited = Vec::new();
        let mut accepted = false;
        let mut done_sent = false;
        let deadline = tokio::time::Instant::now() + max_wait;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let event = if let Ok(ev) = Box::pin(tokio::time::timeout(remaining, self.pump())).await
            {
                ev?
            } else {
                if !accepted {
                    // Server never accepted IDLE within the window.
                    return Ok(unsolicited);
                }
                if !done_sent {
                    if self.client.set_idle_done().is_none() {
                        return Err(SyncError::Protocol("idle done out of sync".into()));
                    }
                    done_sent = true;
                    continue;
                }
                // DONE sent but no status within the remaining window:
                // treat as a lost connection.
                return Err(SyncError::Transport {
                    detail: "no status after IDLE DONE".into(),
                });
            };
            match event {
                Event::IdleAccepted { .. } => {
                    accepted = true;
                }
                Event::IdleCommandSent { .. } | Event::ContinuationRequestReceived { .. } => {
                    // Idle acceptance arrives as IdleAccepted; anything
                    // further here is tolerated and ignored.
                }
                Event::IdleDoneSent { .. } => {
                    done_sent = true;
                }
                Event::IdleRejected { status, .. } => {
                    return Err(SyncError::Protocol(format!("IDLE rejected: {status:?}")));
                }
                Event::DataReceived { data } => {
                    unsolicited.extend(Unsolicited::from_data(&data));
                    if accepted && !done_sent && !unsolicited.is_empty() {
                        // Wake immediately on server push.
                        if self.client.set_idle_done().is_none() {
                            return Err(SyncError::Protocol("idle done out of sync".into()));
                        }
                        done_sent = true;
                    }
                }
                Event::StatusReceived { status } => {
                    // Sequential execution: a status after DONE (or an
                    // unexpected status) completes the IDLE.
                    if accepted {
                        return Ok(unsolicited);
                    }
                    let _ = status;
                }
                other => {
                    tracing::debug!(?other, "unexpected during idle");
                }
            }
        }
    }

    /// Sends LOGOUT and closes politely (best-effort).
    pub async fn logout(&mut self) {
        let _ = self
            .execute(CommandBody::Logout, Duration::from_secs(10))
            .await;
    }
}

async fn futures_write(transport: &mut Transport, bytes: &[u8]) -> std::io::Result<()> {
    transport.write_all(bytes).await?;
    transport.flush().await
}

async fn tls_connect(
    connector: &TlsConnector,
    host: &str,
    tcp: TcpStream,
) -> SyncResult<tokio_rustls::client::TlsStream<TcpStream>> {
    let name =
        rustls_pki_types::ServerName::try_from(host.to_owned()).map_err(|e| SyncError::Tls {
            detail: e.to_string(),
        })?;
    connector
        .connect(name, tcp)
        .await
        .map_err(|e| SyncError::Tls {
            detail: e.to_string(),
        })
}

fn continuation_request_data(
    continuation: &imap_next::imap_types::response::CommandContinuationRequest<'_>,
) -> Vec<u8> {
    use imap_next::imap_types::response::CommandContinuationRequest as Ccr;
    match continuation {
        Ccr::Base64(b64) => base64::engine::general_purpose::STANDARD
            .decode(b64.as_ref())
            .unwrap_or_default(),
        Ccr::Basic(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nz(n: u32) -> std::num::NonZeroU32 {
        std::num::NonZeroU32::new(n).unwrap_or(std::num::NonZeroU32::MIN)
    }

    #[test]
    fn unsolicited_exists_recent_expunge() {
        assert_eq!(
            Unsolicited::from_data(&Data::Exists(42)),
            vec![Unsolicited::Exists(42)]
        );
        assert_eq!(
            Unsolicited::from_data(&Data::Recent(3)),
            vec![Unsolicited::Recent(3)]
        );
        let seq = nz(7);
        assert_eq!(
            Unsolicited::from_data(&Data::Expunge(seq)),
            vec![Unsolicited::Expunge(7)]
        );
    }

    #[test]
    fn unsolicited_fetch_requires_uid_and_flags() {
        // UID only: no event.
        let items = vec![MessageDataItem::Uid(nz(9))];
        assert!(Unsolicited::from_data(&Data::Fetch {
            seq: nz(1),
            items: imap_next::imap_types::core::Vec1::try_from(items.clone()).unwrap(),
        })
        .is_empty());
        // UID + flags: one event.
        let mut both = items;
        both.push(MessageDataItem::Flags(vec![FlagFetch::Flag(Flag::Seen)]));
        assert_eq!(
            Unsolicited::from_data(&Data::Fetch {
                seq: nz(1),
                items: imap_next::imap_types::core::Vec1::try_from(both).unwrap(),
            }),
            vec![Unsolicited::FetchFlags {
                uid: 9,
                flags: vec!["\\Seen".into()]
            }]
        );
    }

    #[test]
    fn unsolicited_unknown_becomes_other() {
        let events =
            Unsolicited::from_data(&Data::Capability(imap_next::imap_types::core::Vec1::from(
                [imap_next::imap_types::response::Capability::Imap4Rev1],
            )));
        assert!(matches!(events.as_slice(), [Unsolicited::Other(_)]));
    }

    #[test]
    fn command_outcome_is_ok_and_summary() {
        let status = imap_next::imap_types::response::Status::new(
            Some(imap_next::imap_types::core::Tag::try_from("K1").unwrap()),
            StatusKind::Ok,
            None,
            "done",
        )
        .unwrap();
        let outcome = CommandOutcome {
            status: status.clone(),
            data: Vec::new(),
            untagged: Vec::new(),
        };
        assert!(outcome.is_ok());
        assert!(outcome.status_summary().contains("Ok"));
        let _ = status;
    }
}
