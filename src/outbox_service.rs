//! `OutboxService`: drains due rows through SMTP with the documented
//! backoff schedule + deterministic jitter, files sent mail to the Sent
//! folder via IMAP APPEND, and emits `OutboxRetry` / `MailSent` /
//! `MailFailed` events. Offline mode defers flushing entirely.

use std::{sync::Arc, time::Duration};

use tokio_util::sync::CancellationToken;

use crate::{
    error::{SyncError, SyncResult},
    event::EngineEvent,
    model::MessageId,
    session::{ConnectParams, ImapSession},
    smtp::{self, SmtpParams},
    store::{MailStore, OutboxRow},
};

/// Backoff schedule: attempt N waits `BACKOFF_SCHEDULE_MS[(N-1) % len]`,
/// scaled by deterministic ±20% jitter derived from the retry counter.
const BACKOFF_SCHEDULE_MS: [u64; 12] = [
    30_000, 120_000, 480_000, 1_800_000, 7_200_000, 21_600_000, 21_600_000, 21_600_000, 21_600_000,
    21_600_000, 21_600_000, 21_600_000,
];

/// Retry budget: after this many attempts the entry is failed permanently
/// (the draft is preserved in the host's store).
pub const MAX_RETRY_ATTEMPTS: u32 = 12;

/// The outbox flush service.
pub struct OutboxService<S: MailStore + ?Sized> {
    storage: Arc<S>,
    smtp: SmtpParams,
    imap: ConnectParams,
    clock: Arc<dyn crate::clock::SyncClock>,
    bus: tokio::sync::mpsc::Sender<EngineEvent>,
    /// Offline gate (host-controlled).
    online: Arc<std::sync::atomic::AtomicBool>,
}

impl<S: MailStore + ?Sized> OutboxService<S> {
    /// Creates the service.
    pub fn new(
        storage: Arc<S>,
        smtp: SmtpParams,
        imap: ConnectParams,
        clock: Arc<dyn crate::clock::SyncClock>,
        bus: tokio::sync::mpsc::Sender<EngineEvent>,
        online: Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self {
            storage,
            smtp,
            imap,
            clock,
            bus,
            online,
        }
    }

    /// Backoff for a 1-based retry count, with deterministic jitter (±20%:
    /// stable across runs so tests can assert exact values).
    #[must_use]
    pub fn backoff_for(retry_count: u32) -> Duration {
        backoff_for(retry_count)
    }

    /// Flush loop until cancellation. Each pass drains all due entries; on
    /// cancellation one final bounded flush runs.
    pub async fn run(&self, cancel: CancellationToken) {
        let mut ticker = tokio::time::interval(Duration::from_secs(5));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                () = cancel.cancelled() => {
                    let _ = Box::pin(self.flush_once()).await;
                    return;
                }
                _ = ticker.tick() => {
                    if self.online.load(std::sync::atomic::Ordering::Relaxed) {
                        if let Err(e) = Box::pin(self.flush_once()).await {
                            tracing::warn!(error = %e, "outbox flush pass failed");
                        }
                    }
                }
            }
        }
    }

    /// Drains all due entries once. Useful for hosts that drive flushing
    /// themselves (tests, manual "send now" actions).
    ///
    /// # Errors
    /// Storage failure while listing due entries; per-entry failures are
    /// reported as events, not errors.
    pub async fn flush_once(&self) -> SyncResult<()> {
        let due = self.storage.outbox_due().await.map_err(SyncError::from)?;
        for row in due {
            match Box::pin(self.try_send(&row)).await {
                SendOutcome::Sent => {
                    let _ = self
                        .storage
                        .outbox_mark_sent(row.id, self.clock.now_unix_ms())
                        .await;
                    let _ = self
                        .bus
                        .send(EngineEvent::MailSent {
                            id: row.id,
                            message: sent_marker(),
                        })
                        .await;
                }
                SendOutcome::Transient(detail) => {
                    let retry = row.retry_count + 1;
                    let next = self.clock.now_unix_ms()
                        + i64::try_from(Self::backoff_for(retry).as_millis()).unwrap_or(0);
                    let _ = self
                        .storage
                        .outbox_mark_retry(row.id, retry, next, &detail)
                        .await;
                    let _ = self
                        .bus
                        .send(EngineEvent::OutboxRetry {
                            id: row.id,
                            attempt: retry,
                            next_in: Self::backoff_for(retry),
                            last_error: detail,
                        })
                        .await;
                    if retry >= MAX_RETRY_ATTEMPTS {
                        let _ = self
                            .bus
                            .send(EngineEvent::MailFailed {
                                id: row.id,
                                error: SyncError::RetryExhausted { attempts: retry },
                                permanent: true,
                            })
                            .await;
                    }
                }
                SendOutcome::Permanent(detail) => {
                    let _ = self
                        .bus
                        .send(EngineEvent::MailFailed {
                            id: row.id,
                            error: SyncError::MessageRejected {
                                detail: detail.clone(),
                            },
                            permanent: true,
                        })
                        .await;
                }
            }
        }
        Ok(())
    }

    async fn try_send(&self, row: &OutboxRow) -> SendOutcome {
        // Load the raw from the content store.
        let raw = match self.storage.read_blob(&row.raw_blob).await {
            Ok(raw) => raw,
            Err(e) => return SendOutcome::Permanent(format!("raw blob unavailable: {e}")),
        };
        let mut recipients: Vec<String> = row
            .envelope
            .to
            .iter()
            .chain(&row.envelope.cc)
            .chain(&row.envelope.bcc)
            .map(|a| a.email.clone())
            .collect();
        recipients.dedup();
        match smtp::submit_envelope(&self.smtp, &row.envelope.from.email, &recipients, &raw).await {
            Ok(()) => {
                // Sent APPEND (best-effort; a failure here still counts as
                // sent — the server copy exists).
                let _ = Box::pin(self.append_to_sent(&raw)).await;
                SendOutcome::Sent
            }
            Err(SyncError::SmtpTransient { code }) => {
                SendOutcome::Transient(format!("smtp {code}"))
            }
            Err(SyncError::Transport { detail } | SyncError::Tls { detail }) => {
                SendOutcome::Transient(detail)
            }
            Err(e) => SendOutcome::Permanent(e.to_string()),
        }
    }

    /// APPEND the sent raw to the account's Sent folder (best-effort).
    async fn append_to_sent(&self, raw: &[u8]) -> SyncResult<()> {
        let mut session = Box::pin(ImapSession::connect_and_authenticate(&self.imap)).await?;
        let sent_name = "Sent";
        let flags: Vec<imap_next::imap_types::flag::Flag<'static>> = vec![];
        let date = None;
        let mailbox = imap_next::imap_types::mailbox::Mailbox::try_from(sent_name.to_owned())
            .map_err(|e| SyncError::Protocol(format!("sent mailbox: {e:?}")))?;
        let outcome = Box::pin(
            session.execute(
                imap_next::imap_types::command::CommandBody::Append {
                    mailbox,
                    flags,
                    date,
                    message: imap_next::imap_types::extensions::binary::LiteralOrLiteral8::Literal(
                        imap_next::imap_types::core::Literal::try_from(raw.to_vec())
                            .map_err(|e| SyncError::Protocol(format!("append literal: {e:?}")))?,
                    ),
                },
                Duration::from_secs(60),
            ),
        )
        .await?;
        Box::pin(session.logout()).await;
        if outcome.is_ok() {
            Ok(())
        } else {
            // Non-fatal: mail is delivered; Sent filing failed.
            tracing::warn!("Sent APPEND failed: {}", outcome.status_summary());
            Ok(())
        }
    }
}

enum SendOutcome {
    Sent,
    Transient(String),
    Permanent(String),
}

/// Backoff for a 1-based retry count: the documented schedule scaled by
/// deterministic ±20% jitter derived from the retry counter.
#[must_use]
pub fn backoff_for(retry_count: u32) -> Duration {
    // Schedule values are far below 2^52; the float round-trip is exact.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    {
        let idx = (retry_count.saturating_sub(1)) as usize % BACKOFF_SCHEDULE_MS.len();
        let base = BACKOFF_SCHEDULE_MS[idx];
        let jitter = 1.0 + (f64::from(retry_count % 10) / 25.0) - 0.2;
        Duration::from_millis((base as f64 * jitter) as u64)
    }
}

/// The outbox row is the durable record; `MailSent` carries the outbox id
/// mapped onto a fresh message id for host-side lists.
fn sent_marker() -> MessageId {
    MessageId::from_uuid(uuid::Uuid::now_v7())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_matches_documented_schedule_with_jitter() {
        // Base table: 30s, 120s, 480s, 30m, 2h, then 6h forever.
        // Schedule values are far below 2^52; the float round-trip is exact.
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss
        )]
        let expected = |attempt: u32, base_ms: u64| {
            let jitter = 1.0 + (f64::from(attempt % 10) / 25.0) - 0.2;
            Duration::from_millis((base_ms as f64 * jitter) as u64)
        };
        let cases = [
            (1, 30_000),
            (2, 120_000),
            (3, 480_000),
            (4, 1_800_000),
            (5, 7_200_000),
            (6, 21_600_000),
            (13, 30_000), // wraps
        ];
        for (attempt, base_ms) in cases {
            let backoff = backoff_for(attempt);
            assert_eq!(backoff, expected(attempt, base_ms));
            // Jitter stays within ±20% of the base.
            let base = Duration::from_millis(base_ms);
            assert!(backoff >= base.mul_f64(0.79) && backoff <= base.mul_f64(1.21));
        }
    }

    #[test]
    fn backoff_zero_and_overflow_are_safe() {
        assert!(backoff_for(0).as_millis() > 0);
        assert!(backoff_for(u32::MAX).as_millis() > 0);
    }
}
