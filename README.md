# mail-sync-kit

Protocol-agnostic mail sync engines: IMAP (CONDSTORE deltas, UIDVALIDITY
reconciliation, IDLE with polling fallback), JMAP (RFC 8620/8621), SMTP
submission (XOAUTH2/PLAIN/LOGIN), and an outbox queue with a documented
retry schedule.

## Installation

```toml
[dependencies]
mail-sync-kit = "0.1"
```

## Trait boundaries

The crate owns its entire vocabulary — no application core is required.
Everything is injected:

| Seam | Type | Notes |
|------|------|-------|
| Storage | `MailStore` (trait, `async_trait`) | 14 methods: folders, ingest, cursors, blobs, outbox. |
| Parsed mail | `MailStore::Parsed` (associated type) + `ParseFn<P>` | Engines build your MIME model through a callback and never inspect it. |
| Events | `EngineEvent` (enum) | Emitted on an `mpsc::Sender<EngineEvent>` you provide. |
| Time | `SyncClock` (trait) | `SystemClock` provided; `FakeClock` for determinism. |
| Config | `SyncConfig` (struct) | Poll/IDLE/prefetch tuning with sane defaults. |
| Auth | `SaslSession` (trait) + `SaslFactory` | Mechanism implementations are host callbacks; PLAIN/SCRAM/XOAUTH2 live outside. |
| Errors | `SyncError` / `StoreError` | `thiserror` enums; storage failures arrive wrapped. |

## Engines

- `SyncService` — per-account IMAP state machine: Disconnected → Connecting →
  Authenticating → Hierarchy → Delta → IDLE, with exponential-backoff
  reconnects and UIDVALIDITY reconciliation.
- `JmapSyncService` — the JMAP analogue: session discovery, `Mailbox/get`
  hierarchy, `Email/query` + `Email/get` delta sync via state tokens.
- `OutboxService` — drains due rows through SMTP, files sent mail via IMAP
  APPEND, emits `OutboxRetry`/`MailSent`/`MailFailed`, and honors an
  offline gate. `flush_once()` is available for hosts that drive flushing
  themselves.
- `ImapSession` — the single-flight IMAP session driver (TLS, STARTTLS,
  SASL AUTHENTICATE with continuations, IDLE).
- `submit_envelope` — raw RFC 5322 SMTP submission with explicit envelope
  (Bcc-safe).

`tls::webpki_connector()` builds a rustls connector over the bundled
Mozilla roots; bring your own `TlsConnector` for custom PKI.

## License

MIT OR Apache-2.0.
