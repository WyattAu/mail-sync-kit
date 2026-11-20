# Pattern adoption

| Pattern | Status | Evidence |
|---|---|---|
| T32 | adopted | src/store.rs:111 (OutboxRow persisted in the durable store), src/outbox_service.rs:1 (drains due rows through SMTP with a documented backoff schedule) |
| P20 | adopted | src/clock.rs:39 (FakeClock with advance for deterministic replay), src/outbox_service.rs:35 (clock injected into the service) |
| T13 | adopted | src/store.rs:205 (MailStore trait as the core boundary), src/jmap_sync.rs:19 (host-injected parse function), src/event.rs:1 (events are hints, never source of truth) |
| T25 | partial | src/outbox_service.rs:3 (offline mode defers flushing), src/jmap_sync.rs:5 (delta sync through JMAP state tokens) |
