# Changelog

All notable changes to this project are documented here. Format: [Keep a
Changelog](https://keepachangelog.com/) — versions follow [semver](https://semver.org).

## [Unreleased]

## [0.1.1] - 2026-09-12

### Fixed
- **Dead knob: `ConnectParams::mechanisms` never took effect.** Session
  capabilities were recorded with `format!("{c:?}")` (`Auth(Plain)`,
  `Imap4Rev1`, …) while `has_capability` matches wire names
  (`AUTH=PLAIN`, `IMAP4rev1`, …), so the SASL intersection in
  `authenticate` never matched and every account silently fell back to
  `LOGIN` — the configured mechanism preference was settable but
  never read. Capabilities are now recorded with `Display` (wire names)
  via `ImapSession::absorb_capability_list`, shared by the greeting and
  untagged-CAPABILITY paths.

### Added
- `SyncService::{should_poll, idle_timeout, poll_interval,
  prefetch_limit}` — public accessors exposing the `SyncConfig`
  decision points (`run_one_cycle` / `prefetch_recent` branch on these
  exact methods, so the knobs stay observable at the API boundary).
- `tests/config_matrix.rs`: every tuning knob behavior-proven — all four
  `SyncConfig` fields through the accessor seam (including
  case-insensitive `idle_poll_only_hosts` matching), plus the
  `mechanisms` dead-knob regression test against a loopback fake IMAP
  server (`[Plain]` + `AUTH=PLAIN` advertised → `AUTHENTICATE` on the
  wire; `[]` → `LOGIN`; proven to fail on the pre-fix code).
  Dead-knob sweep found one dead knob (`mechanisms`, fixed above).
