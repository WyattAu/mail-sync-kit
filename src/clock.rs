//! Clock abstraction: determinism first. Wall-clock time crosses the crate
//! as `i64` milliseconds since the Unix epoch. Timeouts and durations use
//! `tokio::time` directly and are controlled in tests via
//! `tokio::time::pause`.

use std::{
    sync::RwLock,
    time::{SystemTime, UNIX_EPOCH},
};

/// Milliseconds since the Unix epoch.
pub type UnixMillis = i64;

/// Source of wall-clock time; injectable for deterministic tests.
pub trait SyncClock: Send + Sync {
    /// Current wall time in milliseconds since the epoch.
    fn now_unix_ms(&self) -> UnixMillis;
}

/// Production clock backed by the system clock. The single audited site
/// allowed to call `SystemTime::now`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl SyncClock for SystemClock {
    fn now_unix_ms(&self) -> UnixMillis {
        // INVARIANT: audited site — the clock abstraction itself. All other
        // code must go through `Clock`.
        #[allow(clippy::disallowed_methods)]
        let now = SystemTime::now();
        now.duration_since(UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
            .unwrap_or_default()
    }
}

/// Deterministic fake clock for tests and reproducible ingestion runs.
#[derive(Debug, Default)]
pub struct FakeClock {
    now: RwLock<UnixMillis>,
}

impl FakeClock {
    /// Creates a clock fixed at `start`.
    #[must_use]
    pub fn new(start: UnixMillis) -> Self {
        Self {
            now: RwLock::new(start),
        }
    }

    /// Advances the clock by `millis`.
    pub fn advance(&self, millis: UnixMillis) {
        if let Ok(mut now) = self.now.write() {
            *now += millis;
        }
    }
}

impl SyncClock for FakeClock {
    fn now_unix_ms(&self) -> UnixMillis {
        self.now.read().map_or(0, |n| *n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_clock_is_deterministic() {
        let c = FakeClock::new(1_000);
        assert_eq!(c.now_unix_ms(), 1_000);
        c.advance(500);
        assert_eq!(c.now_unix_ms(), 1_500);
    }

    #[test]
    fn system_clock_is_monotonic_enough() {
        let c = SystemClock;
        let a = c.now_unix_ms();
        let b = c.now_unix_ms();
        assert!(b >= a);
        assert!(a > 1_600_000_000_000); // sane epoch: after 2020-09
    }
}
