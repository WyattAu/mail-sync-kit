//! Sync engine tuning knobs (the sync slice of a host's config).
//!
//! The engines take an `Arc<SyncConfig>`; hosts map their own configuration
//! format onto this struct.

/// Sync engine tuning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncConfig {
    /// Poll interval fallback when IDLE is unavailable/broken (seconds).
    pub poll_interval_secs: u64,
    /// IDLE re-issue interval; must stay under the common 30 min server
    /// cutoff.
    pub idle_timeout_mins: u64,
    /// How many recent bodies per folder to prefetch in the background.
    pub body_prefetch_recent: usize,
    /// Hosts where IDLE is known broken: always poll.
    pub idle_poll_only_hosts: Vec<String>,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            poll_interval_secs: 120,
            idle_timeout_mins: 29,
            body_prefetch_recent: 200,
            idle_poll_only_hosts: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_stay_under_server_idle_cutoff() {
        let cfg = SyncConfig::default();
        assert!(cfg.idle_timeout_mins < 30, "IDLE re-issue must stay under the common 30 min server cutoff");
        assert!(cfg.poll_interval_secs > 0);
        assert!(cfg.body_prefetch_recent > 0);
    }
}
