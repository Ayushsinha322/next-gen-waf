//! Anti-DDoS module — connection-rate limiting with automatic IP blocking.
//!
//! Checked at Phase 0 (per new TCP connection), before any HTTP parsing or
//! site matching.  Tracks new connections per source IP in a 1-second sliding
//! window.  IPs exceeding the configured threshold are blocked for a
//! configurable duration.
//!
//! ## Architecture
//! The module is pure userspace Rust — no kernel or eBPF dependencies.
//! It integrates with the proxy's Phase 0 hook and shares the same Tokio
//! runtime as the rest of the data plane.
//!
//! A background task should call [`AntiDdos::gc`] every ~60 seconds to
//! evict expired blocks and stale tracking entries.
//!
//! ## eBPF forward-compat
//! The `DdosVerdict` enum and `check_connection` signature are designed so
//! that a future eBPF/XDP tier can produce the same verdict type.  When the
//! XDP tier is added it will short-circuit before this module runs for
//! already-blocked IPs; this module handles the detection / decision logic.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use sentinel_core::config::AntiDdosConfig;
use tracing::{debug, info};

// ---------------------------------------------------------------------------
// Internal state per tracked IP
// ---------------------------------------------------------------------------

struct ConnectionStats {
    /// Number of connections seen in the current 1-second window.
    count: u32,
    /// When the current window started.
    window_start: Instant,
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Result of a DDoS connection check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DdosVerdict {
    /// Connection is allowed.
    Allow,
    /// Connection is blocked — IP is under active DDoS mitigation.
    Block { reason: String },
}

// ---------------------------------------------------------------------------
// AntiDdos
// ---------------------------------------------------------------------------

/// Stateful connection-rate DDoS protector.
///
/// Thread-safe — uses lock-free `DashMap`s so multiple tokio workers can
/// call `check_connection` concurrently without a global lock.
///
/// Not rebuilt on config hot-reload so that active blocks and tracked rates
/// are preserved across config changes (same design as `RateLimiter`).
pub struct AntiDdos {
    /// Per-IP connection stats in the current sliding window.
    stats: DashMap<IpAddr, ConnectionStats>,
    /// Per-IP block-expiry timestamps.  Entry present ↔ IP is blocked.
    blocked: DashMap<IpAddr, Instant>,
    /// Combined threshold: burst + conn_rate_limit.
    threshold: u32,
    /// How long a violating IP remains blocked.
    block_duration: Duration,
    /// Width of the sliding window (always 1 second).
    window: Duration,
    /// `true` when protection is actually enabled; `false` → always Allow.
    enabled: bool,
}

impl AntiDdos {
    /// Build from config.  Rate state is empty (fresh start).
    pub fn new(config: &AntiDdosConfig) -> Self {
        let threshold = config.burst.saturating_add(config.conn_rate_limit);
        if config.enabled {
            info!(
                threshold,
                burst = config.burst,
                conn_rate = config.conn_rate_limit,
                block_secs = config.block_duration_secs,
                "anti-DDoS protection enabled"
            );
        }
        Self {
            stats: DashMap::new(),
            blocked: DashMap::new(),
            threshold,
            block_duration: Duration::from_secs(config.block_duration_secs),
            window: Duration::from_secs(1),
            enabled: config.enabled,
        }
    }

    /// Disabled instance — `check_connection` always returns `Allow`.
    pub fn disabled() -> Self {
        Self {
            stats: DashMap::new(),
            blocked: DashMap::new(),
            threshold: u32::MAX,
            block_duration: Duration::from_secs(300),
            window: Duration::from_secs(1),
            enabled: false,
        }
    }

    /// Called once per accepted TCP connection in Phase 0.
    ///
    /// Returns `DdosVerdict::Block` if:
    /// - The IP is currently in the block list, OR
    /// - The IP has exceeded the connection-rate threshold this second.
    pub fn check_connection(&self, ip: IpAddr) -> DdosVerdict {
        if !self.enabled {
            return DdosVerdict::Allow;
        }

        let now = Instant::now();

        // 1. Check active block list first (hot path for ongoing attack).
        if let Some(entry) = self.blocked.get(&ip) {
            if now < *entry {
                return DdosVerdict::Block {
                    reason: format!("DDoS mitigation: {ip} is temporarily blocked"),
                };
            }
            // Block expired — remove it.
            drop(entry);
            self.blocked.remove(&ip);
        }

        // 2. Update sliding-window connection count.
        let count = {
            let mut stats = self.stats.entry(ip).or_insert_with(|| ConnectionStats {
                count: 0,
                window_start: now,
            });
            let elapsed = now.duration_since(stats.window_start);
            if elapsed >= self.window {
                // New window: reset counter.
                stats.count = 1;
                stats.window_start = now;
            } else {
                stats.count = stats.count.saturating_add(1);
            }
            stats.count
        };

        // 3. Enforce threshold.
        if count > self.threshold {
            let unblock_at = now + self.block_duration;
            self.blocked.insert(ip, unblock_at);
            let reason = format!(
                "DDoS mitigation: connection rate {count}/s from {ip} exceeds threshold {}/s",
                self.threshold
            );
            debug!(ip = %ip, count, threshold = self.threshold, "anti-DDoS: blocking IP");
            return DdosVerdict::Block { reason };
        }

        DdosVerdict::Allow
    }

    /// Number of IPs currently in the active block list.
    pub fn blocked_count(&self) -> usize {
        self.blocked.len()
    }

    /// Number of IPs being tracked (not necessarily blocked).
    pub fn tracked_count(&self) -> usize {
        self.stats.len()
    }

    /// Evict expired blocks and stale rate-tracking entries.
    ///
    /// Should be called every ~60 seconds by a background task.  A stale
    /// stats entry is one whose window started more than 10 seconds ago —
    /// any attack would have already triggered a block by then.
    pub fn gc(&self) {
        let now = Instant::now();
        let stale_threshold = self.window * 10;

        let expired_blocks = self.blocked.iter()
            .filter(|e| now >= *e.value())
            .map(|e| *e.key())
            .collect::<Vec<_>>();
        let block_removed = expired_blocks.len();
        for ip in expired_blocks {
            self.blocked.remove(&ip);
        }

        let stale_stats = self.stats.iter()
            .filter(|e| now.duration_since(e.value().window_start) > stale_threshold)
            .map(|e| *e.key())
            .collect::<Vec<_>>();
        let stats_removed = stale_stats.len();
        for ip in stale_stats {
            self.stats.remove(&ip);
        }

        if block_removed > 0 || stats_removed > 0 {
            debug!(
                expired_blocks = block_removed,
                stale_stats = stats_removed,
                "anti-DDoS GC complete"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn make_ddos(conn_rate: u32, burst: u32, block_secs: u64) -> AntiDdos {
        let cfg = AntiDdosConfig {
            enabled: true,
            conn_rate_limit: conn_rate,
            burst,
            block_duration_secs: block_secs,
        };
        AntiDdos::new(&cfg)
    }

    #[test]
    fn disabled_always_allows() {
        let ddos = AntiDdos::disabled();
        let ip = ip(1, 2, 3, 4);
        for _ in 0..10_000 {
            assert_eq!(ddos.check_connection(ip), DdosVerdict::Allow);
        }
    }

    #[test]
    fn allows_under_threshold() {
        // threshold = burst(5) + rate(10) = 15
        let ddos = make_ddos(10, 5, 60);
        let ip = ip(10, 0, 0, 1);
        for _ in 0..15 {
            assert_eq!(ddos.check_connection(ip), DdosVerdict::Allow);
        }
    }

    #[test]
    fn blocks_after_threshold_exceeded() {
        // threshold = 2 + 1 = 3; 4th connection should block.
        let ddos = make_ddos(2, 1, 60);
        let ip = ip(10, 0, 0, 2);
        assert_eq!(ddos.check_connection(ip), DdosVerdict::Allow); // 1
        assert_eq!(ddos.check_connection(ip), DdosVerdict::Allow); // 2
        assert_eq!(ddos.check_connection(ip), DdosVerdict::Allow); // 3 (= threshold)
        // 4th exceeds threshold → block
        assert!(matches!(ddos.check_connection(ip), DdosVerdict::Block { .. }));
    }

    #[test]
    fn blocked_ip_stays_blocked_across_calls() {
        let ddos = make_ddos(1, 0, 60); // threshold = 1
        let ip = ip(10, 0, 0, 3);
        // First connection: count = 1 = threshold, allowed.
        ddos.check_connection(ip);
        // Second connection: count = 2 > threshold, triggers block.
        let _ = ddos.check_connection(ip);
        // All subsequent calls return Block.
        assert!(matches!(ddos.check_connection(ip), DdosVerdict::Block { .. }));
        assert!(matches!(ddos.check_connection(ip), DdosVerdict::Block { .. }));
        assert_eq!(ddos.blocked_count(), 1);
    }

    #[test]
    fn different_ips_tracked_independently() {
        let ddos = make_ddos(1, 1, 60); // threshold = 2
        let ip1 = ip(10, 0, 0, 4);
        let ip2 = ip(10, 0, 0, 5);
        // Exhaust ip1's budget.
        ddos.check_connection(ip1);
        ddos.check_connection(ip1);
        let r = ddos.check_connection(ip1);
        assert!(matches!(r, DdosVerdict::Block { .. }));
        // ip2 has its own fresh budget.
        assert_eq!(ddos.check_connection(ip2), DdosVerdict::Allow);
    }

    #[test]
    fn gc_removes_expired_blocks() {
        let mut cfg = AntiDdosConfig {
            enabled: true,
            conn_rate_limit: 0,
            burst: 0,
            block_duration_secs: 0, // expires instantly
        };
        cfg.block_duration_secs = 0;
        let ddos = AntiDdos::new(&cfg);
        let ip = ip(10, 0, 0, 6);
        // Force a block by exceeding threshold (threshold = 0+0 = 0, but
        // saturating_add means threshold = 0, every conn triggers block).
        // threshold = 0 means count(1) > 0 → block on first call.
        let _ = ddos.check_connection(ip);
        // Regardless of exact behavior, force populate blocked map.
        ddos.blocked.insert(ip, Instant::now() - Duration::from_secs(1));
        assert_eq!(ddos.blocked_count(), 1);
        ddos.gc();
        assert_eq!(ddos.blocked_count(), 0);
    }

    #[test]
    fn gc_removes_stale_stats() {
        let ddos = make_ddos(100, 50, 60);
        let ip = ip(10, 0, 0, 7);
        // Insert a stale stat entry (window started 20s ago).
        ddos.stats.insert(
            ip,
            ConnectionStats {
                count: 5,
                window_start: Instant::now() - Duration::from_secs(20),
            },
        );
        assert_eq!(ddos.tracked_count(), 1);
        ddos.gc();
        assert_eq!(ddos.tracked_count(), 0);
    }
}
