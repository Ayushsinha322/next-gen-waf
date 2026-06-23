//! Rate limiting module — token-bucket limiter per-IP, per-site, and global.
//!
//! Uses a token bucket algorithm backed by a lock-free `DashMap` so multiple
//! tokio worker threads can access buckets concurrently without a global lock.
//!
//! Checked at Phase 1 (request headers) after the site is identified.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use sentinel_core::config::RateLimitConfig;
use sentinel_storage::RedisClient;

// ---------------------------------------------------------------------------
// Token bucket
// ---------------------------------------------------------------------------

/// A token bucket that refills at `refill_rate` tokens/second up to `capacity`.
///
/// Each call to [`TokenBucket::try_consume`] attempts to take one token.  If
/// no tokens are available the request is rejected (rate-limited).
#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    capacity: f64,
    /// Tokens added per second.
    refill_rate: f64,
    last_refill: Instant,
    /// Updated on every `try_consume` call; used by GC to evict idle buckets.
    last_used: Instant,
}

impl TokenBucket {
    fn new(rps: u32, burst: u32) -> Self {
        let now = Instant::now();
        Self {
            tokens: burst as f64,
            capacity: burst as f64,
            refill_rate: rps as f64,
            last_refill: now,
            last_used: now,
        }
    }

    /// Refill tokens based on elapsed time, then try to consume one.
    ///
    /// Returns `true` if the request is allowed, `false` if rate-limited.
    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
        self.last_refill = now;
        self.last_used = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// RateLimiter
// ---------------------------------------------------------------------------

/// Concurrent rate limiter.
///
/// Stores two separate bucket maps:
/// - `per_ip` — keyed by `(site_id, client_ip)`, enforces per-client limits.
/// - `per_site` — keyed by `site_id`, enforces site-wide aggregate limits.
///
/// The `RateLimiter` is intentionally **not** rebuilt on config hot-reload so
/// that accumulated bucket state (token counts) is preserved across reloads.
pub struct RateLimiter {
    per_ip: DashMap<(String, IpAddr), TokenBucket>,
    per_site: DashMap<String, TokenBucket>,
    /// Optional distributed backend.  When present, limits are enforced via an
    /// atomic Redis sliding window shared across all WAF nodes; when `None`,
    /// the in-memory token buckets above are used (single-instance only).
    redis: Option<Arc<RedisClient>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::with_redis(None)
    }

    /// Construct a limiter with an optional distributed Redis backend.
    pub fn with_redis(redis: Option<Arc<RedisClient>>) -> Self {
        Self {
            per_ip: DashMap::new(),
            per_site: DashMap::new(),
            redis,
        }
    }

    /// `true` if a distributed (Redis) backend is active.
    pub fn is_distributed(&self) -> bool {
        self.redis.is_some()
    }

    /// Distributed rate check.  Uses the shared Redis sliding window when a
    /// backend is configured; otherwise delegates to the in-memory [`check`].
    ///
    /// Returns `true` (= **block request**) if any limit is exceeded.  On any
    /// Redis error the check degrades to the in-memory limiter rather than
    /// failing open, so a Redis outage never disables rate limiting entirely.
    ///
    /// [`check`]: RateLimiter::check
    pub async fn check_async(
        &self,
        site_id: &str,
        ip: IpAddr,
        config: &RateLimitConfig,
    ) -> bool {
        let Some(redis) = &self.redis else {
            return self.check(site_id, ip, config);
        };

        // 1-second sliding window; allow `rps + burst` requests within it so
        // short bursts pass while sustained rate is capped (mirrors the
        // token-bucket semantics of the in-memory path).
        const WINDOW_MS: u64 = 1000;
        let mut limited = false;

        if let Some(ref global) = config.global {
            let key = format!("rate:site:{site_id}");
            let limit = (global.rps + global.burst) as u64;
            match redis.rate_check(&key, limit, WINDOW_MS).await {
                Ok(allowed) => limited |= !allowed,
                Err(e) => {
                    tracing::warn!(error = %e, "redis rate_check failed — falling back to in-memory");
                    return self.check(site_id, ip, config);
                }
            }
        }

        if let Some(ref per_ip_cfg) = config.per_ip {
            let key = format!("rate:ip:{site_id}:{ip}");
            let limit = (per_ip_cfg.rps + per_ip_cfg.burst) as u64;
            match redis.rate_check(&key, limit, WINDOW_MS).await {
                Ok(allowed) => limited |= !allowed,
                Err(e) => {
                    tracing::warn!(error = %e, "redis rate_check failed — falling back to in-memory");
                    return self.check(site_id, ip, config);
                }
            }
        }

        limited
    }

    /// Check whether a request should be rate-limited.
    ///
    /// Returns `true` (= **block request**) if any limit is exceeded.
    /// Both the per-site aggregate and per-IP limit are checked; the stricter
    /// one wins.
    pub fn check(&self, site_id: &str, ip: IpAddr, config: &RateLimitConfig) -> bool {
        // Per-site aggregate limit is checked first.  If it fires we still
        // consume a per-IP token so that per-IP bookkeeping stays accurate.
        let site_limited = if let Some(ref global) = config.global {
            let mut bucket = self
                .per_site
                .entry(site_id.to_string())
                .or_insert_with(|| TokenBucket::new(global.rps, global.burst));
            !bucket.try_consume()
        } else {
            false
        };

        let ip_limited = if let Some(ref per_ip_cfg) = config.per_ip {
            let key = (site_id.to_string(), ip);
            let mut bucket = self
                .per_ip
                .entry(key)
                .or_insert_with(|| TokenBucket::new(per_ip_cfg.rps, per_ip_cfg.burst));
            !bucket.try_consume()
        } else {
            false
        };

        site_limited || ip_limited
    }

    /// Number of active per-IP buckets (useful for metrics / GC decisions).
    pub fn per_ip_bucket_count(&self) -> usize {
        self.per_ip.len()
    }

    /// Number of active per-site buckets.
    pub fn per_site_bucket_count(&self) -> usize {
        self.per_site.len()
    }

    /// Evict buckets that have not seen traffic in the last 5 minutes.
    ///
    /// The previous approach (retain only non-full buckets) was incorrect:
    /// any bucket that had ever consumed a token kept `tokens < capacity`
    /// permanently and was never evicted, causing unbounded memory growth.
    /// TTL-based eviction correctly handles both idle and exhausted buckets.
    pub fn gc(&self) {
        const TTL: Duration = Duration::from_secs(300);
        let now = Instant::now();
        self.per_ip.retain(|_, v| now.duration_since(v.last_used) < TTL);
        self.per_site.retain(|_, v| now.duration_since(v.last_used) < TTL);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_core::config::{RateLimitConfig, RateWindow};
    use std::net::{IpAddr, Ipv4Addr};

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn config_rps(rps: u32, burst: u32) -> RateLimitConfig {
        RateLimitConfig {
            global: None,
            per_ip: Some(RateWindow { rps, burst }),
        }
    }

    #[test]
    fn burst_allows_initial_requests() {
        let rl = RateLimiter::new();
        let cfg = config_rps(1, 5); // 1 rps, burst of 5
        let ip = ipv4(1, 2, 3, 4);

        for _ in 0..5 {
            assert!(!rl.check("site1", ip, &cfg), "should allow up to burst");
        }
        // 6th request exceeds burst
        assert!(rl.check("site1", ip, &cfg), "should rate-limit after burst");
    }

    #[test]
    fn different_ips_have_independent_buckets() {
        let rl = RateLimiter::new();
        let cfg = config_rps(1, 2);
        let ip1 = ipv4(10, 0, 0, 1);
        let ip2 = ipv4(10, 0, 0, 2);

        // ip1 exhausts its burst
        assert!(!rl.check("site1", ip1, &cfg));
        assert!(!rl.check("site1", ip1, &cfg));
        assert!(rl.check("site1", ip1, &cfg)); // ip1 rate-limited

        // ip2 still has its own fresh bucket
        assert!(!rl.check("site1", ip2, &cfg));
    }

    #[test]
    fn same_ip_different_sites_independent() {
        let rl = RateLimiter::new();
        let cfg = config_rps(1, 1);
        let ip = ipv4(5, 5, 5, 5);

        assert!(!rl.check("site-a", ip, &cfg));
        assert!(rl.check("site-a", ip, &cfg)); // site-a exhausted

        // site-b has its own bucket → should still allow
        assert!(!rl.check("site-b", ip, &cfg));
    }

    #[test]
    fn per_site_global_limit() {
        let rl = RateLimiter::new();
        let cfg = RateLimitConfig {
            global: Some(RateWindow { rps: 100, burst: 3 }),
            per_ip: None,
        };
        let ip = ipv4(1, 1, 1, 1);

        assert!(!rl.check("site1", ip, &cfg));
        assert!(!rl.check("site1", ip, &cfg));
        assert!(!rl.check("site1", ip, &cfg));
        // 4th request exceeds site burst
        assert!(rl.check("site1", ip, &cfg));
    }

    #[test]
    fn no_config_never_rate_limits() {
        let rl = RateLimiter::new();
        let cfg = RateLimitConfig {
            global: None,
            per_ip: None,
        };
        let ip = ipv4(9, 9, 9, 9);
        for _ in 0..1000 {
            assert!(!rl.check("site1", ip, &cfg));
        }
    }
}
