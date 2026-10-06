//! Rate limiting module — token-bucket limiter per-IP, per-site, and global.
//!
//! Uses a token bucket algorithm backed by a lock-free `DashMap` so multiple
//! tokio worker threads can access buckets concurrently without a global lock.
//!
//! Checked at Phase 1 (request headers) after the site is identified.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
use dashmap::DashMap;
use sentinel_core::config::RateLimitConfig;
use sentinel_storage::{RedisClient, StorageError};
use serde::Serialize;

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
// Distributed backend guard
// ---------------------------------------------------------------------------

/// How the request path treats the distributed (Valkey) backend.
///
/// The rate check sits on every request of a rate-limited site, so a Valkey
/// that is slow or gone must cost a bounded, small amount of latency — and,
/// once it is clearly down, nothing at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DistributedGuard {
    /// Budget for the Valkey round trips of ONE rate check (both the site-wide
    /// and the per-IP window). Past it the check is answered in-memory.
    pub timeout: Duration,
    /// Consecutive errors or timeouts that open the breaker.
    pub failure_threshold: u32,
    /// How long an open breaker skips Valkey before letting one probe through.
    pub cooldown: Duration,
}

impl Default for DistributedGuard {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(50),
            failure_threshold: 5,
            cooldown: Duration::from_secs(5),
        }
    }
}

impl DistributedGuard {
    /// Defaults overridden by `SENTINEL_REDIS_TIMEOUT_MS` (1..=500),
    /// `SENTINEL_REDIS_BREAKER_FAILURES` (1..=1000) and
    /// `SENTINEL_REDIS_BREAKER_COOLDOWN_MS` (100..=600000). Out-of-range or
    /// unparseable values keep the default, with a warning.
    ///
    /// The timeout's ceiling is the Valkey client's own per-command timeout
    /// ([`sentinel_storage::redis::RESPONSE_TIMEOUT`]): each call fails there
    /// first, so a larger budget was accepted and silently had no effect.
    pub fn from_env() -> Self {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let num = |k: &str, lo: u64, hi: u64| {
            let raw = lookup(k)?;
            let v = raw
                .trim()
                .parse::<u64>()
                .ok()
                .filter(|v| (lo..=hi).contains(v));
            if v.is_none() {
                tracing::warn!(
                    var = k,
                    value = %raw,
                    min = lo,
                    max = hi,
                    "ignoring out-of-range rate-limit backend setting — using the default"
                );
            }
            v
        };
        let max_timeout_ms = sentinel_storage::redis::RESPONSE_TIMEOUT.as_millis() as u64;
        let d = Self::default();
        Self {
            timeout: num("SENTINEL_REDIS_TIMEOUT_MS", 1, max_timeout_ms)
                .map(Duration::from_millis)
                .unwrap_or(d.timeout),
            failure_threshold: num("SENTINEL_REDIS_BREAKER_FAILURES", 1, 1000)
                .map(|v| v as u32)
                .unwrap_or(d.failure_threshold),
            cooldown: num("SENTINEL_REDIS_BREAKER_COOLDOWN_MS", 100, 600_000)
                .map(Duration::from_millis)
                .unwrap_or(d.cooldown),
        }
    }
}

/// Minimum spacing of the per-failure warnings, and of the breaker's OPEN lines.
/// Individual failures under a dead Valkey would otherwise be one line per
/// request, and a flapping breaker one WARN and one INFO per cycle.
const WARN_INTERVAL_MS: u64 = 10_000;

/// Lock-free circuit breaker over the Valkey calls.
///
/// Closed: every check asks Valkey. After `failure_threshold` consecutive
/// failures it opens: checks skip Valkey (in-memory limiter) for `cooldown`.
/// Then the first check to arrive re-arms the cooldown and probes; a success
/// closes the breaker, a failure leaves it open for another cooldown. Re-arming
/// BEFORE the probe means a probe that never completes (its request cancelled)
/// cannot wedge the breaker half-open.
///
/// Only the probe can close it. Calls admitted while it was still closed keep
/// completing after it opens, and when Valkey only partly fails (latency near
/// the budget) some of those succeed; letting any success close the breaker
/// reopened and reclosed it thousands of times a minute while shedding almost
/// no load.
#[derive(Debug)]
struct Breaker {
    epoch: Instant,
    /// Milliseconds since `epoch` (plus one, so 0 is free) until which Valkey
    /// is skipped; 0 = closed.
    open_until: AtomicU64,
    consecutive_failures: AtomicU32,
    errors_total: AtomicU64,
    timeouts_total: AtomicU64,
    fallback_total: AtomicU64,
    opened_total: AtomicU64,
    last_warn: AtomicU64,
    suppressed_warnings: AtomicU64,
    /// What the log last said: an OPEN line not yet followed by a CLOSE line.
    logged_open: AtomicBool,
    last_open_line: AtomicU64,
    /// Transitions not logged since the last transition line.
    suppressed_transitions: AtomicU64,
    /// Added to the clock, so tests can step past a cooldown without sleeping.
    #[cfg(test)]
    skew_ms: AtomicU64,
}

/// How a rate check was let through the breaker. The completion is judged by
/// it: only a [`Probe`](Admission::Probe) success closes an open breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admission {
    /// The breaker was closed: ask Valkey.
    Closed,
    /// The cooldown is over and this check won the probe.
    Probe,
    /// Open: answer in-memory without asking Valkey.
    Skip,
}

/// Breaker position, as reported at /healthz.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BreakerState {
    Closed,
    Open,
    /// Cooldown over; the next check probes Valkey.
    HalfOpen,
}

impl Breaker {
    fn new() -> Self {
        Self {
            epoch: Instant::now(),
            open_until: AtomicU64::new(0),
            consecutive_failures: AtomicU32::new(0),
            errors_total: AtomicU64::new(0),
            timeouts_total: AtomicU64::new(0),
            fallback_total: AtomicU64::new(0),
            opened_total: AtomicU64::new(0),
            last_warn: AtomicU64::new(0),
            suppressed_warnings: AtomicU64::new(0),
            logged_open: AtomicBool::new(false),
            last_open_line: AtomicU64::new(0),
            suppressed_transitions: AtomicU64::new(0),
            #[cfg(test)]
            skew_ms: AtomicU64::new(0),
        }
    }

    fn now_ms(&self) -> u64 {
        let ms = self.epoch.elapsed().as_millis() as u64 + 1;
        #[cfg(test)]
        let ms = ms + self.skew_ms.load(Ordering::Relaxed);
        ms
    }

    #[cfg(test)]
    fn advance(&self, d: Duration) {
        self.skew_ms
            .fetch_add(d.as_millis() as u64, Ordering::Relaxed);
    }

    fn admit(&self, cooldown: Duration) -> Admission {
        let until = self.open_until.load(Ordering::Acquire);
        if until == 0 {
            return Admission::Closed;
        }
        let now = self.now_ms();
        if now < until {
            return Admission::Skip;
        }
        // Cooldown over: exactly one caller wins the re-arm and probes.
        match self.open_until.compare_exchange(
            until,
            now + cooldown.as_millis() as u64,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => Admission::Probe,
            Err(_) => Admission::Skip,
        }
    }

    fn on_success(&self, admission: Admission) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        if admission == Admission::Probe && self.open_until.swap(0, Ordering::AcqRel) != 0 {
            self.log_closed();
        }
    }

    fn on_failure(
        &self,
        guard: &DistributedGuard,
        admission: Admission,
        timed_out: bool,
        detail: &str,
    ) {
        if timed_out {
            self.timeouts_total.fetch_add(1, Ordering::Relaxed);
        } else {
            self.errors_total.fetch_add(1, Ordering::Relaxed);
        }
        let n = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;

        if self.open_until.load(Ordering::Acquire) == 0 && n >= guard.failure_threshold {
            let until = self.now_ms() + guard.cooldown.as_millis() as u64;
            if self
                .open_until
                .compare_exchange(0, until, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.opened_total.fetch_add(1, Ordering::Relaxed);
                self.log_open(guard, n, detail, true);
                return;
            }
        }
        if admission == Admission::Probe {
            // Still open, for another cooldown. If the OPEN line was
            // suppressed, this is where the log catches up with the state.
            self.log_open(guard, n, detail, false);
        }
        self.warn_throttled(|suppressed| {
            tracing::warn!(
                error = detail,
                timed_out,
                consecutive_failures = n,
                suppressed,
                "valkey rate check failed — answered by the in-memory limiter"
            )
        });
    }

    /// The breaker opened (`transition`), or a probe failed and it stays open.
    /// One OPEN line per [`WARN_INTERVAL_MS`] at most, and none while the log
    /// already says open; a skipped transition is counted into the next line.
    fn log_open(&self, guard: &DistributedGuard, n: u32, detail: &str, transition: bool) {
        let now = self.now_ms();
        let last = self.last_open_line.load(Ordering::Relaxed);
        let due = !self.logged_open.load(Ordering::Relaxed)
            && (last == 0 || now.saturating_sub(last) >= WARN_INTERVAL_MS);
        if due
            && self
                .last_open_line
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            self.logged_open.store(true, Ordering::Relaxed);
            let unlogged = self.suppressed_transitions.swap(0, Ordering::Relaxed);
            tracing::warn!(
                consecutive_failures = n,
                cooldown_ms = guard.cooldown.as_millis() as u64,
                error = detail,
                unlogged_transitions = unlogged,
                "valkey rate-limit backend failing — circuit breaker OPEN: rate checks \
                 use the in-memory limiter (per-node, not cluster-wide, limits) and \
                 skip valkey until a probe succeeds"
            );
        } else if transition {
            self.suppressed_transitions.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A probe closed the breaker. Logged only if the log says open, so every
    /// OPEN line gets its CLOSE and no CLOSE appears without one.
    fn log_closed(&self) {
        if self.logged_open.swap(false, Ordering::Relaxed) {
            let unlogged = self.suppressed_transitions.swap(0, Ordering::Relaxed);
            tracing::info!(
                unlogged_transitions = unlogged,
                "valkey answered again — rate-limit circuit breaker closed, \
                 distributed (cluster-wide) limits resumed"
            );
        } else {
            self.suppressed_transitions.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Run `emit` at most once per [`WARN_INTERVAL_MS`], passing how many
    /// warnings were swallowed since the last one.
    fn warn_throttled(&self, emit: impl FnOnce(u64)) {
        let now = self.now_ms();
        let last = self.last_warn.load(Ordering::Relaxed);
        let due = last == 0 || now.saturating_sub(last) >= WARN_INTERVAL_MS;
        if due
            && self
                .last_warn
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            emit(self.suppressed_warnings.swap(0, Ordering::Relaxed));
        } else {
            self.suppressed_warnings.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn state(&self) -> BreakerState {
        match self.open_until.load(Ordering::Acquire) {
            0 => BreakerState::Closed,
            until if self.now_ms() < until => BreakerState::Open,
            _ => BreakerState::HalfOpen,
        }
    }
}

/// The distributed backend's state, for /healthz.
#[derive(Debug, Clone, Serialize)]
pub struct DistributedStatus {
    /// A Valkey URL is configured.
    pub configured: bool,
    /// The background connect has succeeded and the client is bound into the
    /// limiter. Set once and never cleared: the client reconnects by itself,
    /// so this is NOT a liveness signal. An outage after boot shows in
    /// `breaker` and `consecutive_failures` (and only once rate-limited
    /// traffic has asked Valkey).
    pub client_bound: bool,
    /// What rate checks are actually using right now: `distributed`,
    /// `in_memory` (no Valkey configured) or `in_memory_fallback` (configured
    /// but not connected yet, or the breaker is open).
    pub mode: &'static str,
    pub breaker: BreakerState,
    pub consecutive_failures: u32,
    pub timeout_ms: u64,
    pub failure_threshold: u32,
    pub cooldown_ms: u64,
    pub errors_total: u64,
    pub timeouts_total: u64,
    /// Rate checks answered by the in-memory limiter although Valkey is
    /// configured (not connected, breaker open, error or timeout).
    pub fallback_total: u64,
    pub breaker_opened_total: u64,
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
    /// Optional distributed backend.  When bound, limits are enforced via an
    /// atomic Redis sliding window shared across all WAF nodes; while empty,
    /// the in-memory token buckets above are used (single-instance only).
    /// Late-bound: the data plane serves before Valkey has answered, and the
    /// background connect fills this in when it does.
    redis: ArcSwapOption<RedisClient>,
    /// A Valkey URL is configured (whether or not it is bound yet).
    redis_configured: AtomicBool,
    guard: DistributedGuard,
    breaker: Breaker,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::build(false, DistributedGuard::default())
    }

    /// Construct a limiter with an optional, already-connected Redis backend.
    pub fn with_redis(redis: Option<Arc<RedisClient>>) -> Self {
        let rl = Self::build(redis.is_some(), DistributedGuard::default());
        rl.redis.store(redis);
        rl
    }

    /// A limiter whose Valkey backend is configured but connects later: it
    /// answers in-memory until [`bind_redis`](Self::bind_redis) is called.
    pub fn distributed(guard: DistributedGuard) -> Self {
        Self::build(true, guard)
    }

    fn build(configured: bool, guard: DistributedGuard) -> Self {
        Self {
            per_ip: DashMap::new(),
            per_site: DashMap::new(),
            redis: ArcSwapOption::empty(),
            redis_configured: AtomicBool::new(configured),
            guard,
            breaker: Breaker::new(),
        }
    }

    /// Attach the Valkey client once the background connect succeeds.
    pub fn bind_redis(&self, redis: Arc<RedisClient>) {
        self.redis_configured.store(true, Ordering::Relaxed);
        self.redis.store(Some(redis));
    }

    /// `true` if a distributed (Redis) backend is bound.
    pub fn is_distributed(&self) -> bool {
        self.redis.load().is_some()
    }

    /// Distributed rate check.  Uses the shared Redis sliding window when a
    /// backend is bound and healthy; otherwise delegates to the in-memory
    /// [`check`].
    ///
    /// Returns `true` (= **block request**) if any limit is exceeded.  On any
    /// Redis error or timeout the check degrades to the in-memory limiter
    /// rather than failing open, so a Redis outage never disables rate limiting
    /// entirely — and the Valkey calls are bounded by the guard's timeout, then
    /// skipped altogether while the breaker is open, so it never stalls the
    /// request either.
    ///
    /// [`check`]: RateLimiter::check
    pub async fn check_async(&self, site_id: &str, ip: IpAddr, config: &RateLimitConfig) -> bool {
        if config.global.is_none() && config.per_ip.is_none() {
            return false;
        }
        let Some(redis) = self.redis.load_full() else {
            if self.redis_configured.load(Ordering::Relaxed) {
                self.breaker.fallback_total.fetch_add(1, Ordering::Relaxed);
            }
            return self.check(site_id, ip, config);
        };
        let admission = self.breaker.admit(self.guard.cooldown);
        if admission == Admission::Skip {
            self.breaker.fallback_total.fetch_add(1, Ordering::Relaxed);
            return self.check(site_id, ip, config);
        }

        match tokio::time::timeout(
            self.guard.timeout,
            Self::redis_check(&redis, site_id, ip, config),
        )
        .await
        {
            Ok(Ok(limited)) => {
                self.breaker.on_success(admission);
                limited
            }
            Ok(Err(e)) => {
                // The client's own response timeout comes back as an error;
                // it is still a timeout.
                self.breaker
                    .on_failure(&self.guard, admission, e.is_timeout(), &e.to_string());
                self.breaker.fallback_total.fetch_add(1, Ordering::Relaxed);
                self.check(site_id, ip, config)
            }
            Err(_) => {
                let detail = format!("no reply within {}ms", self.guard.timeout.as_millis());
                self.breaker
                    .on_failure(&self.guard, admission, true, &detail);
                self.breaker.fallback_total.fetch_add(1, Ordering::Relaxed);
                self.check(site_id, ip, config)
            }
        }
    }

    async fn redis_check(
        redis: &RedisClient,
        site_id: &str,
        ip: IpAddr,
        config: &RateLimitConfig,
    ) -> Result<bool, StorageError> {
        // 1-second sliding window; allow `rps + burst` requests within it so
        // short bursts pass while sustained rate is capped (mirrors the
        // token-bucket semantics of the in-memory path).
        const WINDOW_MS: u64 = 1000;
        let mut limited = false;

        if let Some(ref global) = config.global {
            let key = format!("rate:site:{site_id}");
            let limit = (global.rps + global.burst) as u64;
            limited |= !redis.rate_check(&key, limit, WINDOW_MS).await?;
        }

        if let Some(ref per_ip_cfg) = config.per_ip {
            let key = format!("rate:ip:{site_id}:{ip}");
            let limit = (per_ip_cfg.rps + per_ip_cfg.burst) as u64;
            limited |= !redis.rate_check(&key, limit, WINDOW_MS).await?;
        }

        Ok(limited)
    }

    /// The distributed backend's state, for /healthz.
    pub fn distributed_status(&self) -> DistributedStatus {
        let configured = self.redis_configured.load(Ordering::Relaxed);
        let client_bound = self.is_distributed();
        let breaker = self.breaker.state();
        let mode = match (configured, client_bound, breaker) {
            (false, _, _) => "in_memory",
            (true, true, BreakerState::Closed) => "distributed",
            _ => "in_memory_fallback",
        };
        let b = &self.breaker;
        DistributedStatus {
            configured,
            client_bound,
            mode,
            breaker,
            consecutive_failures: b.consecutive_failures.load(Ordering::Relaxed),
            timeout_ms: self.guard.timeout.as_millis() as u64,
            failure_threshold: self.guard.failure_threshold,
            cooldown_ms: self.guard.cooldown.as_millis() as u64,
            errors_total: b.errors_total.load(Ordering::Relaxed),
            timeouts_total: b.timeouts_total.load(Ordering::Relaxed),
            fallback_total: b.fallback_total.load(Ordering::Relaxed),
            breaker_opened_total: b.opened_total.load(Ordering::Relaxed),
        }
    }

    /// Prometheus series for the distributed backend. Empty when no Valkey is
    /// configured: permanently-zero series on single-node installs would read
    /// as an outage.
    ///
    /// Alert on `breaker_open` and `consecutive_failures`. `client_bound` only
    /// says the startup connect has finished; it stays 1 through any later
    /// outage.
    pub fn prometheus_text(&self) -> String {
        let st = self.distributed_status();
        if !st.configured {
            return String::new();
        }
        let breaker_open = u8::from(st.breaker != BreakerState::Closed);
        format!(
            "# HELP sentinel_ratelimit_valkey_client_bound Valkey client bound into the rate limiter (1) or still connecting at startup (0); not a liveness signal\n\
             # TYPE sentinel_ratelimit_valkey_client_bound gauge\n\
             sentinel_ratelimit_valkey_client_bound {}\n\
             # HELP sentinel_ratelimit_valkey_breaker_open Circuit breaker skipping Valkey (1) or closed (0)\n\
             # TYPE sentinel_ratelimit_valkey_breaker_open gauge\n\
             sentinel_ratelimit_valkey_breaker_open {}\n\
             # HELP sentinel_ratelimit_valkey_consecutive_failures Valkey rate checks failed in a row (0 after any success)\n\
             # TYPE sentinel_ratelimit_valkey_consecutive_failures gauge\n\
             sentinel_ratelimit_valkey_consecutive_failures {}\n\
             # HELP sentinel_ratelimit_valkey_errors_total Valkey rate checks that failed with an error\n\
             # TYPE sentinel_ratelimit_valkey_errors_total counter\n\
             sentinel_ratelimit_valkey_errors_total {}\n\
             # HELP sentinel_ratelimit_valkey_timeouts_total Valkey rate checks that exceeded the request-path timeout\n\
             # TYPE sentinel_ratelimit_valkey_timeouts_total counter\n\
             sentinel_ratelimit_valkey_timeouts_total {}\n\
             # HELP sentinel_ratelimit_valkey_fallback_total Rate checks answered by the in-memory limiter while Valkey is configured\n\
             # TYPE sentinel_ratelimit_valkey_fallback_total counter\n\
             sentinel_ratelimit_valkey_fallback_total {}\n\
             # HELP sentinel_ratelimit_valkey_breaker_opened_total Times the Valkey circuit breaker opened\n\
             # TYPE sentinel_ratelimit_valkey_breaker_opened_total counter\n\
             sentinel_ratelimit_valkey_breaker_opened_total {}\n",
            u8::from(st.client_bound),
            breaker_open,
            st.consecutive_failures,
            st.errors_total,
            st.timeouts_total,
            st.fallback_total,
            st.breaker_opened_total,
        )
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
        self.per_ip
            .retain(|_, v| now.duration_since(v.last_used) < TTL);
        self.per_site
            .retain(|_, v| now.duration_since(v.last_used) < TTL);
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

#[cfg(test)]
mod distributed_tests {
    use super::*;
    use sentinel_core::config::{RateLimitConfig, RateWindow};
    use sentinel_storage::testing::{EvalMode, FakeValkey};
    use std::net::Ipv4Addr;

    const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));

    fn per_ip(rps: u32, burst: u32) -> RateLimitConfig {
        RateLimitConfig {
            global: None,
            per_ip: Some(RateWindow { rps, burst }),
        }
    }

    fn guard(timeout_ms: u64, failures: u32, cooldown_ms: u64) -> DistributedGuard {
        DistributedGuard {
            timeout: Duration::from_millis(timeout_ms),
            failure_threshold: failures,
            cooldown: Duration::from_millis(cooldown_ms),
        }
    }

    async fn limiter(fake: &FakeValkey, g: DistributedGuard) -> RateLimiter {
        let rl = RateLimiter::distributed(g);
        let client = RedisClient::connect(&fake.url()).await.expect("handshake");
        rl.bind_redis(Arc::new(client));
        rl
    }

    /// Bound the whole call, so a regression shows up as a failed assertion
    /// rather than a test that never finishes.
    async fn timed_check(rl: &RateLimiter, cfg: &RateLimitConfig) -> (bool, Duration) {
        let t = Instant::now();
        let limited =
            tokio::time::timeout(Duration::from_secs(5), rl.check_async("site1", IP, cfg))
                .await
                .expect("rate check hung on an unresponsive valkey");
        (limited, t.elapsed())
    }

    /// The request-path failure: a Valkey that stops answering held every
    /// rate-limited request for as long as the client library waited — forever
    /// on the 0.24 client, which had no response timeout.
    #[tokio::test]
    async fn an_unresponsive_valkey_costs_at_most_the_timeout() {
        let fake = FakeValkey::start(EvalMode::Hang).await;
        let rl = limiter(&fake, guard(50, 5, 60_000)).await;

        let (limited, took) = timed_check(&rl, &per_ip(1, 5)).await;
        assert!(!limited, "first request is within the in-memory burst");
        assert!(
            took < Duration::from_millis(300),
            "a 50ms budget took {took:?}"
        );
        let st = rl.distributed_status();
        assert_eq!(st.timeouts_total, 1);
        assert_eq!(st.fallback_total, 1);
        assert_eq!(
            st.breaker,
            BreakerState::Closed,
            "one failure is below the threshold"
        );
    }

    #[tokio::test]
    async fn the_breaker_opens_after_consecutive_failures_and_stops_asking_valkey() {
        let fake = FakeValkey::start(EvalMode::Error).await;
        let rl = limiter(&fake, guard(50, 3, 60_000)).await;
        let cfg = per_ip(1, 5);

        for _ in 0..3 {
            timed_check(&rl, &cfg).await;
        }
        assert_eq!(fake.evals(), 3);
        let st = rl.distributed_status();
        assert_eq!(st.breaker, BreakerState::Open);
        assert_eq!(st.breaker_opened_total, 1);
        assert_eq!(st.errors_total, 3);
        assert_eq!(st.mode, "in_memory_fallback");

        // Open: valkey is not contacted at all, and the in-memory limiter keeps
        // enforcing — 5 burst tokens, 3 already spent above.
        let (a, _) = timed_check(&rl, &cfg).await;
        let (b, _) = timed_check(&rl, &cfg).await;
        let (c, _) = timed_check(&rl, &cfg).await;
        assert!(!a && !b, "within the burst");
        assert!(c, "over the burst: an open breaker must not fail open");
        assert_eq!(fake.evals(), 3, "an open breaker must skip valkey");
        assert_eq!(rl.distributed_status().fallback_total, 6);
    }

    // The cooldown tests step the breaker's clock (`advance`) instead of
    // sleeping: with a 60s cooldown, real time that passes during the test (a
    // stalled CI runner) cannot reach the next cooldown boundary.
    const COOLDOWN_MS: u64 = 60_000;

    #[tokio::test]
    async fn a_probe_after_the_cooldown_closes_the_breaker_when_valkey_recovers() {
        let fake = FakeValkey::start(EvalMode::Error).await;
        let rl = limiter(&fake, guard(50, 1, COOLDOWN_MS)).await;
        let cfg = per_ip(100, 100);

        timed_check(&rl, &cfg).await;
        assert_eq!(rl.distributed_status().breaker, BreakerState::Open);

        fake.set_mode(EvalMode::Allow);
        timed_check(&rl, &cfg).await;
        assert_eq!(fake.evals(), 1, "still inside the cooldown");

        rl.breaker.advance(Duration::from_millis(COOLDOWN_MS));
        assert_eq!(rl.distributed_status().breaker, BreakerState::HalfOpen);
        timed_check(&rl, &cfg).await;
        assert_eq!(fake.evals(), 2, "one probe after the cooldown");
        let st = rl.distributed_status();
        assert_eq!(st.breaker, BreakerState::Closed);
        assert_eq!(st.mode, "distributed");
        assert_eq!(st.consecutive_failures, 0);
    }

    #[tokio::test]
    async fn a_failed_probe_keeps_the_breaker_open_for_another_cooldown() {
        let fake = FakeValkey::start(EvalMode::Hang).await;
        let rl = limiter(&fake, guard(30, 1, COOLDOWN_MS)).await;
        let cfg = per_ip(100, 100);

        timed_check(&rl, &cfg).await;
        rl.breaker.advance(Duration::from_millis(COOLDOWN_MS));
        timed_check(&rl, &cfg).await; // the probe — times out
        let st = rl.distributed_status();
        assert_eq!(st.timeouts_total, 2);
        assert_eq!(st.breaker, BreakerState::Open);
        assert_eq!(
            st.breaker_opened_total, 1,
            "a failed probe re-arms, not re-opens"
        );

        timed_check(&rl, &cfg).await;
        assert_eq!(
            fake.evals(),
            2,
            "skipped again until the next cooldown ends"
        );
    }

    /// Valkey connects after the data plane is already serving: until then
    /// checks are in-memory; once bound, Valkey decides.
    #[tokio::test]
    async fn a_late_bound_client_takes_over_from_the_in_memory_limiter() {
        let fake = FakeValkey::start(EvalMode::Deny).await;
        let rl = RateLimiter::distributed(guard(50, 5, 60_000));
        let cfg = per_ip(100, 100);

        let (limited, _) = timed_check(&rl, &cfg).await;
        assert!(!limited);
        let st = rl.distributed_status();
        assert!(st.configured && !st.client_bound);
        assert_eq!(st.mode, "in_memory_fallback");
        assert_eq!(st.fallback_total, 1);

        rl.bind_redis(Arc::new(RedisClient::connect(&fake.url()).await.unwrap()));
        let (limited, _) = timed_check(&rl, &cfg).await;
        assert!(limited, "valkey said over-limit");
        assert_eq!(fake.evals(), 1);
        assert_eq!(rl.distributed_status().mode, "distributed");
    }

    #[test]
    fn metrics_only_when_valkey_is_configured() {
        assert_eq!(RateLimiter::new().prometheus_text(), "");
        assert_eq!(RateLimiter::new().distributed_status().mode, "in_memory");

        let text = RateLimiter::distributed(DistributedGuard::default()).prometheus_text();
        for series in [
            "sentinel_ratelimit_valkey_client_bound 0",
            "sentinel_ratelimit_valkey_breaker_open 0",
            "sentinel_ratelimit_valkey_consecutive_failures 0",
            "sentinel_ratelimit_valkey_errors_total 0",
            "sentinel_ratelimit_valkey_timeouts_total 0",
            "sentinel_ratelimit_valkey_fallback_total 0",
            "sentinel_ratelimit_valkey_breaker_opened_total 0",
        ] {
            assert!(text.contains(series), "missing {series:?} in:\n{text}");
        }
    }

    #[test]
    fn guard_env_overrides_are_bounded() {
        let d = DistributedGuard::default();
        assert_eq!(d.timeout, Duration::from_millis(50));
        assert_eq!(DistributedGuard::from_lookup(|_| None), d);

        let g = DistributedGuard::from_lookup(|k| match k {
            "SENTINEL_REDIS_TIMEOUT_MS" => Some("80".into()),
            "SENTINEL_REDIS_BREAKER_FAILURES" => Some("2".into()),
            "SENTINEL_REDIS_BREAKER_COOLDOWN_MS" => Some("1500".into()),
            _ => None,
        });
        assert_eq!(g, guard(80, 2, 1500));

        // A zero timeout would fail every check; zero failures would never
        // close; garbage keeps the default.
        let g = DistributedGuard::from_lookup(|k| match k {
            "SENTINEL_REDIS_TIMEOUT_MS" => Some("0".into()),
            "SENTINEL_REDIS_BREAKER_FAILURES" => Some("0".into()),
            "SENTINEL_REDIS_BREAKER_COOLDOWN_MS" => Some("soon".into()),
            _ => None,
        });
        assert_eq!(g, d);
    }

    /// A budget above the client's own per-command timeout was accepted and
    /// had no effect: every call failed at 500ms regardless.
    #[test]
    fn a_timeout_beyond_the_clients_own_is_rejected() {
        let env = |v: &'static str| {
            move |k: &str| (k == "SENTINEL_REDIS_TIMEOUT_MS").then(|| v.to_string())
        };
        let max = sentinel_storage::redis::RESPONSE_TIMEOUT;
        assert_eq!(max, Duration::from_millis(500));
        assert_eq!(DistributedGuard::from_lookup(env("500")).timeout, max);
        assert_eq!(
            DistributedGuard::from_lookup(env("800")).timeout,
            DistributedGuard::default().timeout
        );
    }

    /// The client's own response timeout surfaces as an error from the call,
    /// not as our deadline firing; it was counted in `errors_total`, so
    /// /healthz and /metrics blamed errors for what was a slow Valkey.
    #[tokio::test]
    async fn the_clients_own_response_timeout_counts_as_a_timeout() {
        let fake = FakeValkey::start(EvalMode::Hang).await;
        // A budget above the client's 500ms, so the client's timer fires first
        // (from_env no longer allows this; the fields are set directly).
        let rl = limiter(&fake, guard(2_000, 5, COOLDOWN_MS)).await;
        timed_check(&rl, &per_ip(100, 100)).await;
        let st = rl.distributed_status();
        assert_eq!((st.timeouts_total, st.errors_total), (1, 0));
    }
}

/// The breaker state machine on its own, with its clock stepped explicitly.
#[cfg(test)]
mod breaker_tests {
    use super::*;
    use std::sync::Mutex;

    fn guard(failures: u32, cooldown_ms: u64) -> DistributedGuard {
        DistributedGuard {
            timeout: Duration::from_millis(50),
            failure_threshold: failures,
            cooldown: Duration::from_millis(cooldown_ms),
        }
    }

    /// A check admitted while the breaker was closed can complete after it
    /// opened. Its success used to close the breaker.
    #[test]
    fn a_stale_success_does_not_close_an_open_breaker() {
        let g = guard(3, 5_000);
        let b = Breaker::new();
        let in_flight = b.admit(g.cooldown);
        assert_eq!(in_flight, Admission::Closed);
        for _ in 0..3 {
            let a = b.admit(g.cooldown);
            b.on_failure(&g, a, true, "slow");
        }
        assert_eq!(b.state(), BreakerState::Open);

        b.on_success(in_flight);
        assert_eq!(b.state(), BreakerState::Open, "only the probe may close it");
        assert_eq!(b.admit(g.cooldown), Admission::Skip);

        b.advance(g.cooldown);
        let probe = b.admit(g.cooldown);
        assert_eq!(probe, Admission::Probe);
        b.on_success(probe);
        assert_eq!(b.state(), BreakerState::Closed);
    }

    /// Log lines written while `f` runs, from this thread.
    fn captured_lines(f: impl FnOnce()) -> Vec<String> {
        #[derive(Clone, Default)]
        struct Buf(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Buf {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buf = Buf::default();
        let out = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || out.clone())
            .with_ansi(false)
            .finish();
        // tracing caches each callsite's interest globally. While only one
        // dispatcher is registered, a callsite first hit on another test thread
        // (no subscriber there) is cached as "never" and this thread's events
        // from it are dropped. A second live dispatcher makes tracing ask every
        // registered one instead.
        let _second = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
        tracing::subscriber::with_default(subscriber, f);
        let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        text.lines().map(str::to_string).collect()
    }

    /// The flapping the reviewer modelled: Valkey answering about half the
    /// calls within the budget, at 5k rate checks a second, each call
    /// completing 50ms after it was admitted. When any success closed the
    /// breaker, a minute of this opened it thousands of times and wrote a WARN
    /// and an INFO line each time, while Valkey calls barely dropped.
    #[test]
    fn a_half_failing_valkey_opens_the_breaker_at_most_once_per_cooldown() {
        let g = guard(5, 5_000);
        let b = Breaker::new();
        let mut rng: u64 = 0x2545_f491_4f6c_dd1d;
        let mut coin = move || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng & 1 == 0
        };
        let mut valkey_calls = 0u64;
        let lines = captured_lines(|| {
            // (completes at ms, admission, succeeds)
            let mut in_flight: std::collections::VecDeque<(u64, Admission, bool)> =
                Default::default();
            for ms in 0..60_000u64 {
                while in_flight.front().is_some_and(|c| c.0 <= ms) {
                    let (_, a, ok) = in_flight.pop_front().unwrap();
                    if ok {
                        b.on_success(a);
                    } else {
                        b.on_failure(&g, a, true, "no reply within 50ms");
                    }
                }
                for _ in 0..5 {
                    let a = b.admit(g.cooldown);
                    if a != Admission::Skip {
                        valkey_calls += 1;
                        in_flight.push_back((ms + 50, a, coin()));
                    }
                }
                b.advance(Duration::from_millis(1));
            }
        });

        let opened = b.opened_total.load(Ordering::Relaxed);
        // Every reopen needs a probe, and a probe needs a whole cooldown.
        assert!(opened <= 13, "opened {opened} times in a minute");
        assert!(
            valkey_calls < 30_000,
            "{valkey_calls} valkey calls: an open breaker must shed load"
        );
        let transitions = lines
            .iter()
            .filter(|l| l.contains("circuit breaker"))
            .count();
        assert!(
            transitions <= 14,
            "{transitions} breaker lines in a minute:\n{}",
            lines.join("\n")
        );
    }

    /// Throttling must not leave the log saying the opposite of the truth: a
    /// logged OPEN is always followed by a CLOSE when a probe succeeds, and an
    /// unlogged reopen is reported once the breaker has stayed open a while.
    #[test]
    fn the_log_catches_up_with_the_breaker() {
        let g = guard(1, 5_000);
        let b = Breaker::new();
        let fail = |b: &Breaker| {
            let a = b.admit(g.cooldown);
            b.on_failure(&g, a, false, "down");
        };
        let probe_ok = |b: &Breaker| {
            b.advance(g.cooldown);
            let a = b.admit(g.cooldown);
            assert_eq!(a, Admission::Probe);
            b.on_success(a);
        };
        let lines = captured_lines(|| {
            fail(&b); // OPEN (logged)
            probe_ok(&b); // CLOSE (logged)
            fail(&b); // reopened within 10s of the last OPEN line: not logged
            b.advance(g.cooldown);
            fail(&b); // failed probe 10s after the OPEN line: logged now
        });
        let breaker: Vec<&String> = lines
            .iter()
            .filter(|l| l.contains("circuit breaker"))
            .collect();
        assert_eq!(breaker.len(), 3, "{breaker:#?}");
        assert!(breaker[0].contains("OPEN"));
        assert!(breaker[1].contains("closed"));
        assert!(breaker[2].contains("OPEN") && breaker[2].contains("unlogged_transitions=1"));
        assert_eq!(b.state(), BreakerState::Open);
    }
}
