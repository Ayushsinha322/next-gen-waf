//! Redis client — connection manager + distributed rate-limit + KV helpers.
//!
//! Rate limiting uses an atomic Lua sliding-window script so no data races
//! occur even under high concurrency across multiple WAF nodes.
//!
//! Every way of talking to the server is time-bounded. Connecting is capped by
//! the manager's connection timeout (TCP connect + handshake), every command by
//! its response timeout, and reconnects by a short retry budget — a Valkey that
//! accepts TCP and then never answers used to hold `connect` (and with it the
//! data plane's startup) forever.

use std::sync::OnceLock;
use std::time::Duration;

use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use redis::io::tcp::{socket2::TcpKeepalive, TcpSettings};
use redis::{AsyncCommands, IntoConnectionInfo, Script};
use tracing::{debug, info, warn};

use crate::backoff::Backoff;
use crate::error::StorageError;

/// TCP connect + handshake, per attempt.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
/// Per command. The request path applies its own, much shorter budget on top
/// (see the rate limiter); this one bounds everything else, and it caps that
/// budget: a longer one could never take effect, since the command fails here
/// first.
pub const RESPONSE_TIMEOUT: Duration = Duration::from_millis(500);
/// Reconnect attempts inside the manager after a dropped connection. Kept
/// small: a command issued while reconnecting waits on the attempt, and the
/// background connector (not the manager) is what retries indefinitely.
const RECONNECT_RETRIES: usize = 2;
const RECONNECT_MAX_DELAY: Duration = Duration::from_millis(500);
/// Keepalive probes so a peer that vanished without a FIN (VM failover, NAT
/// state dropped) is detected instead of leaving a half-open socket.
const KEEPALIVE_IDLE: Duration = Duration::from_secs(30);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
/// Keepalive only probes an idle socket. With requests outstanding to a peer
/// that vanished, unacknowledged data is governed by TCP retransmission (~15
/// minutes by default), and the rate limiter drops each call at its own short
/// timeout, so the manager never sees an error to reconnect on. This makes the
/// kernel fail such a socket after 10s instead.
#[cfg(target_os = "linux")]
const TCP_USER_TIMEOUT: Duration = Duration::from_secs(10);

pub struct RedisClient {
    conn: ConnectionManager,
}

/// `scheme://user:pass@host` → `scheme://***@host`, for log lines. The URL is
/// the one place a Valkey password lives, and a ClickHouse URL may carry one
/// too (`http://user:pass@clickhouse:8123/`); both were logged verbatim.
pub fn redact_url(url: &str) -> String {
    match (url.find("://"), url.rfind('@')) {
        (Some(scheme_end), Some(at)) if at > scheme_end => {
            format!("{}://***@{}", &url[..scheme_end], &url[at + 1..])
        }
        _ => url.to_string(),
    }
}

impl RedisClient {
    /// Open a connection manager to `url` (e.g. `redis://127.0.0.1:6379`).
    ///
    /// Bounded: at most `1 + RECONNECT_RETRIES` attempts of `CONNECT_TIMEOUT`
    /// each, so an unreachable or mute server is an error in seconds.
    pub async fn connect(url: &str) -> Result<Self, StorageError> {
        let tcp = TcpSettings::default().set_nodelay(true).set_keepalive(
            TcpKeepalive::new()
                .with_time(KEEPALIVE_IDLE)
                .with_interval(KEEPALIVE_INTERVAL),
        );
        #[cfg(target_os = "linux")]
        let tcp = tcp.set_user_timeout(TCP_USER_TIMEOUT);
        let info = url.into_connection_info()?.set_tcp_settings(tcp);
        let client = redis::Client::open(info)?;
        let cfg = ConnectionManagerConfig::new()
            .set_connection_timeout(Some(CONNECT_TIMEOUT))
            .set_response_timeout(Some(RESPONSE_TIMEOUT))
            .set_number_of_retries(RECONNECT_RETRIES)
            .set_max_delay(RECONNECT_MAX_DELAY);
        let conn = ConnectionManager::new_with_config(client, cfg).await?;
        Ok(Self { conn })
    }

    /// Connect, retrying with `backoff` until the server answers.
    ///
    /// Never gives up: a Valkey that is down when the data plane boots is a
    /// degraded state to recover from. The old one-shot connect left the node
    /// on per-node limits for the life of the process. Failures are logged at
    /// warn on the first attempt and then on attempts 2, 4, 8, … so a long
    /// outage does not flood the log.
    pub async fn connect_with_retry(url: &str, mut backoff: Backoff) -> Self {
        let endpoint = redact_url(url);
        let mut attempt: u64 = 0;
        loop {
            attempt += 1;
            match Self::connect(url).await {
                Ok(client) => {
                    info!(url = %endpoint, attempt, "valkey connected");
                    return client;
                }
                Err(e) => {
                    let delay = backoff.next_delay();
                    if attempt.is_power_of_two() {
                        warn!(
                            url = %endpoint,
                            error = %e,
                            attempt,
                            retry_in_ms = delay.as_millis() as u64,
                            "valkey unavailable — rate limiting stays on the in-memory \
                             limiter (per-node limits) and the connect keeps retrying"
                        );
                    } else {
                        debug!(url = %endpoint, error = %e, attempt, "valkey connect retry failed");
                    }
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Distributed sliding-window rate limit
    // -----------------------------------------------------------------------

    /// Sliding-window rate check via atomic Lua.
    ///
    /// `key`       — e.g. `"rate:ip:site1:1.2.3.4"`
    /// `limit`     — max requests allowed within `window_ms`
    /// `window_ms` — window length in milliseconds
    ///
    /// Returns `true` if the request is **allowed**, `false` if over-limit.
    pub async fn rate_check(
        &self,
        key: &str,
        limit: u64,
        window_ms: u64,
    ) -> Result<bool, StorageError> {
        // Millisecond timestamp passed in from Rust so the script doesn't need
        // to call TIME (avoids a round-trip and keeps the Lua deterministic).
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_millis() as i64;
        let cutoff_ms = now_ms - window_ms as i64;
        let expire_secs = (window_ms / 1000 + 2) as i64;

        let mut conn = self.conn.clone();
        let result: i64 = rate_script()
            .key(key)
            .arg(now_ms)
            .arg(cutoff_ms)
            .arg(limit as i64)
            .arg(expire_secs)
            .invoke_async(&mut conn)
            .await?;

        Ok(result == 1)
    }

    // -----------------------------------------------------------------------
    // General KV helpers
    // -----------------------------------------------------------------------

    pub async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let mut conn = self.conn.clone();
        Ok(conn.get(key).await?)
    }

    pub async fn set(
        &self,
        key: &str,
        value: &[u8],
        ttl_secs: Option<u64>,
    ) -> Result<(), StorageError> {
        let mut conn = self.conn.clone();
        if let Some(ttl) = ttl_secs {
            let _: () = conn.set_ex(key, value, ttl).await?;
        } else {
            let _: () = conn.set(key, value).await?;
        }
        Ok(())
    }

    pub async fn del(&self, key: &str) -> Result<(), StorageError> {
        let mut conn = self.conn.clone();
        let _: i64 = conn.del(key).await?;
        Ok(())
    }

    /// Increment a counter and set TTL on the first increment.
    /// Useful for short-lived per-second/per-minute counters.
    pub async fn incr_expire(&self, key: &str, ttl_secs: u64) -> Result<i64, StorageError> {
        let mut conn = self.conn.clone();
        let n: i64 = conn.incr(key, 1i64).await?;
        if n == 1 {
            // First write — set the TTL so the key auto-cleans.
            let _: bool = conn.expire(key, ttl_secs as i64).await?;
        }
        Ok(n)
    }

    pub async fn ping(&self) -> Result<(), StorageError> {
        let mut conn = self.conn.clone();
        let _: String = redis::cmd("PING").query_async(&mut conn).await?;
        Ok(())
    }
}

/// The sliding-window script, built once: `Script::new` hashes the source, and
/// this runs on every rate-limited request.
///
/// ZSET-based sliding window:
///   score  = arrival timestamp in ms
///   member = "ts:seq" where seq is a per-key auto-increment
/// Using a seq counter avoids collisions when multiple requests share the same
/// millisecond timestamp.
fn rate_script() -> &'static Script {
    static SCRIPT: OnceLock<Script> = OnceLock::new();
    SCRIPT.get_or_init(|| {
        Script::new(
            r#"
            local key    = KEYS[1]
            local now    = tonumber(ARGV[1])
            local cutoff = tonumber(ARGV[2])
            local lim    = tonumber(ARGV[3])
            local exp    = tonumber(ARGV[4])
            redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)
            local cnt = redis.call('ZCARD', key)
            if cnt < lim then
                local seq = redis.call('INCR', key .. ':seq')
                redis.call('ZADD', key, now, now .. ':' .. seq)
                redis.call('EXPIRE', key, exp)
                redis.call('EXPIRE', key .. ':seq', exp)
                return 1
            end
            return 0
            "#,
        )
    })
}

// ---------------------------------------------------------------------------
// Tests (require a running Redis — marked #[ignore] for CI)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn redis_url() -> String {
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string())
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn ping_succeeds() {
        let c = RedisClient::connect(&redis_url()).await.unwrap();
        c.ping().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn kv_roundtrip() {
        let c = RedisClient::connect(&redis_url()).await.unwrap();
        let key = "test:kv:roundtrip";
        c.set(key, b"hello", Some(10)).await.unwrap();
        let val = c.get(key).await.unwrap().unwrap();
        assert_eq!(val, b"hello");
        c.del(key).await.unwrap();
        assert!(c.get(key).await.unwrap().is_none());
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn rate_check_allows_within_limit() {
        let c = RedisClient::connect(&redis_url()).await.unwrap();
        let key = "test:rate:allow";
        // 5 req/s limit, 1-second window
        for _ in 0..5 {
            assert!(c.rate_check(key, 5, 1000).await.unwrap(), "should allow");
        }
        assert!(
            !c.rate_check(key, 5, 1000).await.unwrap(),
            "6th should be denied"
        );
        c.del(key).await.ok();
        c.del(&format!("{key}:seq")).await.ok();
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn incr_expire_counter() {
        let c = RedisClient::connect(&redis_url()).await.unwrap();
        let key = "test:incr:counter";
        c.del(key).await.ok();
        assert_eq!(c.incr_expire(key, 5).await.unwrap(), 1);
        assert_eq!(c.incr_expire(key, 5).await.unwrap(), 2);
        c.del(key).await.ok();
    }
}

#[cfg(test)]
mod stub_tests {
    use super::*;
    use crate::testing::{black_hole, hang_up, EvalMode, FakeValkey};
    use std::time::Instant;

    /// A Valkey that accepts TCP and never answers the handshake used to hold
    /// `connect` forever (no connection timeout in the 0.24 manager).
    #[tokio::test]
    async fn connect_to_a_server_that_never_answers_is_a_bounded_error() {
        let addr = black_hole().await;
        let t = Instant::now();
        let r = tokio::time::timeout(
            Duration::from_secs(15),
            RedisClient::connect(&format!("redis://{addr}")),
        )
        .await
        .expect("connect hung on a server that accepts and never replies");
        assert!(r.is_err());
        // 3 attempts x 1s connect timeout + sub-second retry delays.
        assert!(
            t.elapsed() < Duration::from_secs(6),
            "took {:?}",
            t.elapsed()
        );
    }

    #[tokio::test]
    async fn connect_to_a_server_that_hangs_up_is_an_error() {
        let addr = hang_up().await;
        let r = tokio::time::timeout(
            Duration::from_secs(15),
            RedisClient::connect(&format!("redis://{addr}")),
        )
        .await
        .expect("connect hung");
        assert!(r.is_err());
    }

    /// A command the server never answers fails at the response timeout.
    #[tokio::test]
    async fn a_command_the_server_never_answers_times_out() {
        let fake = FakeValkey::start(EvalMode::Hang).await;
        let c = RedisClient::connect(&fake.url()).await.expect("handshake");
        let t = Instant::now();
        let r = tokio::time::timeout(Duration::from_secs(5), c.rate_check("k", 10, 1000))
            .await
            .expect("rate_check hung");
        assert!(r.is_err());
        assert!(
            t.elapsed() < Duration::from_secs(2),
            "took {:?}",
            t.elapsed()
        );
    }

    /// Valkey down at boot, up later: the background connect keeps retrying
    /// and returns once it answers (the old one-shot connect gave up for good).
    #[tokio::test]
    async fn connect_with_retry_succeeds_once_the_server_comes_up() {
        // Reserve a port and free it, so early attempts are refused.
        let addr = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let url = format!("redis://{addr}");
        let task = tokio::spawn(async move {
            RedisClient::connect_with_retry(
                &url,
                Backoff::new(Duration::from_millis(50), Duration::from_millis(200)),
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(!task.is_finished(), "nothing is listening yet");

        let fake = FakeValkey::serve(
            tokio::net::TcpListener::bind(addr).await.unwrap(),
            EvalMode::Allow,
        );
        let client = tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("connect_with_retry did not pick up the server")
            .unwrap();
        assert!(client.rate_check("k", 10, 1000).await.unwrap());
        assert_eq!(fake.evals(), 1);
    }
}
