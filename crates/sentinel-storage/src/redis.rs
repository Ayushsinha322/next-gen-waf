//! Redis client — connection manager + distributed rate-limit + KV helpers.
//!
//! Rate limiting uses an atomic Lua sliding-window script so no data races
//! occur even under high concurrency across multiple WAF nodes.

use redis::aio::ConnectionManager;
use redis::{AsyncCommands, Script};

use crate::error::StorageError;

pub struct RedisClient {
    conn: ConnectionManager,
}

impl RedisClient {
    /// Open a connection manager to `url` (e.g. `redis://127.0.0.1:6379`).
    pub async fn connect(url: &str) -> Result<Self, StorageError> {
        let client = redis::Client::open(url)?;
        let conn = ConnectionManager::new(client).await?;
        Ok(Self { conn })
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

        // ZSET-based sliding window:
        //   score  = arrival timestamp in ms
        //   member = "ts:seq" where seq is a per-key auto-increment
        // Using a seq counter avoids collisions when multiple requests share
        // the same millisecond timestamp.
        let script = Script::new(
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
        );

        let mut conn = self.conn.clone();
        let result: i64 = script
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
