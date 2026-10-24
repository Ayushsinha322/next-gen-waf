//! sentinel-storage — Redis KV + ClickHouse time-series for Sentinel WAF.
//!
//! # Backends
//!
//! | Backend      | Purpose                                            |
//! |---|---|
//! | Redis        | Distributed rate-limit state across WAF nodes      |
//! | ClickHouse   | Traffic-bucket persistence (1-sec + 1-min rollups) |
//! | MemoryStore  | In-process fallback for dev / unit tests           |
//!
//! # Quick start
//!
//! ```rust,no_run
//! use sentinel_storage::{StorageBackendConfig, StorageHandle};
//!
//! #[tokio::main]
//! async fn main() {
//!     let cfg = StorageBackendConfig {
//!         redis_url: Some("redis://127.0.0.1:6379".into()),
//!         clickhouse_url: Some("http://127.0.0.1:8123".into()),
//!         clickhouse_db: Some("sentinel_logs".into()),
//!         ..Default::default()
//!     };
//!     let handle = StorageHandle::connect(&cfg).await;
//!
//!     if let Some(redis) = &handle.redis {
//!         let allowed = redis.token_bucket("rl:ip:site1:1.2.3.4", 100, 200).await.unwrap();
//!         println!("request allowed: {allowed}");
//!     }
//! }
//! ```

pub mod backoff;
pub mod clickhouse;
pub mod error;
pub mod memory;
pub mod redis;
pub mod spool;
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod testing;

pub use backoff::{Backoff, SinkRetry};
pub use clickhouse::{ClickHouseClient, InsertError, InsertRow, TrafficRow, WafEventRow};
pub use error::StorageError;
pub use memory::MemoryStore;
pub use redis::{redact_url, RedisClient};
pub use spool::{Dropped, Spool};

use std::sync::Arc;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// StorageBackendConfig
// ---------------------------------------------------------------------------

/// Flat config consumed by [`StorageHandle::connect`].
///
/// Constructed either from environment variables (CLI / control-plane) or by
/// converting from `sentinel_core::config::StorageConfig` via
/// [`StorageBackendConfig::from_core`].
#[derive(Debug, Clone, Default)]
pub struct StorageBackendConfig {
    /// Redis URL, e.g. `redis://127.0.0.1:6379`.  `None` → Redis disabled.
    pub redis_url: Option<String>,
    /// ClickHouse HTTP URL, e.g. `http://127.0.0.1:8123`.  `None` → CH disabled.
    pub clickhouse_url: Option<String>,
    /// ClickHouse database name. Defaults to `"sentinel_logs"` when `None`.
    pub clickhouse_db: Option<String>,
    /// ClickHouse username (access-management auth).
    pub clickhouse_user: Option<String>,
    /// ClickHouse password.
    pub clickhouse_password: Option<String>,
}

impl StorageBackendConfig {
    /// Build from `sentinel_core::config::StorageConfig`.
    ///
    /// - Redis URL is taken from `storage.kv.url` when `backend = redis`.
    /// - ClickHouse URL + database from `storage.timeseries`.
    pub fn from_core(cfg: &sentinel_core::config::StorageConfig) -> Self {
        use sentinel_core::config::KvBackend;

        let redis_url = cfg
            .kv
            .as_ref()
            .filter(|kv| kv.backend == KvBackend::Redis)
            .and_then(|kv| kv.url.clone());

        let clickhouse_url = cfg.timeseries.as_ref().map(|ts| ts.url.clone());
        let clickhouse_db = cfg.timeseries.as_ref().map(|ts| ts.database.clone());
        let clickhouse_user = cfg.timeseries.as_ref().and_then(|ts| ts.username.clone());
        let clickhouse_password = cfg.timeseries.as_ref().and_then(|ts| ts.password.clone());

        Self {
            redis_url,
            clickhouse_url,
            clickhouse_db,
            clickhouse_user,
            clickhouse_password,
        }
    }

    /// Overlay `SENTINEL_*` environment variables on top of the file-derived
    /// config. A variable wins only when present and non-empty; otherwise the
    /// file value is kept.
    ///
    /// This mirrors the Go control plane's `clickhouse.FromEnv`, so the data
    /// plane and control plane are configured identically from compose/K8s
    /// env — no ClickHouse password has to be baked into the committed proxy
    /// YAML, and the same `SENTINEL_CLICKHOUSE_*` Secret feeds both planes.
    ///
    /// Recognised vars: `SENTINEL_REDIS_URL`, `SENTINEL_CLICKHOUSE_URL`,
    /// `SENTINEL_CLICKHOUSE_DB`, `SENTINEL_CLICKHOUSE_USER`,
    /// `SENTINEL_CLICKHOUSE_PASSWORD`.
    pub fn with_env_overrides(self) -> Self {
        self.apply_overrides(|k| std::env::var(k).ok())
    }

    /// Inner, testable form of [`with_env_overrides`]: takes the variable
    /// lookup as a closure so unit tests need not mutate the process
    /// environment (which races across parallel tests).
    fn apply_overrides(mut self, lookup: impl Fn(&str) -> Option<String>) -> Self {
        let get = |k: &str| {
            lookup(k)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        if let Some(v) = get("SENTINEL_REDIS_URL") {
            self.redis_url = Some(v);
        }
        if let Some(v) = get("SENTINEL_CLICKHOUSE_URL") {
            self.clickhouse_url = Some(v);
        }
        if let Some(v) = get("SENTINEL_CLICKHOUSE_DB") {
            self.clickhouse_db = Some(v);
        }
        if let Some(v) = get("SENTINEL_CLICKHOUSE_USER") {
            self.clickhouse_user = Some(v);
        }
        if let Some(v) = get("SENTINEL_CLICKHOUSE_PASSWORD") {
            self.clickhouse_password = Some(v);
        }
        self
    }
}

// ---------------------------------------------------------------------------
// StorageHandle
// ---------------------------------------------------------------------------

/// Live handles to all configured storage backends.
///
/// Fields are `Option` — a backend is `None` when its URL is absent from
/// config or when the connection attempt fails at startup.  Callers must
/// degrade gracefully (e.g. fall back to `memory` for rate limiting).
#[derive(Clone)]
pub struct StorageHandle {
    pub redis: Option<Arc<RedisClient>>,
    pub clickhouse: Option<Arc<ClickHouseClient>>,
    /// Always present: in-process KV store used as fallback.
    pub memory: Arc<MemoryStore>,
}

impl Default for StorageHandle {
    fn default() -> Self {
        Self {
            redis: None,
            clickhouse: None,
            memory: Arc::new(MemoryStore::new()),
        }
    }
}

impl StorageHandle {
    /// Connect to all configured backends, once.
    ///
    /// Missing or unreachable backends are skipped with a `warn!` log rather
    /// than causing startup failure — the WAF continues in degraded mode.
    /// Bounded by the clients' own connect/request timeouts (a few seconds per
    /// backend), but still a one-shot: the data plane does NOT await this before
    /// serving — it connects each backend in the background and keeps retrying
    /// (see `RedisClient::connect_with_retry` and the history writer).
    pub async fn connect(cfg: &StorageBackendConfig) -> Self {
        let mut handle = Self::default();

        // --- Redis -----------------------------------------------------------
        if let Some(url) = &cfg.redis_url {
            let endpoint = redact_url(url);
            match RedisClient::connect(url).await {
                Ok(client) => {
                    info!(url = %endpoint, "redis connected");
                    handle.redis = Some(Arc::new(client));
                }
                Err(e) => {
                    warn!(
                        url = %endpoint,
                        error = %e,
                        "redis unavailable — rate limit falls back to in-process store"
                    );
                }
            }
        }

        // --- ClickHouse ------------------------------------------------------
        if let Some(url) = &cfg.clickhouse_url {
            // The URL may carry credentials (`http://user:pass@host:8123/`).
            let endpoint = redact_url(url);
            let db = cfg.clickhouse_db.as_deref().unwrap_or("sentinel_logs");
            let client = ClickHouseClient::with_auth(
                url,
                db,
                cfg.clickhouse_user.clone(),
                cfg.clickhouse_password.clone(),
            );
            match client.ping().await {
                Ok(()) => match client.ensure_schema().await {
                    Ok(()) => {
                        info!(url = %endpoint, database = db, "clickhouse connected");
                        handle.clickhouse = Some(Arc::new(client));
                    }
                    Err(e) => {
                        warn!(url = %endpoint, error = %e, "clickhouse schema init failed — traffic history disabled");
                    }
                },
                Err(e) => {
                    warn!(
                        url = %endpoint,
                        error = %e,
                        "clickhouse unreachable — traffic history will not persist across restarts"
                    );
                }
            }
        }

        handle
    }

    /// `true` if Redis is connected and available.
    pub fn has_redis(&self) -> bool {
        self.redis.is_some()
    }

    /// `true` if ClickHouse is connected and available.
    pub fn has_clickhouse(&self) -> bool {
        self.clickhouse.is_some()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn default_handle_has_no_remote_backends() {
        let h = StorageHandle::default();
        assert!(!h.has_redis());
        assert!(!h.has_clickhouse());
    }

    #[tokio::test]
    async fn connect_with_empty_config_is_ok() {
        let h = StorageHandle::connect(&StorageBackendConfig::default()).await;
        assert!(!h.has_redis());
        assert!(!h.has_clickhouse());
    }

    #[tokio::test]
    async fn connect_with_bad_redis_url_degrades_gracefully() {
        let cfg = StorageBackendConfig {
            redis_url: Some("redis://127.0.0.1:19999".into()), // nothing listening
            ..Default::default()
        };
        let h = StorageHandle::connect(&cfg).await;
        assert!(!h.has_redis(), "should degrade, not panic");
    }

    /// Backends that accept TCP and never answer used to hold `connect` — and
    /// with it data-plane startup — forever.
    #[tokio::test]
    async fn connect_is_bounded_when_backends_accept_and_never_answer() {
        let valkey = testing::black_hole().await;
        let clickhouse = testing::black_hole().await;
        let cfg = StorageBackendConfig {
            redis_url: Some(format!("redis://{valkey}")),
            clickhouse_url: Some(format!("http://{clickhouse}")),
            ..Default::default()
        };
        let started = std::time::Instant::now();
        let h = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            StorageHandle::connect(&cfg),
        )
        .await
        .expect("StorageHandle::connect hung on backends that never answer");
        assert!(!h.has_redis() && !h.has_clickhouse());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn redact_url_hides_credentials_only() {
        assert_eq!(
            redact_url("redis://:s3cret@valkey:6379/0"),
            "redis://***@valkey:6379/0"
        );
        assert_eq!(
            redact_url("rediss://user:p@ss@valkey:6380"),
            "rediss://***@valkey:6380"
        );
        assert_eq!(redact_url("redis://valkey:6379"), "redis://valkey:6379");
    }

    /// A ClickHouse URL may carry `user:pass@`, and the connect lines logged it
    /// verbatim.
    #[tokio::test]
    async fn connect_logs_no_credentials() {
        #[derive(Clone, Default)]
        struct Buf(Arc<std::sync::Mutex<Vec<u8>>>);
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
        // The test runtime is single-threaded, so the guard covers the awaits.
        let _guard = tracing::subscriber::set_default(subscriber);
        // tracing caches each callsite's interest globally. While only one
        // dispatcher is registered, a callsite first hit on another test thread
        // (no subscriber there) is cached as "never" and this thread's events
        // from it are dropped. A second live dispatcher makes tracing ask every
        // registered one instead.
        let _second = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());

        let clickhouse = testing::hang_up().await;
        let cfg = StorageBackendConfig {
            clickhouse_url: Some(format!(
                "http://sentinel:s3cret-ch@{clickhouse}/sentinel_logs"
            )),
            ..Default::default()
        };
        StorageHandle::connect(&cfg).await;
        let logged = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(logged.contains("clickhouse"), "nothing logged: {logged}");
        assert!(logged.contains("***@"), "{logged}");
        assert!(!logged.contains("s3cret-ch"), "password logged: {logged}");
    }

    #[tokio::test]
    async fn connect_with_bad_clickhouse_url_degrades_gracefully() {
        let cfg = StorageBackendConfig {
            clickhouse_url: Some("http://127.0.0.1:19999".into()),
            ..Default::default()
        };
        let h = StorageHandle::connect(&cfg).await;
        assert!(!h.has_clickhouse(), "should degrade, not panic");
    }

    #[test]
    fn from_core_redis_url_extracted() {
        use sentinel_core::config::{KvBackend, KvConfig, StorageConfig};
        let cfg = StorageConfig {
            kv: Some(KvConfig {
                backend: KvBackend::Redis,
                path: None,
                url: Some("redis://localhost:6379".into()),
            }),
            ..Default::default()
        };
        let backend = StorageBackendConfig::from_core(&cfg);
        assert_eq!(backend.redis_url.as_deref(), Some("redis://localhost:6379"));
        assert!(backend.clickhouse_url.is_none());
    }

    #[test]
    fn from_core_timeseries_extracted() {
        use sentinel_core::config::{StorageConfig, TimeSeriesConfig};
        let cfg = StorageConfig {
            timeseries: Some(TimeSeriesConfig {
                url: "http://ch:8123".into(),
                database: "mydb".into(),
                username: None,
                password: None,
            }),
            ..Default::default()
        };
        let backend = StorageBackendConfig::from_core(&cfg);
        assert_eq!(backend.clickhouse_url.as_deref(), Some("http://ch:8123"));
        assert_eq!(backend.clickhouse_db.as_deref(), Some("mydb"));
    }

    #[test]
    fn env_overrides_apply_over_file_config() {
        // File config had no ClickHouse; env (compose/K8s Secret) supplies it.
        let cfg = StorageBackendConfig::default().apply_overrides(|k| match k {
            "SENTINEL_CLICKHOUSE_URL" => Some("http://clickhouse:8123".to_string()),
            "SENTINEL_CLICKHOUSE_DB" => Some("sentinel_logs".to_string()),
            "SENTINEL_CLICKHOUSE_USER" => Some("sentinel".to_string()),
            "SENTINEL_CLICKHOUSE_PASSWORD" => Some("s3cr3t".to_string()),
            "SENTINEL_REDIS_URL" => Some("redis://redis:6379".to_string()),
            _ => None,
        });
        assert_eq!(
            cfg.clickhouse_url.as_deref(),
            Some("http://clickhouse:8123")
        );
        assert_eq!(cfg.clickhouse_db.as_deref(), Some("sentinel_logs"));
        assert_eq!(cfg.clickhouse_user.as_deref(), Some("sentinel"));
        assert_eq!(cfg.clickhouse_password.as_deref(), Some("s3cr3t"));
        assert_eq!(cfg.redis_url.as_deref(), Some("redis://redis:6379"));
    }

    #[test]
    fn env_overrides_ignore_blank_and_missing_keep_file_value() {
        // A blank or absent var must NOT clobber a value that came from the file.
        let base = StorageBackendConfig {
            clickhouse_url: Some("http://from-file:8123".into()),
            clickhouse_db: Some("filedb".into()),
            ..Default::default()
        };
        let cfg = base.apply_overrides(|k| match k {
            "SENTINEL_CLICKHOUSE_URL" => Some("   ".to_string()), // whitespace → ignored
            _ => None,                                            // CH_DB absent → kept
        });
        assert_eq!(cfg.clickhouse_url.as_deref(), Some("http://from-file:8123"));
        assert_eq!(cfg.clickhouse_db.as_deref(), Some("filedb"));
    }
}
