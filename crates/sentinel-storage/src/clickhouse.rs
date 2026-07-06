//! ClickHouse client built on hyper — no reqwest, no ICU Rust-version issues.
//!
//! All SQL is sent as a plain POST body (no URL-encoding needed).  The
//! ClickHouse HTTP API accepts `SELECT ... FORMAT JSONEachRow` and
//! `INSERT INTO … FORMAT JSONEachRow\n{json}\n…` as raw request bodies.
//!
//! Table created by [`ClickHouseClient::ensure_schema`]:
//! ```sql
//! CREATE TABLE sentinel.traffic_buckets (
//!     ts      DateTime,
//!     site_id LowCardinality(String),
//!     reqs    Int64,
//!     blocked Int64,
//!     p99_ms  Float64
//! ) ENGINE = MergeTree()
//! PARTITION BY toYYYYMM(ts)
//! ORDER BY (site_id, ts)
//! TTL ts + INTERVAL 30 DAY;
//! ```

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use serde::{Deserialize, Serialize};

use crate::error::StorageError;

type HyperClient = Client<HttpConnector, Full<Bytes>>;

// ---------------------------------------------------------------------------
// TrafficRow
// ---------------------------------------------------------------------------

/// One second of traffic metrics — written to ClickHouse every second.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrafficRow {
    /// Unix timestamp (seconds).
    pub ts: i64,
    /// Site identifier.  Empty string = aggregate / unattributed.
    pub site_id: String,
    /// Total requests during this second.
    pub reqs: i64,
    /// Blocked requests during this second.
    pub blocked: i64,
    /// P99 latency (ms) sampled at this second.
    pub p99_ms: f64,
}

/// One notable WAF event (a block or a learning-mode DETECT) — the searchable
/// detail record behind the live logs. Written in batches to `waf_events`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WafEventRow {
    /// Unix timestamp (seconds).
    pub ts: i64,
    pub ip: String,
    /// ISO country code (empty until GeoIP is loaded).
    pub country: String,
    pub site: String,
    /// Owning tenant id, for per-tenant Threat Search scoping. Empty on rows
    /// written before tenant scoping; `#[serde(default)]` keeps them readable.
    #[serde(default)]
    pub tenant: String,
    pub method: String,
    pub path: String,
    /// Top matched rule ID (empty if none).
    pub rule: String,
    /// Attack class / rule message.
    pub attack: String,
    /// BLOCK | DETECT | PASS.
    pub action: String,
    pub severity: String,
    pub score: u32,
    pub status: u16,
    /// Canonical HTTP protocol label: `h1` | `h2` | `h3`. `#[serde(default)]`
    /// keeps old rows (persisted before this column existed) deserializable.
    #[serde(default)]
    pub protocol: String,
}

// ---------------------------------------------------------------------------
// ClickHouseClient
// ---------------------------------------------------------------------------

pub struct ClickHouseClient {
    http: HyperClient,
    /// Base URL, e.g. `http://127.0.0.1:8123`.
    url: String,
    database: String,
    /// Optional credentials sent as `X-ClickHouse-User` / `X-ClickHouse-Key`
    /// headers. ClickHouse with access-management enabled requires these.
    username: Option<String>,
    password: Option<String>,
}

impl ClickHouseClient {
    /// Construct an unauthenticated client (uses the `default` user).
    pub fn new(url: &str, database: &str) -> Self {
        Self::with_auth(url, database, None, None)
    }

    /// Construct a client with optional ClickHouse credentials.
    pub fn with_auth(
        url: &str,
        database: &str,
        username: Option<String>,
        password: Option<String>,
    ) -> Self {
        Self {
            http: Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>(),
            url: url.trim_end_matches('/').to_string(),
            database: database.to_string(),
            username,
            password,
        }
    }

    /// Attach ClickHouse auth headers to a request builder when credentials
    /// are configured.
    fn auth(&self, mut b: hyper::http::request::Builder) -> hyper::http::request::Builder {
        if let Some(u) = &self.username {
            b = b.header("X-ClickHouse-User", u);
        }
        if let Some(p) = &self.password {
            b = b.header("X-ClickHouse-Key", p);
        }
        b
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// `GET /ping` — fast liveness check.
    pub async fn ping(&self) -> Result<(), StorageError> {
        let uri: hyper::Uri = format!("{}/ping", self.url)
            .parse()
            .map_err(|e| StorageError::ClickHouse(format!("invalid URI: {e}")))?;

        let req = self
            .auth(Request::builder().method(Method::GET).uri(uri))
            .body(Full::new(Bytes::new()))
            .map_err(|e| StorageError::ClickHouse(e.to_string()))?;

        let resp = self
            .http
            .request(req)
            .await
            .map_err(|e| StorageError::ClickHouse(format!("ping: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            return Err(StorageError::ClickHouse(format!("ping HTTP {status}")));
        }
        Ok(())
    }

    /// Create the database and `traffic_buckets` table if they don't exist.
    pub async fn ensure_schema(&self) -> Result<(), StorageError> {
        self.exec(format!(
            "CREATE DATABASE IF NOT EXISTS {db}",
            db = self.database
        ))
        .await?;

        self.exec(format!(
            "CREATE TABLE IF NOT EXISTS {db}.traffic_buckets \
             (ts DateTime, site_id LowCardinality(String), \
              reqs Int64, blocked Int64, p99_ms Float64) \
             ENGINE = MergeTree() \
             PARTITION BY toYYYYMM(ts) \
             ORDER BY (site_id, ts) \
             TTL ts + INTERVAL 30 DAY \
             SETTINGS index_granularity = 8192",
            db = self.database
        ))
        .await?;

        // Detailed, searchable event log (blocks + learning detections).
        self.exec(format!(
            "CREATE TABLE IF NOT EXISTS {db}.waf_events \
             (ts DateTime, ip String, country LowCardinality(String), \
              site LowCardinality(String), tenant LowCardinality(String), \
              method LowCardinality(String), \
              path String, rule LowCardinality(String), attack String, \
              action LowCardinality(String), severity LowCardinality(String), \
              score UInt32, status UInt16, protocol LowCardinality(String)) \
             ENGINE = MergeTree() \
             PARTITION BY toYYYYMMDD(ts) \
             ORDER BY (site, ts) \
             TTL ts + INTERVAL 90 DAY \
             SETTINGS index_granularity = 8192",
            db = self.database
        ))
        .await?;

        // Idempotent online migration for tables created before `protocol`
        // existed (e.g. the already-running VM deployment). ADD COLUMN IF NOT
        // EXISTS is a no-op on a fresh table that already has the column.
        self.exec(format!(
            "ALTER TABLE {db}.waf_events \
             ADD COLUMN IF NOT EXISTS protocol LowCardinality(String) DEFAULT ''",
            db = self.database
        ))
        .await?;

        // Additive online migration: per-tenant scoping column. Empty on rows
        // written before this existed — those are hidden from every tenant
        // (fail-closed), never shown cross-tenant.
        self.exec(format!(
            "ALTER TABLE {db}.waf_events \
             ADD COLUMN IF NOT EXISTS tenant LowCardinality(String) DEFAULT ''",
            db = self.database
        ))
        .await
    }

    /// Batch-insert detailed WAF events into `waf_events`.
    pub async fn insert_events_batch(&self, rows: &[WafEventRow]) -> Result<(), StorageError> {
        if rows.is_empty() {
            return Ok(());
        }
        let mut sql = format!(
            "INSERT INTO {db}.waf_events \
             (ts, ip, country, site, tenant, method, path, rule, attack, action, severity, score, status, protocol) \
             FORMAT JSONEachRow\n",
            db = self.database
        );
        for row in rows {
            sql.push_str(&serde_json::to_string(row)?);
            sql.push('\n');
        }
        self.exec(sql).await
    }

    /// Query recent `waf_events`, optionally filtered. Each filter is an
    /// already-escaped exact match; pass empty string to skip.
    pub async fn query_events(
        &self,
        site: &str,
        country: &str,
        rule: &str,
        from_unix: i64,
        to_unix: i64,
        limit: u32,
    ) -> Result<Vec<WafEventRow>, StorageError> {
        let mut where_clauses = vec![format!(
            "ts >= toDateTime({from}) AND ts <= toDateTime({to})",
            from = from_unix,
            to = to_unix
        )];
        if !site.is_empty() {
            where_clauses.push(format!("site = '{}'", esc(site)));
        }
        if !country.is_empty() {
            where_clauses.push(format!("country = '{}'", esc(country)));
        }
        if !rule.is_empty() {
            where_clauses.push(format!("rule = '{}'", esc(rule)));
        }
        let sql = format!(
            "SELECT toUnixTimestamp(ts) AS ts, ip, country, site, method, path, \
             rule, attack, action, severity, score, status, protocol \
             FROM {db}.waf_events WHERE {where_} \
             ORDER BY ts DESC LIMIT {limit} \
             SETTINGS output_format_json_quote_64bit_integers = 0 \
             FORMAT JSONEachRow",
            db = self.database,
            where_ = where_clauses.join(" AND "),
            limit = limit,
        );
        let text = self.post_sql(sql).await?;
        let mut out = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if !line.is_empty() {
                out.push(serde_json::from_str::<WafEventRow>(line)?);
            }
        }
        Ok(out)
    }

    /// Batch-insert traffic rows.  Sends a single `INSERT … FORMAT JSONEachRow`
    /// request with all rows as newline-separated JSON objects in the body.
    pub async fn insert_traffic_batch(&self, rows: &[TrafficRow]) -> Result<(), StorageError> {
        if rows.is_empty() {
            return Ok(());
        }

        let mut sql = format!(
            "INSERT INTO {db}.traffic_buckets \
             (ts, site_id, reqs, blocked, p99_ms) \
             FORMAT JSONEachRow\n",
            db = self.database
        );
        for row in rows {
            sql.push_str(&serde_json::to_string(row)?);
            sql.push('\n');
        }
        self.exec(sql).await
    }

    /// Query per-second buckets between two Unix timestamps (inclusive).
    pub async fn query_traffic_history(
        &self,
        from_unix: i64,
        to_unix: i64,
        limit: u32,
    ) -> Result<Vec<TrafficRow>, StorageError> {
        let sql = format!(
            "SELECT toUnixTimestamp(ts) AS ts, site_id, reqs, blocked, p99_ms \
             FROM {db}.traffic_buckets \
             WHERE ts >= toDateTime({from}) AND ts <= toDateTime({to}) \
             ORDER BY ts LIMIT {limit} \
             SETTINGS output_format_json_quote_64bit_integers = 0 \
             FORMAT JSONEachRow",
            db = self.database,
            from = from_unix,
            to = to_unix,
            limit = limit,
        );
        let text = self.post_sql(sql).await?;
        parse_rows(&text)
    }

    /// Query 1-minute aggregates (sum reqs/blocked, avg p99) — for dashboards.
    pub async fn query_traffic_1min(
        &self,
        from_unix: i64,
        to_unix: i64,
        limit: u32,
    ) -> Result<Vec<TrafficRow>, StorageError> {
        let sql = format!(
            "SELECT toUnixTimestamp(toStartOfMinute(ts)) AS ts, site_id, \
             sum(reqs) AS reqs, sum(blocked) AS blocked, avg(p99_ms) AS p99_ms \
             FROM {db}.traffic_buckets \
             WHERE ts >= toDateTime({from}) AND ts <= toDateTime({to}) \
             GROUP BY site_id, toStartOfMinute(ts) \
             ORDER BY ts LIMIT {limit} \
             SETTINGS output_format_json_quote_64bit_integers = 0 \
             FORMAT JSONEachRow",
            db = self.database,
            from = from_unix,
            to = to_unix,
            limit = limit,
        );
        let text = self.post_sql(sql).await?;
        parse_rows(&text)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// POST `sql` as the raw request body, return the response body text.
    async fn post_sql(&self, sql: String) -> Result<String, StorageError> {
        let uri: hyper::Uri = self
            .url
            .parse()
            .map_err(|e| StorageError::ClickHouse(format!("invalid URI: {e}")))?;

        let req = self
            .auth(
                Request::builder()
                    .method(Method::POST)
                    .uri(uri)
                    .header("Content-Type", "text/plain; charset=utf-8"),
            )
            .body(Full::new(Bytes::from(sql)))
            .map_err(|e| StorageError::ClickHouse(e.to_string()))?;

        let resp = self
            .http
            .request(req)
            .await
            .map_err(|e| StorageError::ClickHouse(format!("request: {e}")))?;

        let status = resp.status();
        let body_bytes = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| StorageError::ClickHouse(format!("body: {e}")))?
            .to_bytes();
        let body_str = String::from_utf8_lossy(&body_bytes).into_owned();

        if !status.is_success() {
            return Err(StorageError::ClickHouse(format!(
                "HTTP {status}: {body_str}"
            )));
        }
        Ok(body_str)
    }

    /// POST `sql`, discard the response body on success.
    async fn exec(&self, sql: String) -> Result<(), StorageError> {
        self.post_sql(sql).await.map(|_| ())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Escape a string for safe inclusion in a single-quoted ClickHouse SQL literal.
fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

fn parse_rows(text: &str) -> Result<Vec<TrafficRow>, StorageError> {
    let mut rows = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        rows.push(serde_json::from_str::<TrafficRow>(line)?);
    }
    Ok(rows)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ch_url() -> String {
        std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://127.0.0.1:8123".to_string())
    }

    // Authenticated client for live tests. Creds default to the dev compose
    // values; override via CLICKHOUSE_USER / CLICKHOUSE_PASSWORD.
    fn ch_client() -> ClickHouseClient {
        ClickHouseClient::with_auth(
            &ch_url(),
            "sentinel_logs",
            Some(std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "sentinel".into())),
            Some(std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_else(|_| "sentinel_dev".into())),
        )
    }

    #[test]
    fn traffic_row_json_roundtrip() {
        let row = TrafficRow {
            ts: 1_700_000_000,
            site_id: "site1".to_string(),
            reqs: 42,
            blocked: 3,
            p99_ms: 1.5,
        };
        let json = serde_json::to_string(&row).unwrap();
        let back: TrafficRow = serde_json::from_str(&json).unwrap();
        assert_eq!(row, back);
    }

    #[test]
    fn parse_rows_empty_input() {
        assert!(parse_rows("").unwrap().is_empty());
        assert!(parse_rows("  \n  \n").unwrap().is_empty());
    }

    #[test]
    fn parse_rows_multiple() {
        let text = r#"{"ts":1,"site_id":"s1","reqs":10,"blocked":1,"p99_ms":1.0}
{"ts":2,"site_id":"s1","reqs":20,"blocked":0,"p99_ms":2.0}"#;
        let rows = parse_rows(text).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].reqs, 10);
        assert_eq!(rows[1].reqs, 20);
    }

    #[tokio::test]
    #[ignore = "requires ClickHouse on localhost:8123"]
    async fn ping_succeeds() {
        let c = ch_client();
        c.ping().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires ClickHouse on localhost:8123"]
    async fn schema_insert_query() {
        let c = ch_client();
        c.ensure_schema().await.unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let rows = vec![
            TrafficRow {
                ts: now - 5,
                site_id: "s1".into(),
                reqs: 10,
                blocked: 1,
                p99_ms: 2.0,
            },
            TrafficRow {
                ts: now - 4,
                site_id: "s1".into(),
                reqs: 20,
                blocked: 0,
                p99_ms: 1.5,
            },
            TrafficRow {
                ts: now - 3,
                site_id: "s1".into(),
                reqs: 15,
                blocked: 2,
                p99_ms: 3.1,
            },
        ];

        c.insert_traffic_batch(&rows).await.unwrap();

        // MergeTree needs a moment before rows are visible.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let out = c.query_traffic_history(now - 10, now, 100).await.unwrap();
        assert!(out.len() >= 3, "expected ≥ 3 rows, got {}", out.len());
    }

    #[tokio::test]
    #[ignore = "requires ClickHouse on localhost:8123"]
    async fn events_insert_query_roundtrip() {
        let c = ch_client();
        c.ensure_schema().await.unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let rows = vec![sentinel_event_fixture(now, "TESTSITE.example", "942100")];
        c.insert_events_batch(&rows).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Filter by site — must round-trip the row we inserted.
        let out = c
            .query_events("TESTSITE.example", "", "", now - 10, now + 10, 50)
            .await
            .unwrap();
        assert!(
            out.iter()
                .any(|e| e.rule == "942100" && e.site == "TESTSITE.example"),
            "inserted event not found: {out:?}"
        );
    }

    fn sentinel_event_fixture(ts: i64, site: &str, rule: &str) -> WafEventRow {
        WafEventRow {
            ts,
            ip: "203.0.113.9".into(),
            country: String::new(),
            site: site.into(),
            tenant: "tenant-test".into(),
            method: "GET".into(),
            path: "/?id=1 UNION SELECT".into(),
            rule: rule.into(),
            attack: "SQL injection".into(),
            action: "BLOCK".into(),
            severity: "CRITICAL".into(),
            score: 5,
            status: 403,
            protocol: "h2".into(),
        }
    }
}
