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

// ---------------------------------------------------------------------------
// ClickHouseClient
// ---------------------------------------------------------------------------

pub struct ClickHouseClient {
    http: HyperClient,
    /// Base URL, e.g. `http://127.0.0.1:8123`.
    url: String,
    database: String,
}

impl ClickHouseClient {
    pub fn new(url: &str, database: &str) -> Self {
        Self {
            http: Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>(),
            url: url.trim_end_matches('/').to_string(),
            database: database.to_string(),
        }
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// `GET /ping` — fast liveness check.
    pub async fn ping(&self) -> Result<(), StorageError> {
        let uri: hyper::Uri = format!("{}/ping", self.url)
            .parse()
            .map_err(|e| StorageError::ClickHouse(format!("invalid URI: {e}")))?;

        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
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
        .await
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
             ORDER BY ts LIMIT {limit} FORMAT JSONEachRow",
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
             ORDER BY ts LIMIT {limit} FORMAT JSONEachRow",
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

        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("Content-Type", "text/plain; charset=utf-8")
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
        std::env::var("CLICKHOUSE_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8123".to_string())
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
        let c = ClickHouseClient::new(&ch_url(), "sentinel_test");
        c.ping().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires ClickHouse on localhost:8123"]
    async fn schema_insert_query() {
        let c = ClickHouseClient::new(&ch_url(), "sentinel_test");
        c.ensure_schema().await.unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let rows = vec![
            TrafficRow { ts: now - 5, site_id: "s1".into(), reqs: 10, blocked: 1, p99_ms: 2.0 },
            TrafficRow { ts: now - 4, site_id: "s1".into(), reqs: 20, blocked: 0, p99_ms: 1.5 },
            TrafficRow { ts: now - 3, site_id: "s1".into(), reqs: 15, blocked: 2, p99_ms: 3.1 },
        ];

        c.insert_traffic_batch(&rows).await.unwrap();

        // MergeTree needs a moment before rows are visible.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let out = c.query_traffic_history(now - 10, now, 100).await.unwrap();
        assert!(out.len() >= 3, "expected ≥ 3 rows, got {}", out.len());
    }
}
