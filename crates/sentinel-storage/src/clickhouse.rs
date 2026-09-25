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

/// One connector serves both schemes. Built with `https_or_http()`, so a
/// `http://clickhouse:8123` URL (the single-host default) keeps working
/// unchanged while `https://…` negotiates TLS — no second client type, no
/// branching at every call site.
type HyperClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

// ---------------------------------------------------------------------------
// TrafficRow
// ---------------------------------------------------------------------------

/// One second of traffic metrics — written to ClickHouse every second.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrafficRow {
    /// Unix timestamp (seconds).
    pub ts: i64,
    /// Owning tenant.  Empty on rows written before per-tenant scoping existed
    /// (hidden from every tenant, fail-closed).
    #[serde(default)]
    pub tenant: String,
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
    /// The request's query string, capped at write time. Kept separate from
    /// `path` so per-path grouping keeps its cardinality. Empty when the
    /// request had none (or the row predates the column).
    #[serde(default)]
    pub query: String,
    /// Referer header — for SPA traffic, the only field naming which screen of
    /// the app fired the request. Empty when absent.
    #[serde(default)]
    pub referer: String,
    /// The text the top rule actually matched (capped, credential targets
    /// redacted at the source). Empty when nothing capturable matched.
    #[serde(default)]
    pub matched: String,
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
    /// Correlation id shared with the NDJSON access/waf logs and the tracing
    /// span, so a stored event can be tied back to the exact request.
    #[serde(default)]
    pub request_id: String,
    /// Which part of the request tripped the rule (`ARGS:id`). Empty when the
    /// rule inspected several targets — see the VM's target attribution.
    #[serde(default)]
    pub target: String,
    /// Site enforcement mode at the time: blocking | learning | off | node.
    /// Without it a stored DETECT cannot be distinguished from a policy that was
    /// simply not enforcing.
    #[serde(default)]
    pub mode: String,
    /// The site's anomaly threshold, so a stored score means something on its own.
    #[serde(default)]
    pub threshold: u32,
    /// Human-readable explanation of the verdict, as written to waf.log.
    #[serde(default)]
    pub explanation: String,
    /// JA4 TLS fingerprint of the client (`t…` over TCP, `q…` over QUIC), or
    /// empty for plaintext / no fingerprint. This is the value that drove the
    /// malicious-JA4 bot signal and the JA4 blocklist — without it on the row, a
    /// JA4-based block cannot be audited after the fact. `#[serde(default)]`
    /// keeps rows written before the column existed deserializable.
    #[serde(default)]
    pub ja4: String,
    /// Every rule that contributed to the verdict, biggest score first, as a
    /// JSON array of `{id, msg, sev, score, target, matched}`. The row used to
    /// carry only the leading rule, so a score of 85 built from several rules
    /// read as one rule's doing. JSON text rather than nested columns so the
    /// shape can grow without a schema change. `"[]"`/empty on older rows.
    #[serde(default)]
    pub rules: String,
    /// The request's headers as a JSON object, redacted at the source
    /// (sensitive header names, sensitive cookie values, Referer/Origin query).
    #[serde(default)]
    pub headers: String,
    /// User-Agent, capped. Also inside `headers`, but its own column so Threat
    /// Search can filter and facet on the client without parsing JSON.
    #[serde(default)]
    pub ua: String,
}

// ---------------------------------------------------------------------------
// ClickHouseClient
// ---------------------------------------------------------------------------

/// Every column the event INSERT names — and it MUST list every serialised
/// field of [`WafEventRow`], because the body is `FORMAT JSONEachRow` from
/// `serde_json::to_string(row)` and ClickHouse rejects a JSON key that is not
/// in the column list (`input_format_skip_unknown_fields` is off). A struct
/// field added without a matching entry here therefore fails EVERY event
/// insert at runtime while compiling clean. `every_serialised_field_is_an_insert_column`
/// pins the two together.
const WAF_EVENT_COLUMNS: &str = "ts, ip, country, site, tenant, method, path, query, \
    referer, matched, rule, attack, action, severity, score, status, protocol, \
    request_id, target, mode, threshold, explanation, ja4, rules, headers, ua";

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

/// Reads a retention window (in days) from `var`, clamped to 1..=3650 days,
/// falling back to `default` when unset or unparseable. Retention is operator
/// policy (compliance windows differ per customer / product tier), so it is
/// env-configurable rather than hardcoded — see the
/// `SENTINEL_CLICKHOUSE_{EVENT,TRAFFIC}_RETENTION_DAYS` variables.
fn retention_days(var: &str, default: u32) -> u32 {
    std::env::var(var)
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .map(|d| d.clamp(1, 3650))
        .unwrap_or(default)
}

/// Load the private CA bundle named by `SENTINEL_CLICKHOUSE_CA_FILE`, if set.
///
/// `Ok(None)`  — not configured; use the public webpki roots.
/// `Ok(Some)`  — configured and parsed; trust EXACTLY these.
/// `Err`       — configured but unusable. Deliberately NOT a fallback to the
///               public roots: silently widening what we trust because a file
///               was missing is the wrong failure for a WAF. The caller turns
///               this into an empty root store, so TLS fails loudly instead —
///               and the history spool means the events wait on disk rather than
///               being lost while someone fixes the path.
fn clickhouse_ca_roots() -> Result<Option<rustls::RootCertStore>, String> {
    let path = match std::env::var("SENTINEL_CLICKHOUSE_CA_FILE") {
        Ok(p) if !p.trim().is_empty() => p,
        _ => return Ok(None),
    };
    let pem = std::fs::read(&path).map_err(|e| format!("read {path}: {e}"))?;
    let mut rd = std::io::BufReader::new(std::io::Cursor::new(pem));
    let mut roots = rustls::RootCertStore::empty();
    let mut added = 0usize;
    for cert in rustls_pemfile::certs(&mut rd) {
        let cert = cert.map_err(|e| format!("parse {path}: {e}"))?;
        roots
            .add(cert)
            .map_err(|e| format!("add cert from {path}: {e}"))?;
        added += 1;
    }
    if added == 0 {
        return Err(format!("{path} contained no CERTIFICATE blocks"));
    }
    tracing::info!(ca_file = %path, certs = added, "clickhouse TLS: trusting private CA");
    Ok(Some(roots))
}

/// Connector accepting both `http://` and `https://` ClickHouse URLs.
///
/// `https_or_http()` (rather than `https_only()`) is deliberate: the single-host
/// compose default is `http://clickhouse:8123` over a private bridge, and forcing
/// TLS there would break every existing deployment for no gain — that traffic
/// never leaves the host. TLS is what the URL asks for, not a global mode.
///
/// The `ring` provider is passed explicitly rather than relying on the
/// process-default one. sentinel-bin installs ring at startup, but this crate is
/// also used from unit tests and other binaries where nothing has installed a
/// default, and `ClientConfig::builder()` panics in that state.
fn https_connector() -> hyper_rustls::HttpsConnector<HttpConnector> {
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());

    let roots = match clickhouse_ca_roots() {
        Ok(Some(r)) => Some(r),
        Ok(None) => None,
        Err(e) => {
            // Configured but broken: trust nothing rather than trust more.
            tracing::error!(
                error = %e,
                "clickhouse TLS: SENTINEL_CLICKHOUSE_CA_FILE is set but unusable — \
                 refusing to fall back to public roots; every https connection to \
                 ClickHouse will now FAIL verification (history spools to disk meanwhile)"
            );
            Some(rustls::RootCertStore::empty())
        }
    };

    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default protocol versions");

    let tls = match roots {
        Some(r) => builder.with_root_certificates(r).with_no_client_auth(),
        None => {
            let mut r = rustls::RootCertStore::empty();
            r.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            builder.with_root_certificates(r).with_no_client_auth()
        }
    };

    let mut http = HttpConnector::new();
    http.enforce_http(false); // required, else the connector rejects https URIs
    hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .wrap_connector(http)
}

#[cfg(test)]
mod tls_tests {
    use super::*;
    use std::io::Write as _;

    /// Env-var tests must not run concurrently — they mutate process state.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_ca_env<T>(value: Option<&str>, f: impl FnOnce() -> T) -> T {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var("SENTINEL_CLICKHOUSE_CA_FILE").ok();
        match value {
            Some(v) => std::env::set_var("SENTINEL_CLICKHOUSE_CA_FILE", v),
            None => std::env::remove_var("SENTINEL_CLICKHOUSE_CA_FILE"),
        }
        let out = f();
        match prev {
            Some(p) => std::env::set_var("SENTINEL_CLICKHOUSE_CA_FILE", p),
            None => std::env::remove_var("SENTINEL_CLICKHOUSE_CA_FILE"),
        }
        out
    }

    fn tmp(name: &str, body: &[u8]) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("sentinel-ch-ca-{}-{name}", std::process::id()));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(body).unwrap();
        p
    }

    #[test]
    fn unset_ca_uses_public_roots() {
        with_ca_env(None, || {
            assert!(matches!(clickhouse_ca_roots(), Ok(None)));
        });
    }

    #[test]
    fn empty_ca_var_is_treated_as_unset() {
        with_ca_env(Some(""), || {
            assert!(matches!(clickhouse_ca_roots(), Ok(None)));
        });
    }

    #[test]
    fn missing_ca_file_is_an_error_not_a_silent_fallback() {
        // The security property: a broken CA path must NOT quietly widen trust
        // back to the public roots.
        with_ca_env(Some("/nonexistent/sentinel/root.crt"), || {
            let r = clickhouse_ca_roots();
            assert!(r.is_err(), "expected Err, got {r:?}");
        });
    }

    #[test]
    fn ca_file_without_certificates_is_an_error() {
        let p = tmp("empty.pem", b"not a pem file at all\n");
        with_ca_env(Some(p.to_str().unwrap()), || {
            let e = clickhouse_ca_roots().unwrap_err();
            assert!(e.contains("no CERTIFICATE"), "unexpected error: {e}");
        });
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn a_real_ca_pem_is_loaded_and_trusted_exclusively() {
        // Minimal self-signed CA generated once and pasted in, so the test needs
        // no openssl at runtime.
        const CA: &[u8] = b"-----BEGIN CERTIFICATE-----\n\
MIIBhTCCASugAwIBAgIUJ8Vd0mBvbEDMBhDLRWCLBjjzWQ0wCgYIKoZIzj0EAwIw\n\
FDESMBAGA1UEAwwJc2VudGluZWxDQTAeFw0yNTAxMDEwMDAwMDBaFw0zNTAxMDEw\n\
MDAwMDBaMBQxEjAQBgNVBAMMCXNlbnRpbmVsQ0EwWTATBgcqhkjOPQIBBggqhkjO\n\
PQMBBwNCAAS0Vf4Yl7lQ0dQfVfLKQxJwCJqYQfKp0h9x8fVKQeXKQnBqQdVQKzXK\n\
Qb1nQ8VqKzXKQb1nQ8VqKzXKQb1nQ8VqKzWjUzBRMB0GA1UdDgQWBBQx8fVKQeXK\n\
QnBqQdVQKzXKQb1nQzAfBgNVHSMEGDAWgBQx8fVKQeXKQnBqQdVQKzXKQb1nQzAP\n\
BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQCx8fVKQeXKQnBqQdVQ\n\
KzXKQb1nQ8VqKzXKQb1nQ8VqKwIgKzXKQb1nQ8VqKzXKQb1nQ8VqKzXKQb1nQ8Vq\n\
KzU=\n\
-----END CERTIFICATE-----\n";
        let p = tmp("ca.pem", CA);
        with_ca_env(Some(p.to_str().unwrap()), || {
            match clickhouse_ca_roots() {
                // Parsed: trust is scoped to exactly this one anchor, NOT the
                // ~150 public roots — that scoping is the whole point.
                Ok(Some(store)) => assert_eq!(store.len(), 1),
                // A hand-rolled PEM may be rejected by webpki's stricter parser;
                // an Err is still correct behaviour (fail closed, never widen).
                Ok(None) => panic!("configured CA must not read as 'unset'"),
                Err(e) => assert!(
                    e.contains("add cert") || e.contains("parse"),
                    "unexpected error: {e}"
                ),
            }
        });
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn connector_builds_for_both_schemes() {
        // Must not panic even with no process-default CryptoProvider installed —
        // that is why the ring provider is passed explicitly.
        with_ca_env(None, || {
            let _ = https_connector();
        });
    }

    #[test]
    fn connector_still_builds_when_the_ca_is_broken() {
        // Degrades to an empty root store (all TLS fails, loudly) rather than
        // panicking or silently trusting the public roots.
        with_ca_env(Some("/nonexistent/sentinel/root.crt"), || {
            let _ = https_connector();
        });
    }
}

impl ClickHouseClient {
    /// Construct an unauthenticated client (uses the `default` user).
    pub fn new(url: &str, database: &str) -> Self {
        Self::with_auth(url, database, None, None)
    }

    /// Construct a client with optional ClickHouse credentials.
    ///
    /// Speaks TLS when the URL scheme is `https`. This matters because in the
    /// 2-VM topology the passive node writes its event history to the ACTIVE
    /// node's ClickHouse across the peer link, and the ClickHouse password plus
    /// every event body travels that wire — plaintext there was the one
    /// remaining place this deployment protected a database by reachability
    /// rather than by crypto (see deploy/docker/compose.2vm-active.yml).
    pub fn with_auth(
        url: &str,
        database: &str,
        username: Option<String>,
        password: Option<String>,
    ) -> Self {
        Self {
            http: Client::builder(TokioExecutor::new()).build(https_connector()),
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
        // Operator-configurable retention (in days). Applied to fresh tables via
        // the CREATE statements below, and to ALREADY-EXISTING tables via
        // ALTER ... MODIFY TTL at the end of this function (so a retention change
        // takes effect on restart, not only on first creation).
        let event_days = retention_days("SENTINEL_CLICKHOUSE_EVENT_RETENTION_DAYS", 90);
        let traffic_days = retention_days("SENTINEL_CLICKHOUSE_TRAFFIC_RETENTION_DAYS", 30);

        self.exec(format!(
            "CREATE DATABASE IF NOT EXISTS {db}",
            db = self.database
        ))
        .await?;

        self.exec(format!(
            "CREATE TABLE IF NOT EXISTS {db}.traffic_buckets \
             (ts DateTime, tenant LowCardinality(String), site_id LowCardinality(String), \
              reqs Int64, blocked Int64, p99_ms Float64) \
             ENGINE = MergeTree() \
             PARTITION BY toYYYYMM(ts) \
             ORDER BY (tenant, site_id, ts) \
             TTL ts + INTERVAL {ttl_days} DAY \
             SETTINGS index_granularity = 8192",
            db = self.database,
            ttl_days = traffic_days
        ))
        .await?;

        // Detailed, searchable event log (blocks + learning detections).
        self.exec(format!(
            "CREATE TABLE IF NOT EXISTS {db}.waf_events \
             (ts DateTime, ip String, country LowCardinality(String), \
              site LowCardinality(String), tenant LowCardinality(String), \
              method LowCardinality(String), \
              path String, query String, referer String, matched String, \
              rule LowCardinality(String), attack String, \
              action LowCardinality(String), severity LowCardinality(String), \
              score UInt32, status UInt16, protocol LowCardinality(String), \
              request_id String, target String, mode LowCardinality(String), \
              threshold UInt32, explanation String, ja4 LowCardinality(String), \
              rules String, headers String, ua String) \
             ENGINE = MergeTree() \
             PARTITION BY toYYYYMMDD(ts) \
             ORDER BY (site, ts) \
             TTL ts + INTERVAL {ttl_days} DAY \
             SETTINGS index_granularity = 8192",
            db = self.database,
            ttl_days = event_days
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
        .await?;

        // Additive online migration: the explain-the-verdict columns. Existing
        // deployments (the VM's table predates these) get them with empty
        // defaults; old rows simply have no explanation, which the UI renders as
        // absent rather than inventing one.
        for col in [
            "request_id String",
            "target String",
            "mode LowCardinality(String)",
            "threshold UInt32",
            "explanation String",
            // Forensic-triage columns (2026-08): the query string, the page the
            // request came from, and the text the rule matched. Empty on rows
            // written before they existed — the UI renders that as absent.
            "query String",
            "referer String",
            "matched String",
            // The client's JA4 (2026-09): the fingerprint that drives bot scoring
            // and the JA4 blocklist was never stored, so a block it caused could
            // not be explained from the row. LowCardinality: a fleet sees a few
            // thousand distinct fingerprints, not one per request.
            "ja4 LowCardinality(String)",
            // Every contributing rule, the redacted request headers and the
            // User-Agent (2026-09-25): the event named only the leading rule and
            // never the client, so a false positive could not be triaged from it.
            "rules String",
            "headers String",
            "ua String",
        ] {
            self.exec(format!(
                "ALTER TABLE {db}.waf_events ADD COLUMN IF NOT EXISTS {col} DEFAULT {default}",
                db = self.database,
                default = if col.contains("UInt32") { "0" } else { "''" }
            ))
            .await?;
        }

        // Additive online migration: per-tenant scoping on traffic_buckets too
        // (empty on pre-existing rows → hidden from every tenant, fail-closed).
        self.exec(format!(
            "ALTER TABLE {db}.traffic_buckets \
             ADD COLUMN IF NOT EXISTS tenant LowCardinality(String) DEFAULT ''",
            db = self.database
        ))
        .await?;

        // Enforce the configured retention on EXISTING tables. CREATE ... IF NOT
        // EXISTS only sets TTL when it first creates the table, so an operator
        // changing SENTINEL_CLICKHOUSE_*_RETENTION_DAYS needs MODIFY TTL for it
        // to apply to the already-created tables. This is a cheap metadata
        // change; ClickHouse drops expired parts lazily during background merges.
        self.exec(format!(
            "ALTER TABLE {db}.waf_events MODIFY TTL ts + INTERVAL {ttl_days} DAY",
            db = self.database,
            ttl_days = event_days
        ))
        .await?;
        self.exec(format!(
            "ALTER TABLE {db}.traffic_buckets MODIFY TTL ts + INTERVAL {ttl_days} DAY",
            db = self.database,
            ttl_days = traffic_days
        ))
        .await
    }

    /// Batch-insert detailed WAF events into `waf_events`.
    pub async fn insert_events_batch(&self, rows: &[WafEventRow]) -> Result<(), StorageError> {
        if rows.is_empty() {
            return Ok(());
        }
        let mut sql = format!(
            "INSERT INTO {db}.waf_events ({cols}) FORMAT JSONEachRow\n",
            db = self.database,
            cols = WAF_EVENT_COLUMNS,
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
             rule, attack, action, severity, score, status, protocol, ja4 \
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
             (ts, tenant, site_id, reqs, blocked, p99_ms) \
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
            "SELECT toUnixTimestamp(ts) AS ts, tenant, site_id, reqs, blocked, p99_ms \
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
            "SELECT toUnixTimestamp(toStartOfMinute(ts)) AS ts, tenant, site_id, \
             sum(reqs) AS reqs, sum(blocked) AS blocked, avg(p99_ms) AS p99_ms \
             FROM {db}.traffic_buckets \
             WHERE ts >= toDateTime({from}) AND ts <= toDateTime({to}) \
             GROUP BY tenant, site_id, toStartOfMinute(ts) \
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
            tenant: "t1".to_string(),
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
                tenant: "t1".into(),
                site_id: "s1".into(),
                reqs: 10,
                blocked: 1,
                p99_ms: 2.0,
            },
            TrafficRow {
                ts: now - 4,
                tenant: "t1".into(),
                site_id: "s1".into(),
                reqs: 20,
                blocked: 0,
                p99_ms: 1.5,
            },
            TrafficRow {
                ts: now - 3,
                tenant: "t1".into(),
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
            path: "/".into(),
            query: "id=1 UNION SELECT".into(),
            referer: String::new(),
            matched: "1 UNION SELECT".into(),
            rule: rule.into(),
            attack: "SQL injection".into(),
            action: "BLOCK".into(),
            severity: "CRITICAL".into(),
            score: 5,
            status: 403,
            protocol: "h2".into(),
            request_id: "11111111-2222-3333-4444-555555555555".into(),
            target: "ARGS:id".into(),
            mode: "blocking".into(),
            threshold: 5,
            explanation: "BLOCKED on 'TESTSITE.example': SQL injection in parameter 'id'.".into(),
            ja4: String::new(),
            rules: String::new(),
            headers: String::new(),
            ua: String::new(),
        }
    }
}

#[cfg(test)]
mod insert_column_pinning {
    use super::*;

    /// A `WafEventRow` field with no INSERT column fails every event insert at
    /// runtime and compiles clean — the worst kind of schema drift. This pins the
    /// serialised field set to the column list, both ways.
    #[test]
    fn every_serialised_field_is_an_insert_column() {
        let row = WafEventRow {
            ts: 0,
            ip: String::new(),
            country: String::new(),
            site: String::new(),
            tenant: String::new(),
            method: String::new(),
            path: String::new(),
            query: String::new(),
            referer: String::new(),
            matched: String::new(),
            rule: String::new(),
            attack: String::new(),
            action: String::new(),
            severity: String::new(),
            score: 0,
            status: 0,
            protocol: String::new(),
            request_id: String::new(),
            target: String::new(),
            mode: String::new(),
            threshold: 0,
            explanation: String::new(),
            ja4: String::new(),
            rules: String::new(),
            headers: String::new(),
            ua: String::new(),
        };
        let json = serde_json::to_value(&row).expect("serialise");
        let mut fields: Vec<&str> = json
            .as_object()
            .expect("row serialises to an object")
            .keys()
            .map(String::as_str)
            .collect();
        fields.sort_unstable();

        let mut cols: Vec<&str> = WAF_EVENT_COLUMNS
            .split(',')
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .collect();
        cols.sort_unstable();

        assert_eq!(
            fields, cols,
            "WafEventRow's serialised fields and WAF_EVENT_COLUMNS have drifted. A field \
             without a column makes ClickHouse reject EVERY event insert; a column without \
             a field is a silent NULL/default. Fix both sides together, and add the column \
             to ensure_schema's ADD COLUMN list."
        );
    }
}
