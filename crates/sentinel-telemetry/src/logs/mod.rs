//! Real structured event logger.
//!
//! Writes NDJSON (one JSON object per line) to per-kind log files under
//! `$SENTINEL_LOG_DIR` (default: `/tmp/sentinel-logs`).  The Go control-plane
//! tails these files and streams the events to dashboard clients over SSE.
//!
//! # File layout
//!
//! ```text
//! $SENTINEL_LOG_DIR/
//!   access.log    — HTTP request/response records
//!   waf.log       — WAF rule matches (blocked / flagged)
//!   error.log     — system errors and warnings
//!   audit.log     — admin actions and config changes
//!   modsec.log    — CRS/ModSec phase transactions
//!   ml.log        — ML model inference decisions
//! ```
//!
//! Each line is a valid JSON object terminated by `\n`.

use std::{
    fs::{self, File, OpenOptions},
    io::{BufWriter, Write},
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;

// ---------------------------------------------------------------------------
// Low-level writer
// ---------------------------------------------------------------------------

struct LogFile {
    writer: Mutex<BufWriter<File>>,
}

impl LogFile {
    fn open(path: &Path) -> Result<Self> {
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("open log file: {}", path.display()))?;
        Ok(Self {
            writer: Mutex::new(BufWriter::with_capacity(8 * 1024, f)),
        })
    }

    fn write_json<T: Serialize>(&self, value: &T) -> Result<()> {
        let mut line = serde_json::to_string(value)?;
        line.push('\n');
        let mut w = self.writer.lock().expect("log writer poisoned");
        w.write_all(line.as_bytes())?;
        w.flush()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Timestamps
// ---------------------------------------------------------------------------

fn now_ts() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Format as UTC ISO-8601 (approx — no sub-second for log files)
    let (year, month, day, hour, min, sec) = epoch_to_ymdhms(secs);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        year, month, day, hour, min, sec
    )
}

fn epoch_to_ymdhms(epoch: u64) -> (u64, u64, u64, u64, u64, u64) {
    let sec = epoch % 60;
    let min = (epoch / 60) % 60;
    let hour = (epoch / 3600) % 24;
    let days = epoch / 86400;
    // Gregorian calendar approximation
    let mut year = 1970u64;
    let mut remaining = days;
    loop {
        let leap = if year % 400 == 0 {
            366
        } else if year % 100 == 0 {
            365
        } else if year % 4 == 0 {
            366
        } else {
            365
        };
        if remaining < leap {
            break;
        }
        remaining -= leap;
        year += 1;
    }
    let leap_year = year % 400 == 0 || (year % 4 == 0 && year % 100 != 0);
    let month_days: [u64; 12] = [
        31,
        if leap_year { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1u64;
    for &md in &month_days {
        if remaining < md {
            break;
        }
        remaining -= md;
        month += 1;
    }
    let day = remaining + 1;
    (year, month, day, hour, min, sec)
}

// ---------------------------------------------------------------------------
// Public event types
// ---------------------------------------------------------------------------

/// HTTP access log entry.
#[derive(Debug, Serialize)]
pub struct AccessEvent {
    pub ts: String,
    pub site: String,
    pub method: String,
    pub path: String,
    pub ip: String,
    pub status: u16,
    pub bytes: u64,
    /// Response latency in milliseconds.
    pub latency: f64,
    pub ua: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// WAF rule match / block event.
#[derive(Debug, Serialize)]
pub struct WafEvent {
    pub ts: String,
    pub ip: String,
    pub site: String,
    pub attack: String,
    pub rule: String,
    pub score: u32,
    pub sev: String,
    pub action: String,
    pub method: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_id: Option<String>,
}

/// System error / warning event.
#[derive(Debug, Serialize)]
pub struct ErrorEvent {
    pub ts: String,
    pub lvl: String,
    pub component: String,
    pub msg: String,
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

/// Admin audit event (written by both Go and Rust sides).
#[derive(Debug, Serialize)]
pub struct AuditEvent {
    pub ts: String,
    pub user: String,
    pub action: String,
    pub resource: String,
    pub ip: String,
    pub result: String,
    pub session: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff: Option<Value>,
}

/// ModSecurity / CRS rule transaction event.
#[derive(Debug, Serialize)]
pub struct ModsecEvent {
    pub ts: String,
    #[serde(rename = "txId")]
    pub tx_id: String,
    pub phase: u8,
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub msg: String,
    pub sev: String,
    pub site: String,
    pub ip: String,
    pub uri: String,
    pub action: String,
}

/// ML / AI inference decision event.
#[derive(Debug, Serialize)]
pub struct MlEvent {
    pub ts: String,
    pub ip: String,
    pub site: String,
    pub path: String,
    pub verdict: String,
    pub conf: String,
    pub model: String,
    pub latency: String,
    pub features: u32,
}

// ---------------------------------------------------------------------------
// EventLogger
// ---------------------------------------------------------------------------

/// Thread-safe, multi-kind event logger.
///
/// Create once at startup and share via `Arc<EventLogger>`.
pub struct EventLogger {
    access: LogFile,
    waf: LogFile,
    error: LogFile,
    audit: LogFile,
    modsec: LogFile,
    ml: LogFile,
}

impl EventLogger {
    /// Create a new `EventLogger` writing into `log_dir`.
    /// The directory is created if it does not exist.
    pub fn new(log_dir: impl AsRef<Path>) -> Result<Arc<Self>> {
        let dir = log_dir.as_ref();
        fs::create_dir_all(dir).with_context(|| format!("create log dir: {}", dir.display()))?;

        Ok(Arc::new(Self {
            access: LogFile::open(&dir.join("access.log"))?,
            waf: LogFile::open(&dir.join("waf.log"))?,
            error: LogFile::open(&dir.join("error.log"))?,
            audit: LogFile::open(&dir.join("audit.log"))?,
            modsec: LogFile::open(&dir.join("modsec.log"))?,
            ml: LogFile::open(&dir.join("ml.log"))?,
        }))
    }

    /// Create from the `SENTINEL_LOG_DIR` env var, defaulting to `/tmp/sentinel-logs`.
    pub fn from_env() -> Result<Arc<Self>> {
        let dir =
            std::env::var("SENTINEL_LOG_DIR").unwrap_or_else(|_| "/tmp/sentinel-logs".to_owned());
        Self::new(dir)
    }

    // ── Per-kind write methods ─────────────────────────────────────────────

    pub fn log_access(&self, mut ev: AccessEvent) {
        if ev.ts.is_empty() {
            ev.ts = now_ts();
        }
        if let Err(e) = self.access.write_json(&ev) {
            tracing::error!(error = %e, "failed to write access log");
        }
    }

    pub fn log_waf(&self, mut ev: WafEvent) {
        if ev.ts.is_empty() {
            ev.ts = now_ts();
        }
        if let Err(e) = self.waf.write_json(&ev) {
            tracing::error!(error = %e, "failed to write waf log");
        }
    }

    pub fn log_error(&self, mut ev: ErrorEvent) {
        if ev.ts.is_empty() {
            ev.ts = now_ts();
        }
        if let Err(e) = self.error.write_json(&ev) {
            tracing::error!(error = %e, "failed to write error log");
        }
    }

    pub fn log_audit(&self, mut ev: AuditEvent) {
        if ev.ts.is_empty() {
            ev.ts = now_ts();
        }
        if let Err(e) = self.audit.write_json(&ev) {
            tracing::error!(error = %e, "failed to write audit log");
        }
    }

    pub fn log_modsec(&self, mut ev: ModsecEvent) {
        if ev.ts.is_empty() {
            ev.ts = now_ts();
        }
        if let Err(e) = self.modsec.write_json(&ev) {
            tracing::error!(error = %e, "failed to write modsec log");
        }
    }

    pub fn log_ml(&self, mut ev: MlEvent) {
        if ev.ts.is_empty() {
            ev.ts = now_ts();
        }
        if let Err(e) = self.ml.write_json(&ev) {
            tracing::error!(error = %e, "failed to write ml log");
        }
    }
}

// ---------------------------------------------------------------------------
// Builder helpers
// ---------------------------------------------------------------------------

impl AccessEvent {
    pub fn new(
        site: &str,
        method: &str,
        path: &str,
        ip: &str,
        status: u16,
        bytes: u64,
        latency_ms: f64,
        ua: &str,
    ) -> Self {
        Self {
            ts: now_ts(),
            site: site.to_owned(),
            method: method.to_owned(),
            path: path.to_owned(),
            ip: ip.to_owned(),
            status,
            bytes,
            latency: latency_ms,
            ua: ua.to_owned(),
            request_id: None,
        }
    }
}

impl WafEvent {
    pub fn new(
        ip: &str,
        site: &str,
        attack: &str,
        rule: &str,
        score: u32,
        sev: &str,
        action: &str,
        method: &str,
        path: &str,
    ) -> Self {
        Self {
            ts: now_ts(),
            ip: ip.to_owned(),
            site: site.to_owned(),
            attack: attack.to_owned(),
            rule: rule.to_owned(),
            score,
            sev: sev.to_owned(),
            action: action.to_owned(),
            method: method.to_owned(),
            path: path.to_owned(),
            tx_id: None,
        }
    }
}

impl ErrorEvent {
    pub fn new(lvl: &str, component: &str, msg: &str, code: &str) -> Self {
        Self {
            ts: now_ts(),
            lvl: lvl.to_owned(),
            component: component.to_owned(),
            msg: msg.to_owned(),
            code: code.to_owned(),
            details: None,
        }
    }
}

impl MlEvent {
    pub fn new(
        ip: &str,
        site: &str,
        path: &str,
        verdict: &str,
        conf: f64,
        model: &str,
        latency_ms: f64,
        features: u32,
    ) -> Self {
        Self {
            ts: now_ts(),
            ip: ip.to_owned(),
            site: site.to_owned(),
            path: path.to_owned(),
            verdict: verdict.to_owned(),
            conf: format!("{:.1}", conf),
            model: model.to_owned(),
            latency: format!("{:.2}", latency_ms),
            features,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn writes_access_log() {
        let dir = TempDir::new().unwrap();
        let logger = EventLogger::new(dir.path()).unwrap();
        logger.log_access(AccessEvent::new(
            "test.local",
            "GET",
            "/api/v1/health",
            "127.0.0.1",
            200,
            128,
            0.5,
            "sentinel-test/1.0",
        ));
        let contents = std::fs::read_to_string(dir.path().join("access.log")).unwrap();
        assert!(contents.contains("\"site\":\"test.local\""));
        assert!(contents.contains("\"status\":200"));
        let parsed: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();
        assert_eq!(parsed["method"], "GET");
    }

    #[test]
    fn writes_waf_log() {
        let dir = TempDir::new().unwrap();
        let logger = EventLogger::new(dir.path()).unwrap();
        logger.log_waf(WafEvent::new(
            "1.2.3.4",
            "api.acme.com",
            "SQL Injection",
            "CRS-942100",
            25,
            "HIGH",
            "BLOCKED",
            "POST",
            "/search",
        ));
        let contents = std::fs::read_to_string(dir.path().join("waf.log")).unwrap();
        assert!(contents.contains("BLOCKED"));
    }

    #[test]
    fn from_env_uses_default() {
        std::env::remove_var("SENTINEL_LOG_DIR");
        let logger = EventLogger::from_env().unwrap();
        logger.log_error(ErrorEvent::new("INFO", "test", "startup check", "E0000"));
    }
}
