//! HMAC-SHA256-chained audit log for the Sentinel WAF.
//!
//! Every audit entry is hashed as:
//!
//! ```text
//! hash = HMAC-SHA256(key=prev_hash, msg=entry_json_without_hash_field)
//! ```
//!
//! The genesis entry uses the empty string as the previous hash.
//! This creates a tamper-evident chain: any modification to a past entry
//! invalidates all subsequent hashes.
//!
//! Entries are written as NDJSON to `$SENTINEL_LOG_DIR/audit.log`.
//!
//! # Example
//!
//! ```rust,no_run
//! use sentinel_telemetry::audit::AuditLogger;
//!
//! let logger = AuditLogger::from_env().unwrap();
//! logger.write("admin@acme.com", "rule.update", "WafRule", "crs-942100", "10.0.0.1").unwrap();
//! ```

use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Audit entry
// ---------------------------------------------------------------------------

/// A single audit log record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique entry identifier.
    pub id: String,
    /// ISO-8601 timestamp (UTC, second precision).
    pub timestamp: String,
    /// Identity that performed the action (user name / service account).
    pub actor_id: String,
    /// Verb describing the action (e.g. `rule.create`, `policy.delete`).
    pub action: String,
    /// Resource type affected (e.g. `WafRule`, `SitePolicy`).
    pub target_kind: String,
    /// Resource identifier (name, UUID, slug …).
    pub target_id: String,
    /// Source IP address of the request.
    pub ip: String,
    /// Hex-encoded HMAC of the *previous* entry (empty string for genesis).
    pub prev_hash: String,
    /// Hex-encoded HMAC of this entry (excluding the `hash` field itself).
    pub hash: String,
}

// ---------------------------------------------------------------------------
// HMAC helper
// ---------------------------------------------------------------------------

fn compute_hmac(key: &[u8], message: &[u8]) -> String {
    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(message);
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

/// Encode bytes as lowercase hex without the `hex` crate.
mod hex {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";

    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        let bytes = bytes.as_ref();
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(DIGITS[(b >> 4) as usize] as char);
            s.push(DIGITS[(b & 0xf) as usize] as char);
        }
        s
    }

    pub fn decode(s: &str) -> Vec<u8> {
        fn nibble(c: u8) -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => 0,
            }
        }
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len() / 2);
        let mut i = 0;
        while i + 1 < bytes.len() {
            out.push((nibble(bytes[i]) << 4) | nibble(bytes[i + 1]));
            i += 2;
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Timestamp helper
// ---------------------------------------------------------------------------

fn now_iso8601() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let sec = secs % 60;
    let min = (secs / 60) % 60;
    let hour = (secs / 3600) % 24;
    let days = secs / 86400;
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
        31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
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
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, min, sec
    )
}

// ---------------------------------------------------------------------------
// AuditLogger
// ---------------------------------------------------------------------------

struct AuditLoggerInner {
    writer: BufWriter<File>,
    prev_hash: String,
}

/// Thread-safe, HMAC-chained audit logger.
///
/// Obtain the global singleton with [`AuditLogger::global`] or create a
/// standalone instance with [`AuditLogger::new`] / [`AuditLogger::from_env`].
pub struct AuditLogger {
    inner: Mutex<AuditLoggerInner>,
    _log_path: PathBuf,
}

impl AuditLogger {
    /// Open (or create) an audit log at `path`.
    ///
    /// The previous hash is initialised by reading the last entry in the
    /// existing file, so the chain is preserved across restarts.
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create audit log dir: {}", parent.display()))?;
        }

        let prev_hash = Self::read_last_hash(path)?;

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("open audit log: {}", path.display()))?;

        Ok(Self {
            inner: Mutex::new(AuditLoggerInner {
                writer: BufWriter::with_capacity(8 * 1024, file),
                prev_hash,
            }),
            _log_path: path.to_owned(),
        })
    }

    /// Create from `$SENTINEL_LOG_DIR` (default: `/tmp/sentinel-logs`).
    pub fn from_env() -> Result<Self> {
        let dir = std::env::var("SENTINEL_LOG_DIR")
            .unwrap_or_else(|_| "/tmp/sentinel-logs".to_owned());
        Self::new(PathBuf::from(dir).join("audit.log"))
    }

    /// Read the `hash` field from the last line of an existing log file.
    fn read_last_hash(path: &Path) -> Result<String> {
        if !path.exists() {
            return Ok(String::new());
        }
        let f = File::open(path).with_context(|| format!("open audit log for read: {}", path.display()))?;
        let reader = BufReader::new(f);
        let mut last = String::new();
        for line in reader.lines() {
            let l = line?;
            if !l.trim().is_empty() {
                last = l;
            }
        }
        if last.is_empty() {
            return Ok(String::new());
        }
        let entry: AuditEntry = serde_json::from_str(&last)
            .with_context(|| "parse last audit entry")?;
        Ok(entry.hash)
    }

    /// Write a new audit entry and append it to the log.
    pub fn write(
        &self,
        actor_id: impl Into<String>,
        action: impl Into<String>,
        target_kind: impl Into<String>,
        target_id: impl Into<String>,
        ip: impl Into<String>,
    ) -> Result<()> {
        let mut inner = self.inner.lock().expect("audit logger poisoned");

        // Build a partial entry (no hash yet) and serialise it.
        let partial = AuditEntry {
            id: Uuid::new_v4().to_string(),
            timestamp: now_iso8601(),
            actor_id: actor_id.into(),
            action: action.into(),
            target_kind: target_kind.into(),
            target_id: target_id.into(),
            ip: ip.into(),
            prev_hash: inner.prev_hash.clone(),
            hash: String::new(), // placeholder
        };

        // Serialise without the hash field to produce the HMAC message.
        let msg = serde_json::to_string(&AuditEntryWithoutHash::from(&partial))?;

        // Compute HMAC: key = prev_hash bytes (or empty key for genesis).
        let key = if inner.prev_hash.is_empty() {
            vec![0u8; 32]
        } else {
            hex::decode(&inner.prev_hash)
        };
        let hash = compute_hmac(&key, msg.as_bytes());

        let full = AuditEntry {
            hash: hash.clone(),
            ..partial
        };

        // Write NDJSON.
        let mut line = serde_json::to_string(&full)?;
        line.push('\n');
        inner.writer.write_all(line.as_bytes())?;
        inner.writer.flush()?;

        // Update chain pointer.
        inner.prev_hash = hash;

        Ok(())
    }

    /// Read all entries from `path` and verify the HMAC chain.
    ///
    /// Returns `Ok(true)` if the chain is intact, `Ok(false)` if any entry
    /// fails verification, or an `Err` if the file cannot be parsed.
    pub fn verify_chain(path: impl AsRef<Path>) -> Result<bool> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(true); // empty file is trivially valid
        }
        let f = File::open(path)?;
        let reader = BufReader::new(f);
        let mut prev_hash = String::new();

        for (line_no, line) in reader.lines().enumerate() {
            let l = line?;
            if l.trim().is_empty() {
                continue;
            }
            let entry: AuditEntry = serde_json::from_str(&l)
                .with_context(|| format!("parse audit entry at line {}", line_no + 1))?;

            // Re-compute expected hash.
            let msg = serde_json::to_string(&AuditEntryWithoutHash::from(&entry))?;
            let key = if prev_hash.is_empty() {
                vec![0u8; 32]
            } else {
                hex::decode(&prev_hash)
            };
            let expected = compute_hmac(&key, msg.as_bytes());

            if entry.hash != expected {
                tracing::warn!(
                    line = line_no + 1,
                    entry_id = %entry.id,
                    "audit chain verification failed"
                );
                return Ok(false);
            }
            prev_hash = entry.hash.clone();
        }
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Global singleton
// ---------------------------------------------------------------------------

static GLOBAL_AUDIT_LOGGER: OnceCell<AuditLogger> = OnceCell::new();

impl AuditLogger {
    /// Initialise the global audit logger.
    ///
    /// Must be called once at startup before [`AuditLogger::global`].
    pub fn init_global(path: impl AsRef<Path>) -> Result<()> {
        let logger = AuditLogger::new(path)?;
        GLOBAL_AUDIT_LOGGER
            .set(logger)
            .map_err(|_| anyhow::anyhow!("global audit logger already initialised"))
    }

    /// Return a reference to the global logger.
    ///
    /// # Panics
    ///
    /// Panics if [`AuditLogger::init_global`] was not called first.
    pub fn global() -> &'static AuditLogger {
        GLOBAL_AUDIT_LOGGER
            .get()
            .expect("AuditLogger::init_global() not called")
    }
}

// ---------------------------------------------------------------------------
// Internal helper: entry without the `hash` field for HMAC computation
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct AuditEntryWithoutHash<'a> {
    id: &'a str,
    timestamp: &'a str,
    actor_id: &'a str,
    action: &'a str,
    target_kind: &'a str,
    target_id: &'a str,
    ip: &'a str,
    prev_hash: &'a str,
}

impl<'a> From<&'a AuditEntry> for AuditEntryWithoutHash<'a> {
    fn from(e: &'a AuditEntry) -> Self {
        Self {
            id: &e.id,
            timestamp: &e.timestamp,
            actor_id: &e.actor_id,
            action: &e.action,
            target_kind: &e.target_kind,
            target_id: &e.target_id,
            ip: &e.ip,
            prev_hash: &e.prev_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn write_and_verify_chain() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.log");
        let logger = AuditLogger::new(&log_path).unwrap();

        logger
            .write("alice", "rule.create", "WafRule", "crs-942100", "10.0.0.1")
            .unwrap();
        logger
            .write("bob", "policy.update", "SitePolicy", "default", "192.168.1.5")
            .unwrap();
        logger
            .write("alice", "rule.delete", "WafRule", "crs-942100", "10.0.0.1")
            .unwrap();

        let valid = AuditLogger::verify_chain(&log_path).unwrap();
        assert!(valid, "chain should be intact");
    }

    #[test]
    fn tampered_entry_fails_verification() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.log");
        let logger = AuditLogger::new(&log_path).unwrap();

        logger
            .write("alice", "rule.create", "WafRule", "crs-942100", "10.0.0.1")
            .unwrap();
        logger
            .write("bob", "policy.update", "SitePolicy", "default", "192.168.1.5")
            .unwrap();

        // Tamper: replace the file content with a modified first line.
        let contents = std::fs::read_to_string(&log_path).unwrap();
        let tampered = contents.replacen("rule.create", "rule.delete", 1);
        std::fs::write(&log_path, tampered).unwrap();

        let valid = AuditLogger::verify_chain(&log_path).unwrap();
        assert!(!valid, "chain should be broken after tampering");
    }

    #[test]
    fn empty_log_verifies() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("nonexistent_audit.log");
        let valid = AuditLogger::verify_chain(&log_path).unwrap();
        assert!(valid);
    }

    #[test]
    fn prev_hash_carried_across_entries() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.log");
        let logger = AuditLogger::new(&log_path).unwrap();
        logger
            .write("sys", "startup", "System", "sentinel", "127.0.0.1")
            .unwrap();

        let contents = std::fs::read_to_string(&log_path).unwrap();
        let first: AuditEntry = serde_json::from_str(contents.trim()).unwrap();
        assert_eq!(first.prev_hash, "", "genesis entry has empty prev_hash");
        assert!(!first.hash.is_empty());
    }
}
