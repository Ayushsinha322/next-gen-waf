//! Continuous security-event feed to a SIEM.
//!
//! # Why this exists
//!
//! The product could already *alert* to syslog/CEF, but that path is
//! alert-driven: the control plane's alerting engine only sees `action="BLOCK"`,
//! and de-duplicates within a throttle window before sending. A SOC therefore
//! received "IP x was blocked 50 times" once, and never received a learning-mode
//! DETECT at all — so the feed could not be used to reconstruct traffic, which
//! is the whole reason a SIEM is fed. The only complete records were the NDJSON
//! files on each node and ClickHouse, both pull-only.
//!
//! This forwards EVERY notable event (block and would-have-blocked alike) as it
//! happens, from the data plane, where the events already exist.
//!
//! # Design constraints, and why each one is load-bearing
//!
//! * **It cannot slow down or break request handling.** Enqueue is a
//!   non-blocking `try_send` on a bounded channel; when the queue is full the
//!   event is dropped and counted. A SIEM that stops reading must never become
//!   backpressure on a WAF.
//! * **It cannot cost the primary record, and the primary record cannot cost
//!   it.** The two sinks are independent in `record_event`: this one is a
//!   non-blocking try_send on its own bounded queue, so it cannot delay the
//!   ClickHouse buffer, and a full ClickHouse buffer cannot stop the feed. An
//!   earlier cut hooked this behind ClickHouse's "is there a drainer" gate,
//!   which silently disabled the feed on a SIEM-only deployment — caught by
//!   running it against a real collector, not by reading the code.
//! * **Loss is visible.** `sentinel_siem_events_dropped_total` and
//!   `sentinel_siem_connect_failures_total` are scraped, because a silent gap in
//!   a security feed is worse than a visible one — the reader believes the quiet
//!   period was quiet.
//! * **Delivery is at-most-once, deliberately.** There is no disk spool here.
//!   ClickHouse is the durable record and already spools; a second on-disk
//!   replay queue would double the disk cost of every event to give a SIEM a
//!   guarantee it usually does not want (most deployments would rather have a
//!   gap than a delayed replay storm). This is stated so the trade-off is a
//!   decision rather than an accident.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sentinel_storage::WafEventRow;
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

/// Wire format for each event.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SiemFormat {
    /// ArcSight CEF carried in an RFC 5424 syslog frame. Matches the vendor and
    /// product strings the control plane's alert CEF sender already uses, so
    /// both streams land in the same SIEM parser.
    Cef,
    /// The full event as JSON in the syslog message. Loses nothing; preferred
    /// when the SIEM can parse JSON, because CEF's fixed slots cannot carry
    /// every field the event has.
    Json,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SiemTransport {
    Udp,
    Tcp,
    Tls,
}

#[derive(Clone, Debug)]
pub struct SiemConfig {
    pub target: String,
    pub transport: SiemTransport,
    pub format: SiemFormat,
    pub ca_file: Option<String>,
    /// TLS server name. Defaults to the host part of `target`; override when
    /// connecting to an address whose certificate names something else.
    pub server_name: Option<String>,
    pub queue: usize,
    pub facility: u8,
    pub hostname: String,
}

impl SiemConfig {
    /// Read the feed configuration from the environment. Returns `None` when
    /// `SENTINEL_SIEM_TARGET` is unset — the feed is opt-in, and an unconfigured
    /// deployment must not spend a task or a queue on it.
    pub fn from_env() -> Option<Self> {
        let target = std::env::var("SENTINEL_SIEM_TARGET")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())?;

        let transport = match std::env::var("SENTINEL_SIEM_PROTOCOL")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "tls" | "tcp+tls" | "tcps" => SiemTransport::Tls,
            "udp" => SiemTransport::Udp,
            // TCP rather than UDP is the default on purpose: UDP silently
            // discards under loss and offers no delivery signal at all, which
            // for security data means an unknowable gap.
            _ => SiemTransport::Tcp,
        };
        let format = match std::env::var("SENTINEL_SIEM_FORMAT")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "json" => SiemFormat::Json,
            _ => SiemFormat::Cef,
        };

        let queue = std::env::var("SENTINEL_SIEM_QUEUE")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(10_000)
            .min(1_000_000);

        Some(Self {
            target,
            transport,
            format,
            ca_file: std::env::var("SENTINEL_SIEM_CA_FILE")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            server_name: std::env::var("SENTINEL_SIEM_SERVER_NAME")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            queue,
            facility: std::env::var("SENTINEL_SIEM_FACILITY")
                .ok()
                .and_then(|v| v.trim().parse::<u8>().ok())
                .filter(|f| *f <= 23)
                .unwrap_or(16), // local0
            hostname: std::env::var("SENTINEL_NODE_ID")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "sentinel".to_string()),
        })
    }
}

static SENT: AtomicU64 = AtomicU64::new(0);
static DROPPED: AtomicU64 = AtomicU64::new(0);
static CONNECT_FAILURES: AtomicU64 = AtomicU64::new(0);

pub fn sent_total() -> u64 {
    SENT.load(Ordering::Relaxed)
}
pub fn dropped_total() -> u64 {
    DROPPED.load(Ordering::Relaxed)
}
pub fn connect_failures_total() -> u64 {
    CONNECT_FAILURES.load(Ordering::Relaxed)
}

static SENDER: std::sync::OnceLock<tokio::sync::mpsc::Sender<String>> = std::sync::OnceLock::new();

/// Hand one already-formatted line to the forwarder. Never blocks; drops and
/// counts when the queue is full.
fn enqueue(line: String) {
    let Some(tx) = SENDER.get() else { return };
    if tx.try_send(line).is_err() {
        let n = DROPPED.fetch_add(1, Ordering::Relaxed) + 1;
        // Rate-limited so a dead SIEM under load cannot turn the drop path into
        // the overload. Powers of two give a loud first signal, then quiet.
        if n == 1 || n.is_power_of_two() {
            warn!(
                dropped_total = n,
                "SIEM feed queue full — events are NOT reaching the SIEM \
                 (they are still recorded in ClickHouse); see \
                 sentinel_siem_events_dropped_total"
            );
        }
    }
}

/// Format and enqueue one event.
///
/// Called from `record_event`, independently of the ClickHouse buffer: neither
/// sink gates the other, so a SIEM outage costs SIEM delivery only and a
/// ClickHouse-less deployment still feeds its SIEM.
pub fn record(cfg_format: SiemFormat, facility: u8, hostname: &str, row: &WafEventRow) {
    if SENDER.get().is_none() {
        return;
    }
    let msg = match cfg_format {
        SiemFormat::Cef => cef_line(row),
        SiemFormat::Json => json_line(row),
    };
    enqueue(syslog_frame(facility, hostname, row.ts, &msg));
}

/// RFC 5424 header + message. `ts` is the event's own unix second, not "now":
/// a queued event must not appear to have happened when it was finally sent.
fn syslog_frame(facility: u8, hostname: &str, ts: i64, msg: &str) -> String {
    // Severity 4 (warning) for the whole feed: these are security findings, and
    // per-event severity is carried inside CEF/JSON where a parser can use it.
    let pri = (facility as u16) * 8 + 4;
    let when = chrono::DateTime::from_timestamp(ts, 0)
        .unwrap_or_else(chrono::Utc::now)
        .format("%Y-%m-%dT%H:%M:%SZ");
    format!("<{pri}>1 {when} {hostname} sentinel-waf - - - {msg}")
}

fn cef_severity(sev: &str) -> u8 {
    match sev.to_ascii_uppercase().as_str() {
        "CRITICAL" => 10,
        "HIGH" => 8,
        "MEDIUM" => 6,
        "LOW" => 4,
        _ => 3,
    }
}

/// Escape a CEF *header* field: only `|` and `\` are special there.
fn cef_head(s: &str) -> String {
    s.replace('\\', "\\\\").replace('|', "\\|")
}

/// Escape a CEF *extension* value: `=` and `\` are special, and newlines would
/// break syslog framing.
fn cef_ext(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('=', "\\=")
        .replace(['\n', '\r'], " ")
}

fn cef_line(r: &WafEventRow) -> String {
    // Vendor/Product/Version match the control plane's alert CEF sender so both
    // streams parse with one SIEM rule.
    let mut out = format!(
        "CEF:0|Sentinel|WAF|1.0|{}|{}|{}|",
        cef_head(if r.rule.is_empty() { "event" } else { &r.rule }),
        cef_head(if r.attack.is_empty() {
            "WAF event"
        } else {
            &r.attack
        }),
        cef_severity(&r.severity),
    );
    // act carries BLOCK vs DETECT, which is the field that tells a SOC whether
    // the request was actually stopped — the alert path could not express it
    // because it only ever sent blocks.
    let pairs: [(&str, &str); 6] = [
        ("src", &r.ip),
        ("act", &r.action),
        ("requestMethod", &r.method),
        ("request", &r.path),
        ("externalId", &r.request_id),
        ("dhost", &r.site),
    ];
    for (k, v) in pairs {
        if !v.is_empty() {
            out.push_str(&format!("{k}={} ", cef_ext(v)));
        }
    }
    out.push_str(&format!("rt={} ", r.ts.saturating_mul(1000)));
    if r.status != 0 {
        out.push_str(&format!("outcome={} ", r.status));
    }
    // Custom slots, labelled so a parser can name them. `mode` is here because
    // a DETECT in learning mode and a DETECT that failed open look identical
    // without it.
    let cs: [(&str, &str, &str); 5] = [
        ("cs1", "mode", &r.mode),
        ("cs2", "query", &r.query),
        ("cs3", "matched", &r.matched),
        ("cs4", "target", &r.target),
        // The TLS fingerprint behind a JA4-driven bot verdict. cs5 of CEF's six
        // custom-string slots; cs6 stays free.
        ("cs5", "ja4", &r.ja4),
    ];
    for (slot, label, val) in cs {
        if !val.is_empty() {
            out.push_str(&format!("{slot}Label={label} {slot}={} ", cef_ext(val)));
        }
    }
    out.push_str(&format!("cn1Label=score cn1={} ", r.score));
    out.push_str(&format!("cn2Label=threshold cn2={}", r.threshold));
    out
}

fn json_line(r: &WafEventRow) -> String {
    // Serialised by hand rather than via serde on WafEventRow so the feed's
    // field names are a stable contract that a schema change cannot silently
    // rename under a customer's SIEM rules.
    serde_json::json!({
        "ts": r.ts,
        "site": r.site,
        "tenant": r.tenant,
        "src_ip": r.ip,
        "country": r.country,
        "method": r.method,
        "path": r.path,
        "query": r.query,
        "referer": r.referer,
        "rule": r.rule,
        "attack": r.attack,
        "matched": r.matched,
        "target": r.target,
        "action": r.action,
        "mode": r.mode,
        "severity": r.severity,
        "score": r.score,
        "threshold": r.threshold,
        "status": r.status,
        "protocol": r.protocol,
        "request_id": r.request_id,
        "explanation": r.explanation,
        "ja4": r.ja4,
    })
    .to_string()
}

/// Start the forwarder. Returns the configuration in use so the caller can pass
/// format/facility/hostname to `record` without re-reading the environment per
/// event.
pub fn start(cfg: SiemConfig) -> SiemConfig {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(cfg.queue);
    if SENDER.set(tx).is_err() {
        // Already started (a second listener, or a test). Nothing to do.
        return cfg;
    }
    info!(
        target_addr = %cfg.target,
        transport = ?cfg.transport,
        format = ?cfg.format,
        queue = cfg.queue,
        "SIEM event feed enabled — every block and learning-mode detection is forwarded"
    );

    let task_cfg = cfg.clone();
    tokio::spawn(async move {
        let mut backoff = Duration::from_millis(500);
        const MAX_BACKOFF: Duration = Duration::from_secs(30);

        loop {
            match Conn::connect(&task_cfg).await {
                Ok(mut conn) => {
                    backoff = Duration::from_millis(500);
                    info!(target_addr = %task_cfg.target, "SIEM feed connected");
                    // Drain until a write fails, then reconnect. Events that
                    // arrive while disconnected are dropped by `enqueue` once
                    // the queue fills — counted, never silent.
                    while let Some(line) = rx.recv().await {
                        if let Err(e) = conn.write_line(&line).await {
                            warn!(error = %e, "SIEM feed write failed — reconnecting");
                            break;
                        }
                        SENT.fetch_add(1, Ordering::Relaxed);
                    }
                    if rx.is_closed() {
                        return;
                    }
                }
                Err(e) => {
                    let n = CONNECT_FAILURES.fetch_add(1, Ordering::Relaxed) + 1;
                    if n == 1 || n.is_power_of_two() {
                        warn!(
                            error = %e,
                            failures = n,
                            target_addr = %task_cfg.target,
                            "SIEM feed cannot connect — events are recorded in ClickHouse \
                             but NOT forwarded"
                        );
                    }
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
        }
    });

    cfg
}

/// One live connection to the collector.
enum Conn {
    Udp(tokio::net::UdpSocket, String),
    Tcp(tokio::net::TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
}

impl Conn {
    async fn connect(cfg: &SiemConfig) -> anyhow::Result<Self> {
        match cfg.transport {
            SiemTransport::Udp => {
                let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
                Ok(Conn::Udp(sock, cfg.target.clone()))
            }
            SiemTransport::Tcp => {
                let s = tokio::time::timeout(
                    Duration::from_secs(10),
                    tokio::net::TcpStream::connect(&cfg.target),
                )
                .await??;
                Ok(Conn::Tcp(s))
            }
            SiemTransport::Tls => {
                let tcp = tokio::time::timeout(
                    Duration::from_secs(10),
                    tokio::net::TcpStream::connect(&cfg.target),
                )
                .await??;
                let connector = tls_connector(cfg)?;
                let host = cfg.server_name.clone().unwrap_or_else(|| {
                    cfg.target
                        .rsplit_once(':')
                        .map(|(h, _)| h.to_string())
                        .unwrap_or_else(|| cfg.target.clone())
                });
                let server_name = rustls::pki_types::ServerName::try_from(host)
                    .map_err(|_| anyhow::anyhow!("invalid TLS server name for SIEM target"))?;
                let s = connector.connect(server_name, tcp).await?;
                Ok(Conn::Tls(Box::new(s)))
            }
        }
    }

    async fn write_line(&mut self, line: &str) -> anyhow::Result<()> {
        match self {
            Conn::Udp(sock, target) => {
                sock.send_to(line.as_bytes(), target.as_str()).await?;
            }
            Conn::Tcp(s) => {
                s.write_all(octet_counted(line).as_bytes()).await?;
            }
            Conn::Tls(s) => {
                s.write_all(octet_counted(line).as_bytes()).await?;
            }
        }
        Ok(())
    }
}

/// RFC 6587 octet counting: `<length> <message>`.
///
/// Newline-delimited framing is the common alternative and is wrong here: a
/// message can legitimately contain a newline (a matched payload, a URL), and a
/// single stray one would split one event into two malformed ones. A length
/// prefix cannot be confused by content.
fn octet_counted(line: &str) -> String {
    format!("{} {}", line.len(), line)
}

fn tls_connector(cfg: &SiemConfig) -> anyhow::Result<tokio_rustls::TlsConnector> {
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();

    if let Some(path) = &cfg.ca_file {
        let pem = std::fs::read(path).map_err(|e| anyhow::anyhow!("SIEM CA file {path}: {e}"))?;
        let mut rd = std::io::BufReader::new(std::io::Cursor::new(pem));
        let mut added = 0usize;
        for cert in rustls_pemfile::certs(&mut rd) {
            roots.add(cert?)?;
            added += 1;
        }
        if added == 0 {
            // Fail rather than fall back to the public roots: a private
            // collector's certificate cannot be signed by them, so falling back
            // would turn a config error into a permanent, silent delivery
            // failure. Same rule as the ClickHouse CA loader.
            anyhow::bail!("SIEM CA file {path} contained no CERTIFICATE blocks");
        }
    } else {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(std::sync::Arc::new(
        config,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> WafEventRow {
        WafEventRow {
            ts: 1_787_000_000,
            ip: "203.0.113.9".into(),
            country: "IN".into(),
            site: "shop.example".into(),
            tenant: "t1".into(),
            method: "GET".into(),
            path: "/search".into(),
            query: "q=1' OR 1=1--".into(),
            referer: "https://shop.example/#/search".into(),
            matched: "1' OR 1=1--".into(),
            rule: "942100".into(),
            attack: "SQL Injection".into(),
            action: "DETECT".into(),
            severity: "CRITICAL".into(),
            score: 15,
            status: 200,
            protocol: "h1".into(),
            request_id: "abc-123".into(),
            target: "ARGS:q".into(),
            mode: "learning".into(),
            threshold: 10,
            explanation: "would have blocked".into(),
            ja4: "t13d1516h2_8daaf6152771_02713d6af862".into(),
        }
    }

    // The gap the alert path left: a learning-mode DETECT never reached a SIEM
    // at all, and a BLOCK arrived only as a throttled count.
    #[test]
    fn detect_events_carry_their_action_and_mode() {
        let cef = cef_line(&row());
        assert!(cef.contains("act=DETECT"), "action missing: {cef}");
        assert!(cef.contains("cs1Label=mode"), "mode label missing: {cef}");
        assert!(cef.contains("cs1=learning"), "mode value missing: {cef}");
        let js = json_line(&row());
        assert!(js.contains("\"action\":\"DETECT\""));
        assert!(js.contains("\"mode\":\"learning\""));
    }

    /// The fingerprint behind a JA4-driven bot verdict must reach the SIEM in
    /// BOTH formats — it is the field that lets a SOC answer "why was this client
    /// scored as sqlmap" without access to the WAF's own logs.
    #[test]
    fn both_formats_carry_the_ja4_fingerprint() {
        let r = row();
        let cef = cef_line(&r);
        assert!(
            cef.contains("cs5Label=ja4"),
            "CEF must label the slot: {cef}"
        );
        assert!(
            cef.contains("cs5=t13d1516h2_8daaf6152771_02713d6af862"),
            "CEF must carry the value: {cef}"
        );
        let json = json_line(&r);
        assert!(
            json.contains(r#""ja4":"t13d1516h2_8daaf6152771_02713d6af862""#),
            "JSON feed must carry ja4 under a stable key: {json}"
        );
        // And an absent fingerprint must not invent a slot.
        let mut bare = row();
        bare.ja4 = String::new();
        assert!(
            !cef_line(&bare).contains("cs5"),
            "no fingerprint, no cs5 slot"
        );
    }

    #[test]
    fn cef_carries_the_payload_for_triage() {
        let cef = cef_line(&row());
        assert!(cef.contains("cs2Label=query"), "{cef}");
        assert!(cef.contains("cs3Label=matched"), "{cef}");
        assert!(
            cef.contains("externalId=abc-123"),
            "support id missing: {cef}"
        );
    }

    // A payload is attacker-controlled and reaches a CEF parser. `=` and `\`
    // must be escaped or one event can be made to look like several fields.
    #[test]
    fn cef_escapes_attacker_controlled_values() {
        let mut r = row();
        r.matched = "a=b\\c".into();
        r.attack = "pipe|inject".into();
        let cef = cef_line(&r);
        assert!(cef.contains("a\\=b\\\\c"), "extension not escaped: {cef}");
        assert!(cef.contains("pipe\\|inject"), "header not escaped: {cef}");
    }

    // A newline in a value would otherwise terminate the record early.
    #[test]
    fn newlines_cannot_split_one_event_into_two() {
        let mut r = row();
        r.query = "a\nb\r\nc".into();
        let framed = syslog_frame(16, "node1", r.ts, &cef_line(&r));
        assert_eq!(
            framed.matches('\n').count(),
            0,
            "framed record must contain no newline: {framed}"
        );
    }

    // The frame must state the EVENT's time, not the send time: a queued event
    // that arrives late must not claim to have just happened.
    #[test]
    fn frame_uses_the_event_timestamp() {
        let framed = syslog_frame(16, "node1", 1_787_000_000, "msg");
        assert!(
            framed.contains("2026-"),
            "expected event year in frame: {framed}"
        );
        assert!(
            framed.starts_with("<132>1 "),
            "priority/version wrong: {framed}"
        );
    }

    #[test]
    fn octet_counting_prefixes_the_exact_byte_length() {
        let f = octet_counted("hello");
        assert_eq!(f, "5 hello");
        // Multi-byte content must be counted in BYTES, not chars, or the
        // collector will mis-frame the stream.
        let s = "héllo";
        assert_eq!(octet_counted(s), format!("{} {}", s.len(), s));
    }

    #[test]
    fn feed_is_opt_in() {
        // With no target configured there must be no queue and no task: an
        // unconfigured deployment should spend nothing on this.
        std::env::remove_var("SENTINEL_SIEM_TARGET");
        assert!(SiemConfig::from_env().is_none());
    }

    #[test]
    fn tcp_is_the_default_transport() {
        std::env::set_var("SENTINEL_SIEM_TARGET", "collector:6514");
        std::env::remove_var("SENTINEL_SIEM_PROTOCOL");
        let cfg = SiemConfig::from_env().expect("configured");
        // UDP silently discards under loss, which for security data is an
        // unknowable gap.
        assert_eq!(cfg.transport, SiemTransport::Tcp);
        std::env::remove_var("SENTINEL_SIEM_TARGET");
    }
}
