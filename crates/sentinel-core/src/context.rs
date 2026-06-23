use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode, Uri, Version};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// WAF phases (0-6, matching AGENTS.md lifecycle)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(u8)]
pub enum Phase {
    #[default]
    Connection = 0,
    RequestHeaders = 1,
    RequestBody = 2,
    Upstream = 3,
    ResponseHeaders = 4,
    ResponseBody = 5,
    Logging = 6,
}

impl std::fmt::Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Phase::Connection => "connection",
            Phase::RequestHeaders => "request_headers",
            Phase::RequestBody => "request_body",
            Phase::Upstream => "upstream",
            Phase::ResponseHeaders => "response_headers",
            Phase::ResponseBody => "response_body",
            Phase::Logging => "logging",
        };
        f.write_str(name)
    }
}

// ---------------------------------------------------------------------------
// WAF decision
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum WafDecision {
    /// Request passes all checks — forward to upstream.
    #[default]
    Allow,
    /// Block request with an error response; do not forward.
    Block,
    /// Issue a browser challenge (CAPTCHA / PoW) before forwarding.
    Challenge,
    /// Allow but log (learning mode).
    Log,
}

// ---------------------------------------------------------------------------
// Rule match detail
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub rule_id: String,
    pub message: String,
    pub severity: Severity,
    pub score: u32,
    /// Which part of the request triggered the match (e.g. `"ARGS:id"`).
    pub target: String,
    pub phase: Phase,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Notice,
}

// ---------------------------------------------------------------------------
// Request context — lives for the duration of a single request
// ---------------------------------------------------------------------------

/// Per-request state threaded through the entire WAF phase pipeline.
///
/// Created at Phase 0 (connection), enriched through each phase, and
/// consumed by Phase 6 (logging).
#[derive(Debug)]
pub struct RequestContext {
    // --- Identity ---
    pub request_id: Uuid,
    pub start: Instant,

    // --- Connection layer ---
    pub client_ip: IpAddr,
    pub client_port: u16,
    /// JA4 TLS fingerprint (set during Phase 0 TLS handshake).
    pub tls_fingerprint: Option<String>,

    // --- HTTP request ---
    pub http_version: Version,
    pub method: Method,
    pub uri: Uri,
    pub request_headers: HeaderMap,
    /// Body is `None` until it has been read (Phase 2).  For streaming
    /// requests, this may be buffered or stay `None` if the policy says
    /// pass-through.
    pub request_body: Option<Bytes>,

    // --- Site routing ---
    /// Which site config matched (by Host header / SNI).
    pub site_id: Option<String>,

    // --- WAF state ---
    pub phase: Phase,
    pub anomaly_score: u32,
    pub rule_matches: Vec<RuleMatch>,
    /// Per-model ML classifier scores (model name → [0.0, 1.0]).
    pub ml_scores: HashMap<String, f32>,
    /// Transaction variables for rule chaining (e.g. TX:anomaly_score_pl1).
    pub tx_vars: HashMap<String, String>,
    pub decision: WafDecision,
    /// Human-readable reason for a Block/Challenge decision.
    pub block_reason: Option<String>,

    // --- Upstream / response ---
    pub upstream_addr: Option<std::net::SocketAddr>,
    /// Round-trip time to upstream in microseconds.
    pub upstream_latency_us: Option<u64>,
    pub response_status: Option<StatusCode>,
    pub response_headers: Option<HeaderMap>,
    /// Response body, buffered in Phase 5 for response-body rule inspection
    /// (e.g. CRS RESPONSE-* data-leakage rules) and DLP scanning.  `None` until
    /// collected; stays `None` for streaming / oversized / non-text responses.
    pub response_body: Option<Bytes>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl RequestContext {
    /// Create a fresh context at the moment of connection.
    pub fn new(client_ip: IpAddr, client_port: u16) -> Self {
        Self {
            request_id: Uuid::new_v4(),
            start: Instant::now(),
            client_ip,
            client_port,
            tls_fingerprint: None,
            http_version: Version::HTTP_11,
            method: Method::GET,
            uri: Uri::from_static("/"),
            request_headers: HeaderMap::new(),
            request_body: None,
            site_id: None,
            phase: Phase::Connection,
            anomaly_score: 0,
            rule_matches: Vec::new(),
            ml_scores: HashMap::new(),
            tx_vars: HashMap::new(),
            decision: WafDecision::Allow,
            block_reason: None,
            upstream_addr: None,
            upstream_latency_us: None,
            response_status: None,
            response_headers: None,
            response_body: None,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    /// Advance to the next phase.
    pub fn advance_phase(&mut self, phase: Phase) {
        self.phase = phase;
    }

    /// Add an anomaly score and optionally a rule match.
    pub fn add_finding(&mut self, rule_match: RuleMatch) {
        self.anomaly_score = self.anomaly_score.saturating_add(rule_match.score);
        self.rule_matches.push(rule_match);
    }

    /// Check if this request should be blocked given the configured threshold.
    pub fn exceeds_threshold(&self, threshold: u32) -> bool {
        self.anomaly_score >= threshold
    }

    /// Elapsed time since the connection was received, in milliseconds.
    pub fn elapsed_ms(&self) -> f64 {
        self.start.elapsed().as_secs_f64() * 1000.0
    }

    /// Extract the `Host` header value, or `None` if missing/invalid.
    pub fn host(&self) -> Option<&str> {
        self.request_headers
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(|h| h.split(':').next().unwrap_or(h))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn new_context_defaults() {
        let ctx = RequestContext::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
        assert_eq!(ctx.phase, Phase::Connection);
        assert_eq!(ctx.decision, WafDecision::Allow);
        assert_eq!(ctx.anomaly_score, 0);
    }

    #[test]
    fn add_finding_accumulates_score() {
        let mut ctx = RequestContext::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234);
        ctx.add_finding(RuleMatch {
            rule_id: "942100".to_string(),
            message: "SQL injection".to_string(),
            severity: Severity::Critical,
            score: 5,
            target: "ARGS:id".to_string(),
            phase: Phase::RequestBody,
        });
        ctx.add_finding(RuleMatch {
            rule_id: "941100".to_string(),
            message: "XSS".to_string(),
            severity: Severity::High,
            score: 3,
            target: "ARGS:q".to_string(),
            phase: Phase::RequestHeaders,
        });
        assert_eq!(ctx.anomaly_score, 8);
        assert!(ctx.exceeds_threshold(5));
        assert!(!ctx.exceeds_threshold(10));
    }

    #[test]
    fn phase_ordering() {
        assert!(Phase::Connection < Phase::RequestHeaders);
        assert!(Phase::RequestHeaders < Phase::Upstream);
        assert!(Phase::Upstream < Phase::Logging);
    }
}
