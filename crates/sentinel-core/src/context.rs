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
    /// Soft-deny: throttle / limit the client (a 429 by default) instead of a
    /// hard block. Set by weighted verdict fusion for suspicious-but-uncertain
    /// traffic whose fused score is in the limit band (below the block band).
    Limit,
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
    /// The text that actually matched (capped, control-chars stripped). Empty
    /// when the operator produced no capturable text (numeric comparisons,
    /// validators) — logging must render that as absent, never invent one.
    /// This is what lets an operator judge a false positive from the event
    /// alone instead of reproducing the request to learn what the rule saw.
    pub matched_value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Notice,
}

impl Severity {
    /// How serious this is, higher being worse.
    ///
    /// Deliberately an explicit method rather than a derived `Ord`. The variants
    /// are declared most-severe-first, so a derived ordering would make
    /// `Critical` the MINIMUM and hand anyone reaching for `max_by_key` a
    /// `Notice` — a footgun in exactly the code that has to pick the worst
    /// finding on a request.
    pub fn rank(&self) -> u8 {
        match self {
            Severity::Critical => 4,
            Severity::High => 3,
            Severity::Medium => 2,
            Severity::Low => 1,
            Severity::Notice => 0,
        }
    }
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
    /// Owning tenant of the matched site (for per-tenant telemetry scoping).
    pub tenant_id: Option<String>,
    /// ISO-3166-1 alpha-2 country code resolved by the GeoIP module, when known.
    pub geo_country: Option<String>,
    /// Enforcement mode of the matched site, stamped once at routing time.
    /// `None` for requests rejected before routing (connection-layer blocks such
    /// as anti-DDoS, IP reputation and threat intel).
    ///
    /// Logging needs this: without it a record cannot say whether a verdict was
    /// actually *enforced* or merely *observed* in learning mode, and that
    /// distinction is not recoverable from the other fields — a learning-mode
    /// downgrade and a genuine pass both end up as a non-Block decision.
    pub enforcement_mode: Option<crate::config::WafMode>,
    /// The matched site's anomaly-score threshold, stamped at routing time so a
    /// score-driven verdict can be reported as "score N of threshold M" rather
    /// than a bare number the reader has to go look up.
    pub anomaly_threshold: Option<u32>,
    /// `path_prefix` of the per-path override that produced the two fields above,
    /// when one matched. Recorded so an operator reading an event can tell that a
    /// non-default threshold or mode came from a path rule rather than wondering
    /// why this request was judged differently from the rest of the site.
    pub path_override: Option<String>,
    /// The matched site's block-page policy, stamped at routing time for the same
    /// reason as the two fields above: a block can be issued from call sites that
    /// have no site config in scope (connection-layer rejections such as
    /// anti-DDoS, IP reputation and threat intel all fire before routing). `None`
    /// means "no site matched, or the site customised nothing" and renders the
    /// built-in default page.
    pub block_page: Option<crate::config::BlockPageConfig>,
    /// Whether the client asked for HTML, decided once at Phase 0.
    ///
    /// Stamped this early because the connection-layer rejections (anti-DDoS, IP
    /// reputation, threat intel) all answer BEFORE `request_headers` is
    /// populated — that happens only after `into_parts()`, downstream of a Host
    /// synthesis step that site matching depends on and so cannot be hoisted.
    /// Reading the header map at block time therefore saw it empty and served
    /// JSON to browsers, which is precisely the audience a threat-intel block
    /// hits. A bool costs one header lookup instead of a second HeaderMap clone
    /// on every request.
    pub client_accepts_html: bool,

    // --- WAF state ---
    pub phase: Phase,
    pub anomaly_score: u32,
    /// Per-engine anomaly contributions (engine name → points), recorded
    /// alongside `anomaly_score` so weighted verdict fusion can apply per-engine
    /// weights and explain which engines drove the verdict.
    pub engine_scores: HashMap<String, u32>,
    pub rule_matches: Vec<RuleMatch>,
    /// Per-model ML classifier scores (model name → [0.0, 1.0]).
    pub ml_scores: HashMap<String, f32>,
    /// Transaction variables for rule chaining (e.g. TX:anomaly_score_pl1).
    pub tx_vars: HashMap<String, String>,
    pub decision: WafDecision,
    /// Human-readable reason for a Block/Challenge decision.
    pub block_reason: Option<String>,
    /// HTTP status for the block response when it should not be 403 — a rate
    /// limit answers 429 so an API client can tell a throttle from a policy block.
    pub block_status: Option<u16>,
    /// Set when the request could not be served at all — origin refused, no site
    /// matched, body unreadable — i.e. the paths that answer 502.
    ///
    /// Explicit rather than reusing `block_reason`, because a gateway failure is
    /// NOT a WAF decision: `classify_nonrule_block` would try to turn it into a
    /// rule/attack label and the dashboard's attack breakdown would gain a
    /// category for "the origin is down", which is an availability event, not an
    /// attack.
    ///
    /// Exists because these requests used to produce no log record whatsoever
    /// while `inc_requests()` still counted them.
    pub gateway_error: Option<String>,
    /// True when the WAF *would* have blocked/challenged this request but the
    /// site is in Learning mode, so the decision was downgraded to Log. Drives
    /// the learning report (would-have-blocked aggregation) without affecting
    /// traffic. The reason that triggered it is retained in `block_reason`.
    pub would_block: bool,
    /// True when this request matched the hot threat-intelligence feed at a
    /// *watch* tier (high-confidence block-tier IOCs are rejected before ML
    /// runs). The ML feature extractor turns this into a strong anomaly signal
    /// so the classifier learns to treat feed-matched traffic as malicious.
    pub threat_intel_hit: bool,

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

    /// `Set-Cookie` values to attach to the eventual origin response. Used when a
    /// Proof-of-Work grant is consumed in-line (e.g. a challenged POST that must
    /// reach origin with its body intact) instead of via a 302 redirect.
    pub pending_set_cookies: Vec<String>,
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
            tenant_id: None,
            geo_country: None,
            enforcement_mode: None,
            anomaly_threshold: None,
            path_override: None,
            block_page: None,
            client_accepts_html: false,
            phase: Phase::Connection,
            anomaly_score: 0,
            engine_scores: HashMap::new(),
            rule_matches: Vec::new(),
            ml_scores: HashMap::new(),
            tx_vars: HashMap::new(),
            decision: WafDecision::Allow,
            block_reason: None,
            block_status: None,
            gateway_error: None,
            would_block: false,
            threat_intel_hit: false,
            upstream_addr: None,
            upstream_latency_us: None,
            response_status: None,
            response_headers: None,
            response_body: None,
            bytes_sent: 0,
            bytes_received: 0,
            pending_set_cookies: Vec::new(),
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

    /// Add `points` to the total anomaly score and attribute them to `engine`
    /// (for weighted verdict fusion + explainability). Use this instead of
    /// mutating `anomaly_score` directly so the per-engine breakdown stays
    /// accurate.
    pub fn add_engine_score(&mut self, engine: &str, points: u32) {
        if points == 0 {
            return;
        }
        self.anomaly_score = self.anomaly_score.saturating_add(points);
        *self.engine_scores.entry(engine.to_string()).or_insert(0) += points;
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

    /// The match that best explains why this request was flagged: highest
    /// severity, then highest score, and the EARLIEST of equals.
    ///
    /// Every record of a request — the ClickHouse event row, the NDJSON line,
    /// and the operator-facing prose — names one rule, one severity and one
    /// target. They used to take `rule_matches.first()`, but matches are
    /// appended in phase order, so the first is simply whichever rule ran
    /// earliest, not the one that matters. A header-phase rule therefore masked
    /// every later finding and donated its own, usually lower, severity to the
    /// record.
    ///
    /// Measured on the live demo node: 46% of 80,153 stored events were
    /// attributed to a MEDIUM "Host header is a numeric IP address" while
    /// carrying scores up to 61, i.e. several further rules had matched and none
    /// of them was named. The same request sent with an ordinary Host header was
    /// recorded correctly as CRITICAL SQL injection, which is what made the
    /// ordering the culprit rather than the detection.
    ///
    /// Ties keep the earliest match, so a request whose findings are genuinely
    /// equal still reports them in the order they were detected.
    pub fn primary_rule_match(&self) -> Option<&RuleMatch> {
        self.rule_matches.iter().reduce(|best, m| {
            if (m.severity.rank(), m.score) > (best.severity.rank(), best.score) {
                m
            } else {
                best
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Build a match with just the fields the selection looks at.
    fn m(rule_id: &str, severity: Severity, score: u32) -> RuleMatch {
        RuleMatch {
            rule_id: rule_id.to_string(),
            message: format!("finding {rule_id}"),
            severity,
            score,
            target: String::new(),
            phase: Phase::RequestHeaders,
            matched_value: String::new(),
        }
    }

    #[test]
    fn severity_rank_orders_critical_above_notice() {
        assert!(Severity::Critical.rank() > Severity::High.rank());
        assert!(Severity::High.rank() > Severity::Medium.rank());
        assert!(Severity::Medium.rank() > Severity::Low.rank());
        assert!(Severity::Low.rank() > Severity::Notice.rank());
    }

    /// The regression this exists for. A header-phase rule is appended first, so
    /// `first()` named the protocol nit and reported it as MEDIUM while the SQL
    /// injection that actually mattered went unnamed on the record.
    #[test]
    fn primary_match_is_the_worst_finding_not_the_earliest() {
        let mut ctx = RequestContext::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
        ctx.rule_matches.push(m("920350", Severity::Medium, 3));
        ctx.rule_matches.push(m("942100", Severity::Critical, 5));
        ctx.rule_matches.push(m("920330", Severity::Notice, 2));

        let top = ctx.primary_rule_match().expect("a match");
        assert_eq!(top.rule_id, "942100");
        assert_eq!(top.severity, Severity::Critical);
    }

    /// Within one severity the higher score wins, so "worst" stays meaningful
    /// when every finding is critical.
    #[test]
    fn primary_match_breaks_severity_ties_on_score() {
        let mut ctx = RequestContext::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
        ctx.rule_matches.push(m("941100", Severity::Critical, 5));
        ctx.rule_matches.push(m("942190", Severity::Critical, 9));

        assert_eq!(ctx.primary_rule_match().unwrap().rule_id, "942190");
    }

    /// Fully equal findings keep detection order, so the record stays stable
    /// rather than depending on which way the comparison happened to fall.
    #[test]
    fn primary_match_keeps_the_earliest_of_equals() {
        let mut ctx = RequestContext::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
        ctx.rule_matches.push(m("first", Severity::High, 4));
        ctx.rule_matches.push(m("second", Severity::High, 4));

        assert_eq!(ctx.primary_rule_match().unwrap().rule_id, "first");
    }

    #[test]
    fn primary_match_is_none_without_matches() {
        let ctx = RequestContext::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
        assert!(ctx.primary_rule_match().is_none());
    }

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
            matched_value: "' OR 1=1--".to_string(),
        });
        ctx.add_finding(RuleMatch {
            rule_id: "941100".to_string(),
            message: "XSS".to_string(),
            severity: Severity::High,
            score: 3,
            target: "ARGS:q".to_string(),
            phase: Phase::RequestHeaders,
            matched_value: String::new(),
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
