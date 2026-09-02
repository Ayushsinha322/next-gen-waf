//! Bot detection module — User-Agent classification and JA4 fingerprint matching.
//!
//! Checked at Phase 1 (request headers).  The detector classifies each request
//! into one of several bot categories so the proxy can block attack tools,
//! challenge suspicious bots, or pass verified search-engine crawlers.
//!
//! ## Classification order (highest priority first)
//! 1. JA4 TLS fingerprint — fingerprint cannot be spoofed by changing the UA.
//! 2. Known-attacker User-Agent patterns (sqlmap, nikto, etc.).
//! 3. Known-good bot User-Agent patterns (Googlebot, Bingbot, etc.).
//! 4. Generic "bot-like" UA fragments (contains "bot", "spider", "crawler"…).
//! 5. Empty or whitespace-only User-Agent.
//! 6. Looks human.

use std::collections::HashMap;

use once_cell::sync::Lazy;
use regex::Regex;
use tracing::info;

// ---------------------------------------------------------------------------
// Static pattern tables
// ---------------------------------------------------------------------------

/// `(regex_pattern, display_name)` pairs for known-good crawlers.
static GOOD_BOT_PATTERNS: &[(&str, &str)] = &[
    (r"(?i)\bgooglebot\b", "Googlebot"),
    (r"(?i)\bbingbot\b|\bmsnbot\b", "Bingbot"),
    (r"(?i)\bduckduckbot\b", "DuckDuckBot"),
    (r"(?i)\bslurp\b", "Yahoo Slurp"),
    (r"(?i)\bbaiduspider\b", "Baiduspider"),
    (r"(?i)\byandexbot\b", "YandexBot"),
    (r"(?i)\bfacebot\b|\bfacebookexternalhit\b", "FacebookBot"),
    (r"(?i)\btwitterbot\b", "Twitterbot"),
    (r"(?i)\blinkedinbot\b", "LinkedInBot"),
    (r"(?i)\bapplebot\b", "Applebot"),
    (r"(?i)\bsemrushbot\b", "SEMrushBot"),
    (r"(?i)\bahrefsbot\b", "AhrefsBot"),
    (r"(?i)\bpetalbot\b", "PetalBot"),
    (r"(?i)\bcoccocbot\b", "CocCocBot"),
];

/// `(regex_pattern, display_name)` pairs for known attack / scanner tools.
/// Any match → `BotVerdict::KnownAttacker`.
static ATTACKER_PATTERNS: &[(&str, &str)] = &[
    (r"(?i)\bsqlmap\b", "sqlmap"),
    (r"(?i)\bnikto\b", "Nikto"),
    (r"(?i)\bnmap\b", "Nmap"),
    (r"(?i)\bmasscan\b", "Masscan"),
    (r"(?i)\bzgrab\b", "ZGrab"),
    (
        r"(?i)\bdirbuster\b|\bgobuster\b|\bffuf\b|\bwfuzz\b|\bferoxbuster\b",
        "DirBruter",
    ),
    (r"(?i)\bzaproxy\b|\bZAP/\b", "OWASP ZAP"),
    (r"(?i)\bbsqlbf\b", "BSQL Brute Force"),
    (r"(?i)\bhavij\b", "Havij"),
    (r"(?i)\bacunetix\b", "Acunetix"),
    (r"(?i)\bnetsparker\b", "Netsparker"),
    (r"(?i)\bw3af\b", "W3AF"),
    (r"(?i)\bmetasploit\b", "Metasploit"),
    (r"(?i)\bcewl\b/", "CeWL"),
    (r"(?i)\bjbrofuzz\b", "JBroFuzz"),
    (r"(?i)\bslowloris\b", "Slowloris"),
    (r"(?i)\bpausescanner\b|\bparos\b", "Paros Proxy"),
    (r"(?i)\bvega\b/\d", "Vega Scanner"),
    // Headless browsers used by automation / scrapers (context-dependent)
    (r"(?i)headlesschrome|phantomjs|slimerjs", "Headless Browser"),
    // Common pentest frameworks
    (r"(?i)\bburp\b|burpsuite", "Burp Suite"),
];

/// Known-malicious JA4 fingerprints: `fingerprint → tool_name`.
///
/// These are for demonstration; a production deployment should load a full
/// threat-intelligence feed.  JA4 hashes are stable across tool versions
/// unless the tool's TLS config changes.
static MALICIOUS_JA4_TABLE: &[(&str, &str)] = &[
    // sqlmap default Python TLS stack (CPython 3.x + ssl module defaults)
    ("t13d1715h2_4b8e96bdf8c2_0c5ec3ea4b74", "sqlmap"),
    // Metasploit Ruby net-http default
    ("t13d191000_9dc949149365_97f8aa674fd9", "Metasploit"),
    // Nmap ssl-scan probe
    ("t13d480900_b3e5b4268c47_e0e5af456ef0", "Nmap-ssl"),
    // zgrab2 default
    ("t13d880900_c6e2b4e5e9f3_5c7d3a1b0e4f", "zgrab2"),
    // curl with default TLS (not blocked by default but flagged)
    // — not included here; curl is a legitimate dev tool
];

// ---------------------------------------------------------------------------
// Pre-compiled pattern sets (compiled once at first use)
// ---------------------------------------------------------------------------

struct CompiledPatterns {
    good_bots: Vec<(Regex, String)>,
    attackers: Vec<(Regex, String)>,
}

/// Compile one table, reporting any pattern that does not build.
///
/// `error!` and not `warn!`: these patterns are compiled into the shipped
/// binary, so a failure here is not something an operator can fix from config —
/// it is a defect in the build, and the consequence is that the named tool's
/// signature is simply not detected while the module reports itself as working.
/// That is the same test the geoip module applies when choosing ERROR over WARN.
///
/// `filter_map(...ok())` silently dropped these, and because `PATTERNS` is a
/// `Lazy` forced by the FIRST REQUEST rather than at construction, even a log
/// line here would previously have been emitted mid-traffic (or, under a target
/// filter that excluded this crate, never).
fn compile_table(table: &[(&str, &str)], kind: &'static str) -> Vec<(Regex, String)> {
    table
        .iter()
        .filter_map(|(pat, name)| match Regex::new(pat) {
            Ok(re) => Some((re, name.to_string())),
            Err(e) => {
                tracing::error!(
                    kind,
                    name = %name,
                    pattern = %pat,
                    error = %e,
                    "bot_detect: BUILT-IN pattern failed to compile — this signature IS NOT \
                     DETECTED and cannot be fixed from configuration; it is a defect in the \
                     shipped binary. Counts are queryable at /healthz -> modules.bot."
                );
                None
            }
        })
        .collect()
}

static PATTERNS: Lazy<CompiledPatterns> = Lazy::new(|| CompiledPatterns {
    good_bots: compile_table(GOOD_BOT_PATTERNS, "good_bot"),
    attackers: compile_table(ATTACKER_PATTERNS, "attacker"),
});

impl CompiledPatterns {
    /// Return the display name of the first matching known-attacker pattern.
    fn match_attacker(&self, user_agent: &str) -> Option<String> {
        self.attackers
            .iter()
            .find(|(re, _)| re.is_match(user_agent))
            .map(|(_, name)| name.clone())
    }

    /// Return the display name of the first matching known-good bot pattern.
    fn match_good_bot(&self, user_agent: &str) -> Option<String> {
        self.good_bots
            .iter()
            .find(|(re, _)| re.is_match(user_agent))
            .map(|(_, name)| name.clone())
    }
}

/// Generic "bot-like" lexical hints in a User-Agent string.
///
/// Shared by [`BotDetector::classify`] and [`BotDetector::score`] so the
/// substring list lives in exactly one place.
fn is_botlike_ua(user_agent: &str) -> bool {
    let ua_lower = user_agent.to_ascii_lowercase();
    ua_lower.contains("bot")
        || ua_lower.contains("spider")
        || ua_lower.contains("crawler")
        || ua_lower.contains("scraper")
        || ua_lower.contains("fetcher")
        || ua_lower.contains("scanner")
        || ua_lower.contains("wget")
        || ua_lower.contains("libwww")
        || ua_lower.contains("python-urllib")
        || ua_lower.contains("java/")
        || ua_lower.contains("go-http-client")
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Classification result for a single request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BotVerdict {
    /// Looks like a real browser.
    Human,
    /// Verified search-engine crawler — allow and optionally serve a special
    /// response (e.g. pre-rendered HTML).
    GoodBot(String),
    /// Vulnerability scanner — block or add anomaly score.
    KnownAttacker(String),
    /// UA matches a bot pattern but is not a known-good crawler — flag / score.
    SuspiciousBot,
    /// Request requires a browser challenge (CAPTCHA / PoW) before forwarding.
    Challenge,
}

// ---------------------------------------------------------------------------
// Weighted bot score (issue #8)
// ---------------------------------------------------------------------------

/// Per-request signals fed into the weighted [`BotDetector::score`] model.
///
/// The struct borrows its string fields so the caller can build it cheaply
/// from the parsed request headers without allocating.
pub struct BotSignals<'a> {
    /// Value of the `User-Agent` header (may be empty).
    pub user_agent: &'a str,
    /// JA4 TLS fingerprint captured during the handshake, if available.
    pub ja4: Option<&'a str>,
    /// Whether the request carried an `Accept` header.
    pub has_accept: bool,
    /// Whether the request carried an `Accept-Language` header (browsers always
    /// send it; most bots do not).
    pub has_accept_language: bool,
    /// Correlation-engine repeat-offender bonus (expected 0 / 3 / 8).
    pub recent_block_score: u32,
}

/// Enforcement tier derived from the weighted bot score.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BotTier {
    /// Forward the request untouched.
    Allow,
    /// Serve a transparent JavaScript proof-of-work challenge.
    JsChallenge,
    /// Serve an interactive CAPTCHA challenge.
    Captcha,
    /// Hard-block the request.
    Block,
}

/// Result of the weighted bot-scoring model.
///
/// `score` is a saturating 0–100 value; `tier` is derived from it. `reasons`
/// holds one short string per signal that fired, for logging / audit.
pub struct BotScore {
    /// Weighted bot score, capped at 100.
    pub score: u8,
    /// Enforcement tier derived from `score`.
    pub tier: BotTier,
    /// True only for a good-bot whose claim has been positively verified
    /// (e.g. via reverse DNS). Currently always false — see [`BotDetector::score`].
    pub verified_good_bot: bool,
    /// One short reason string per signal that contributed.
    pub reasons: Vec<String>,
}

/// Map a saturated 0–100 bot score to its enforcement tier.
///
/// Thresholds (inclusive lower bounds): ≥ 70 → `Block`, 40–69 → `Captcha`,
/// 25–39 → `JsChallenge`, else `Allow`.
fn tier_for_score(score: u8) -> BotTier {
    if score >= 70 {
        BotTier::Block
    } else if score >= 40 {
        BotTier::Captcha
    } else if score >= 25 {
        BotTier::JsChallenge
    } else {
        BotTier::Allow
    }
}

// ---------------------------------------------------------------------------
// BotDetector
// ---------------------------------------------------------------------------

/// Stateless classifier — cheap to clone, heavy initialisation only happens
/// once via the `Lazy` static.  A new `BotDetector` can be built on each
/// config reload because all data is either static or comes from config.
pub struct BotDetector {
    /// JA4 fingerprint → attack tool name (loaded from config / feeds).
    malicious_ja4: HashMap<String, String>,
}

impl Default for BotDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl BotDetector {
    /// Build a detector with the built-in static JA4 table.
    pub fn new() -> Self {
        let malicious_ja4: std::collections::HashMap<String, String> = MALICIOUS_JA4_TABLE
            .iter()
            .map(|(fp, name)| (fp.to_string(), name.to_string()))
            .collect();
        // Force the pattern tables HERE rather than leaving them to the first
        // request. Without this, `compile_table`'s error! for a built-in pattern
        // that does not build would be emitted mid-traffic — or never, if the
        // very first request arrived before a subscriber was installed. A defect
        // in the shipped binary should be visible at boot.
        Lazy::force(&PATTERNS);
        info!(
            malicious_ja4 = malicious_ja4.len(),
            attacker_patterns = PATTERNS.attackers.len(),
            good_bot_patterns = PATTERNS.good_bots.len(),
            "bot detection initialised"
        );
        Self { malicious_ja4 }
    }

    /// How many JA4 fingerprints this detector will match against.
    ///
    /// Exposed because the number is smaller than the feature suggests: it is a
    /// static built-in table, `add_malicious_ja4` is the only way to extend it,
    /// and the proxy re-creates the detector with `new()` on every config
    /// reload — so anything added at runtime is discarded. A JA4-based block
    /// list that is quietly this small is worth being able to read.
    pub fn ja4_fingerprint_count(&self) -> usize {
        self.malicious_ja4.len()
    }

    /// Attacker UA signatures that actually compiled. A shortfall against
    /// `ATTACKER_PATTERNS.len()` means a built-in signature is not detected.
    pub fn attacker_pattern_count(&self) -> usize {
        PATTERNS.attackers.len()
    }

    /// Good-bot UA patterns that actually compiled. Note these are an
    /// UNAUTHENTICATED allowlist — see `score`.
    pub fn good_bot_pattern_count(&self) -> usize {
        PATTERNS.good_bots.len()
    }

    /// Add an extra JA4 fingerprint to block (e.g. from a threat-intel feed).
    pub fn add_malicious_ja4(&mut self, fingerprint: impl Into<String>, tool: impl Into<String>) {
        self.malicious_ja4.insert(fingerprint.into(), tool.into());
    }

    /// Classify a request.
    ///
    /// `user_agent` — value of the `User-Agent` header (may be empty).
    /// `ja4` — JA4 TLS fingerprint captured during the TLS handshake (Phase 0).
    pub fn classify(&self, user_agent: &str, ja4: Option<&str>) -> BotVerdict {
        // Ensure patterns are initialised (one-time cost).
        let patterns = &*PATTERNS;

        // 1. JA4 fingerprint check — takes priority over UA because it cannot
        //    be spoofed by changing the User-Agent header.
        if let Some(fp) = ja4 {
            if let Some(tool) = self.malicious_ja4.get(fp) {
                return BotVerdict::KnownAttacker(format!("{tool} [ja4:{fp}]"));
            }
        }

        // 2. Known attack tools (UA-based).
        if let Some(name) = patterns.match_attacker(user_agent) {
            return BotVerdict::KnownAttacker(name);
        }

        // 3. Known-good search crawlers.
        if let Some(name) = patterns.match_good_bot(user_agent) {
            return BotVerdict::GoodBot(name);
        }

        // 4. Empty or whitespace-only UA — almost certainly a bot or scanner.
        if user_agent.trim().is_empty() {
            return BotVerdict::SuspiciousBot;
        }

        // 5. Generic bot-like lexical hints in the UA string.
        if is_botlike_ua(user_agent) {
            return BotVerdict::SuspiciousBot;
        }

        BotVerdict::Human
    }

    /// Weighted 0–100 bot score with an enforcement tier (issue #8).
    ///
    /// Unlike [`classify`](Self::classify) — which returns a single categorical
    /// verdict — this combines several independent signals additively so a
    /// borderline request accumulates evidence before being challenged. The
    /// score saturates at 100 and each contributing signal pushes a short
    /// reason string.
    ///
    /// Signals and weights:
    /// * good-bot UA **with a non-malicious JA4** → early return, score 0,
    ///   tier `Allow` (unverified). A good-bot UA riding a *malicious* JA4 does
    ///   NOT short-circuit and instead falls through to full scoring below;
    /// * malicious JA4 → +45;
    /// * known-attacker UA → +40, else empty UA → +30, else bot-like UA → +20;
    /// * missing both `Accept` and `Accept-Language` → +20, else missing
    ///   `Accept-Language` only → +8;
    /// * repeat offender (`recent_block_score` ≥ 8 → +20, ≥ 3 → +10).
    ///
    /// Tier thresholds: ≥ 70 `Block`, 40–69 `Captcha`, 25–39 `JsChallenge`,
    /// else `Allow`.
    pub fn score(&self, sig: &BotSignals) -> BotScore {
        let patterns = &*PATTERNS;

        // A malicious JA4 fingerprint cannot be spoofed by the UA, so resolve
        // it up front — it must override any good-bot UA claim (this mirrors
        // the JA4-first precedence in `classify`). Looked up once, reused below.
        let bad_ja4_tool: Option<&String> = sig.ja4.and_then(|fp| self.malicious_ja4.get(fp));

        // Good-bot UA is allowed outright — but ONLY when its TLS fingerprint
        // is not on the malicious list. A spoofed "Googlebot" UA riding a
        // known-bad JA4 (e.g. sqlmap's TLS stack) must NOT short-circuit here;
        // it falls through to full scoring. `verified_good_bot` stays false
        // because we have not yet confirmed the claim.
        //
        // TODO(issue #8 follow-up): reverse-DNS verify the good-bot claim
        // (PTR + forward-confirmed A/AAAA) before trusting it, and set
        // `verified_good_bot: true` only on success.
        if bad_ja4_tool.is_none() && patterns.match_good_bot(sig.user_agent).is_some() {
            return BotScore {
                score: 0,
                tier: BotTier::Allow,
                verified_good_bot: false,
                reasons: vec!["good-bot-ua (unverified)".to_string()],
            };
        }

        let mut score: u32 = 0;
        let mut reasons: Vec<String> = Vec::new();

        // Malicious JA4 fingerprint (additive; cannot be spoofed via the UA).
        if let Some(tool) = bad_ja4_tool {
            score += 45;
            reasons.push(format!("ja4-bad:{tool}"));
        }

        // UA classification — mutually exclusive categories, highest first.
        if let Some(name) = patterns.match_attacker(sig.user_agent) {
            score += 40;
            reasons.push(format!("attacker-ua:{name}"));
        } else if sig.user_agent.trim().is_empty() {
            score += 30;
            reasons.push("empty-ua".to_string());
        } else if is_botlike_ua(sig.user_agent) {
            score += 20;
            reasons.push("botlike-ua".to_string());
        }

        // Browser-header heuristics.
        if !sig.has_accept && !sig.has_accept_language {
            score += 20;
            reasons.push("no-browser-headers".to_string());
        } else if !sig.has_accept_language {
            score += 8;
            reasons.push("no-accept-language".to_string());
        }

        // Correlation-engine repeat-offender bonus.
        if sig.recent_block_score >= 8 {
            score += 20;
            reasons.push("repeat-offender".to_string());
        } else if sig.recent_block_score >= 3 {
            score += 10;
            reasons.push("repeat-offender".to_string());
        }

        let score = score.min(100) as u8;
        let tier = tier_for_score(score);

        BotScore {
            score,
            tier,
            verified_good_bot: false,
            reasons,
        }
    }

    /// Convenience: should this verdict result in a hard block?
    ///
    /// `block_scanners` — if true, known vulnerability scanners are blocked
    /// (recommended in production).
    pub fn is_blocked(&self, verdict: &BotVerdict, block_scanners: bool) -> bool {
        match verdict {
            BotVerdict::KnownAttacker(_) => true,
            BotVerdict::SuspiciousBot if block_scanners => false, // challenge, not block
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn det() -> BotDetector {
        BotDetector::new()
    }

    #[test]
    fn real_browser_is_human() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                  (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
        assert_eq!(det().classify(ua, None), BotVerdict::Human);
    }

    #[test]
    fn sqlmap_blocked() {
        let ua = "sqlmap/1.8.3#stable (https://sqlmap.org)";
        assert!(matches!(
            det().classify(ua, None),
            BotVerdict::KnownAttacker(_)
        ));
    }

    #[test]
    fn nikto_blocked() {
        let ua = "Mozilla/5.00 (Nikto/2.1.6)";
        assert!(matches!(
            det().classify(ua, None),
            BotVerdict::KnownAttacker(_)
        ));
    }

    #[test]
    fn gobuster_blocked() {
        let ua = "gobuster/3.6";
        assert!(matches!(
            det().classify(ua, None),
            BotVerdict::KnownAttacker(_)
        ));
    }

    #[test]
    fn burp_suite_blocked() {
        let ua = "Mozilla/5.0 (compatible; BurpSuite/2024.3)";
        assert!(matches!(
            det().classify(ua, None),
            BotVerdict::KnownAttacker(_)
        ));
    }

    #[test]
    fn googlebot_is_good() {
        let ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
        assert!(matches!(det().classify(ua, None), BotVerdict::GoodBot(_)));
    }

    #[test]
    fn bingbot_is_good() {
        let ua = "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)";
        assert!(matches!(det().classify(ua, None), BotVerdict::GoodBot(_)));
    }

    #[test]
    fn empty_ua_is_suspicious() {
        assert_eq!(det().classify("", None), BotVerdict::SuspiciousBot);
        assert_eq!(det().classify("   ", None), BotVerdict::SuspiciousBot);
    }

    #[test]
    fn python_urllib_is_suspicious() {
        assert_eq!(
            det().classify("python-urllib/3.11", None),
            BotVerdict::SuspiciousBot
        );
    }

    #[test]
    fn go_http_client_is_suspicious() {
        assert_eq!(
            det().classify("Go-http-client/1.1", None),
            BotVerdict::SuspiciousBot
        );
    }

    #[test]
    fn ja4_fingerprint_overrides_clean_ua() {
        let clean_ua = "Mozilla/5.0 (Windows NT 10.0) Chrome/124";
        // Inject the sqlmap fingerprint from the static table
        let fp = "t13d1715h2_4b8e96bdf8c2_0c5ec3ea4b74";
        assert!(matches!(
            det().classify(clean_ua, Some(fp)),
            BotVerdict::KnownAttacker(_)
        ));
    }

    #[test]
    fn custom_ja4_entry() {
        let mut d = BotDetector::new();
        d.add_malicious_ja4("aabbccdd_11223344_55667788", "CustomTool");
        let ua = "Mozilla/5.0 (legit looking UA)";
        assert!(matches!(
            d.classify(ua, Some("aabbccdd_11223344_55667788")),
            BotVerdict::KnownAttacker(_)
        ));
    }

    #[test]
    fn headless_browser_blocked() {
        let ua = "Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/124.0";
        assert!(matches!(
            det().classify(ua, None),
            BotVerdict::KnownAttacker(_)
        ));
    }

    // -- Weighted bot score (issue #8) --------------------------------------

    #[test]
    fn score_real_browser_allows() {
        let sig = BotSignals {
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                         (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            ja4: None,
            has_accept: true,
            has_accept_language: true,
            recent_block_score: 0,
        };
        let r = det().score(&sig);
        assert_eq!(r.score, 0, "reasons: {:?}", r.reasons);
        assert_eq!(r.tier, BotTier::Allow);
        assert!(!r.verified_good_bot);
    }

    #[test]
    fn score_sqlmap_ja4_blocks() {
        // Real sqlmap request: bad JA4 (+45) + attacker UA (+40) + no
        // browser headers (+20) → saturates → Block.
        let sig = BotSignals {
            user_agent: "sqlmap/1.8.3#stable (https://sqlmap.org)",
            ja4: Some("t13d1715h2_4b8e96bdf8c2_0c5ec3ea4b74"),
            has_accept: false,
            has_accept_language: false,
            recent_block_score: 0,
        };
        let r = det().score(&sig);
        assert!(r.score >= 45, "score was {} ({:?})", r.score, r.reasons);
        assert_eq!(r.tier, BotTier::Block);
        assert!(r.reasons.iter().any(|s| s.starts_with("ja4-bad:")));
    }

    #[test]
    fn score_empty_ua_missing_headers_challenges() {
        // empty-ua (+30) + no-browser-headers (+20) = 50 → Captcha.
        let sig = BotSignals {
            user_agent: "   ",
            ja4: None,
            has_accept: false,
            has_accept_language: false,
            recent_block_score: 0,
        };
        let r = det().score(&sig);
        assert!(
            matches!(r.tier, BotTier::Captcha | BotTier::Block),
            "tier was {:?} (score {})",
            r.tier,
            r.score
        );
    }

    #[test]
    fn score_good_bot_allows() {
        let sig = BotSignals {
            user_agent: "Mozilla/5.0 (compatible; Googlebot/2.1; \
                         +http://www.google.com/bot.html)",
            ja4: None,
            has_accept: false,
            has_accept_language: false,
            recent_block_score: 8,
        };
        let r = det().score(&sig);
        // Early return wins over every other signal.
        assert_eq!(r.score, 0);
        assert_eq!(r.tier, BotTier::Allow);
        assert!(!r.verified_good_bot);
        assert_eq!(r.reasons, vec!["good-bot-ua (unverified)".to_string()]);
    }

    #[test]
    fn score_borderline_botlike_only_stays_allow() {
        // Only the bot-like UA hit (+20); browser headers present, no repeat.
        // 20 < 25, so the JsChallenge tier must NOT trigger.
        let sig = BotSignals {
            user_agent: "MyCoolScraper/1.0",
            ja4: None,
            has_accept: true,
            has_accept_language: true,
            recent_block_score: 0,
        };
        let r = det().score(&sig);
        assert_eq!(r.score, 20, "reasons: {:?}", r.reasons);
        assert_eq!(r.tier, BotTier::Allow);
        assert!(r.reasons.iter().any(|s| s == "botlike-ua"));
    }

    #[test]
    fn tier_boundaries_exact_edges() {
        // Directly exercise every threshold edge in the spec:
        // >=70 Block, 40..=69 Captcha, 25..=39 JsChallenge, else Allow.
        use BotTier::*;
        assert_eq!(tier_for_score(0), Allow);
        assert_eq!(tier_for_score(24), Allow); // upper edge of Allow
        assert_eq!(tier_for_score(25), JsChallenge); // lower edge of JsChallenge
        assert_eq!(tier_for_score(39), JsChallenge); // upper edge of JsChallenge
        assert_eq!(tier_for_score(40), Captcha); // lower edge of Captcha
        assert_eq!(tier_for_score(69), Captcha); // upper edge of Captcha
        assert_eq!(tier_for_score(70), Block); // lower edge of Block
        assert_eq!(tier_for_score(100), Block); // saturated
    }

    #[test]
    fn score_spoofed_good_bot_bad_ja4_not_allowed() {
        // Attacker spoofs a Googlebot UA but rides sqlmap's TLS stack. The
        // unspoofable malicious JA4 must override the good-bot UA claim, so the
        // request must NOT be allowed (regression for the good-bot early-return
        // precedence bug).
        let sig = BotSignals {
            user_agent: "Mozilla/5.0 (compatible; Googlebot/2.1; \
                         +http://www.google.com/bot.html)",
            ja4: Some("t13d1715h2_4b8e96bdf8c2_0c5ec3ea4b74"),
            has_accept: true,
            has_accept_language: true,
            recent_block_score: 0,
        };
        let r = det().score(&sig);
        assert_ne!(
            r.tier,
            BotTier::Allow,
            "spoofed good-bot UA with a malicious JA4 must not be allowed (score {}, reasons {:?})",
            r.score,
            r.reasons
        );
        assert!(
            r.reasons.iter().any(|s| s.starts_with("ja4-bad:")),
            "expected ja4-bad reason, got {:?}",
            r.reasons
        );
    }

    #[test]
    fn score_tier_boundaries() {
        // Exercise every threshold edge directly through the tier mapping by
        // constructing scores via known signal combinations.

        // 25 → JsChallenge: empty-ua (30) alone is 30 (JsChallenge band 25..=39).
        let js = det().score(&BotSignals {
            user_agent: "",
            ja4: None,
            has_accept: true, // present → no header bonus
            has_accept_language: true,
            recent_block_score: 0,
        });
        assert_eq!(js.score, 30);
        assert_eq!(js.tier, BotTier::JsChallenge);

        // 40 → Captcha: attacker-ua (40) alone.
        let cap = det().score(&BotSignals {
            user_agent: "sqlmap/1.8",
            ja4: None,
            has_accept: true,
            has_accept_language: true,
            recent_block_score: 0,
        });
        assert_eq!(cap.score, 40);
        assert_eq!(cap.tier, BotTier::Captcha);

        // 70 → Block: attacker-ua (40) + no-browser-headers (20) + repeat (10).
        let block = det().score(&BotSignals {
            user_agent: "nikto/2.1.6",
            ja4: None,
            has_accept: false,
            has_accept_language: false,
            recent_block_score: 3,
        });
        assert_eq!(block.score, 70);
        assert_eq!(block.tier, BotTier::Block);
    }
}

#[cfg(test)]
mod observability_tests {
    use super::*;

    /// Every built-in pattern must compile. `compile_table` drops any that does
    /// not (now with an `error!`), so a shortfall here means a shipped signature
    /// is silently not detected — which is precisely what the old
    /// `filter_map(...ok())` allowed with no trace at all.
    #[test]
    fn every_builtin_pattern_compiles() {
        let det = BotDetector::new();
        assert_eq!(
            det.attacker_pattern_count(),
            ATTACKER_PATTERNS.len(),
            "an attacker signature failed to compile and was dropped — that tool is not \
             detected, and it cannot be fixed from configuration"
        );
        assert_eq!(
            det.good_bot_pattern_count(),
            GOOD_BOT_PATTERNS.len(),
            "a good-bot pattern failed to compile"
        );
    }

    /// Pins how small the JA4 table actually is, so the number cannot quietly
    /// drift and so the gap between "JA4 bot blocking" as a feature name and a
    /// 4-entry built-in demo table stays on the record.
    ///
    /// If a real feed is ever wired in, this assertion should be changed
    /// deliberately — not deleted.
    #[test]
    fn the_ja4_table_is_a_small_builtin_demo_set() {
        let det = BotDetector::new();
        assert_eq!(
            det.ja4_fingerprint_count(),
            MALICIOUS_JA4_TABLE.len(),
            "new() must expose exactly the built-in table"
        );
        assert!(
            det.ja4_fingerprint_count() < 10,
            "still the demo table ({}). If a threat-intel feed now populates this, update \
             this test on purpose and note that the proxy re-creates the detector with \
             new() on every config reload, which discards add_malicious_ja4 additions.",
            det.ja4_fingerprint_count()
        );
    }

    /// Runtime additions do not survive what the proxy actually does on reload.
    /// Documents the limitation rather than asserting it is fine.
    #[test]
    fn runtime_ja4_additions_are_lost_on_reconstruction() {
        let mut det = BotDetector::new();
        let base = det.ja4_fingerprint_count();
        det.add_malicious_ja4("t13d000000_aaaaaaaaaaaa_bbbbbbbbbbbb", "test-tool");
        assert_eq!(det.ja4_fingerprint_count(), base + 1);
        // What the proxy does on every config change.
        let fresh = BotDetector::new();
        assert_eq!(
            fresh.ja4_fingerprint_count(),
            base,
            "a fingerprint added at runtime is discarded by the next reload; any feed \
             integration must repopulate after reconstruction"
        );
    }
}
