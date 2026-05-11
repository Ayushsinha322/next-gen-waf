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
    (r"(?i)\bdirbuster\b|\bgobuster\b|\bffuf\b|\bwfuzz\b|\bferoxbuster\b", "DirBruter"),
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

static PATTERNS: Lazy<CompiledPatterns> = Lazy::new(|| CompiledPatterns {
    good_bots: GOOD_BOT_PATTERNS
        .iter()
        .filter_map(|(pat, name)| Regex::new(pat).ok().map(|re| (re, name.to_string())))
        .collect(),
    attackers: ATTACKER_PATTERNS
        .iter()
        .filter_map(|(pat, name)| Regex::new(pat).ok().map(|re| (re, name.to_string())))
        .collect(),
});

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
        let malicious_ja4 = MALICIOUS_JA4_TABLE
            .iter()
            .map(|(fp, name)| (fp.to_string(), name.to_string()))
            .collect();
        Self { malicious_ja4 }
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
        for (re, name) in &patterns.attackers {
            if re.is_match(user_agent) {
                return BotVerdict::KnownAttacker(name.clone());
            }
        }

        // 3. Known-good search crawlers.
        for (re, name) in &patterns.good_bots {
            if re.is_match(user_agent) {
                return BotVerdict::GoodBot(name.clone());
            }
        }

        // 4. Empty or whitespace-only UA — almost certainly a bot or scanner.
        if user_agent.trim().is_empty() {
            return BotVerdict::SuspiciousBot;
        }

        // 5. Generic bot-like lexical hints in the UA string.
        let ua_lower = user_agent.to_ascii_lowercase();
        if ua_lower.contains("bot")
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
        {
            return BotVerdict::SuspiciousBot;
        }

        BotVerdict::Human
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
        assert!(matches!(det().classify(ua, None), BotVerdict::KnownAttacker(_)));
    }

    #[test]
    fn nikto_blocked() {
        let ua = "Mozilla/5.00 (Nikto/2.1.6)";
        assert!(matches!(det().classify(ua, None), BotVerdict::KnownAttacker(_)));
    }

    #[test]
    fn gobuster_blocked() {
        let ua = "gobuster/3.6";
        assert!(matches!(det().classify(ua, None), BotVerdict::KnownAttacker(_)));
    }

    #[test]
    fn burp_suite_blocked() {
        let ua = "Mozilla/5.0 (compatible; BurpSuite/2024.3)";
        assert!(matches!(det().classify(ua, None), BotVerdict::KnownAttacker(_)));
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
        assert!(matches!(det().classify(ua, None), BotVerdict::KnownAttacker(_)));
    }
}
