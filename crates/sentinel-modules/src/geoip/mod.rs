//! GeoIP module — country-level IP filtering via MaxMind GeoLite2-Country.
//!
//! Checked at Phase 1 (after the site is matched) because different sites
//! can have different country allow/block rules.
//!
//! ## Graceful degradation
//! If the `.mmdb` file is missing or unreadable the filter is disabled and
//! returns `GeoVerdict::Unknown` for every IP (traffic passes through).
//! This ensures the proxy always starts regardless of whether a GeoIP
//! database has been provisioned.

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;

use maxminddb::{geoip2, Reader};
use tracing::{error, info};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Result of a GeoIP country lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeoVerdict {
    /// IP is allowed by the country policy.
    Allow,
    /// IP's country is blocked by policy.
    Block { country_code: String },
    /// No database loaded or country not found in the database — allow by default.
    Unknown,
}

// ---------------------------------------------------------------------------
// GeoIp
// ---------------------------------------------------------------------------

/// Country-level filter.
///
/// Built cheaply from a config block; the heavy mmdb Reader is loaded once
/// at startup and can be hot-swapped on config reload via `ArcSwap`.
pub struct GeoIp {
    reader: Option<Reader<Vec<u8>>>,
    block_countries: HashSet<String>,
    allow_countries: HashSet<String>,
}

impl Default for GeoIp {
    fn default() -> Self {
        Self::disabled()
    }
}

impl GeoIp {
    /// Create a disabled filter that returns `GeoVerdict::Unknown` for all IPs.
    pub fn disabled() -> Self {
        Self {
            reader: None,
            block_countries: HashSet::new(),
            allow_countries: HashSet::new(),
        }
    }

    /// Load a MaxMind GeoLite2-Country `.mmdb` database.
    ///
    /// If the file cannot be read this falls back to `disabled()` and the proxy
    /// still starts. That is deliberate — one missing data file should not take a
    /// WAF down — but it is also how this control stayed invisible: `disabled()`
    /// answers `Unknown` for every address, so a site set to block `["CN","RU"]`
    /// blocks nothing while the console still shows the policy.
    ///
    /// So the failure is logged at ERROR, not WARN, and it names the
    /// consequence. `is_active()` reports the same fact in a queryable form and
    /// `/healthz` publishes it under `geoip.inert` — a single startup line is not
    /// enough, which is the lesson kernel XDP already taught here.
    pub fn from_path(
        db_path: impl AsRef<Path>,
        block_countries: Vec<String>,
        allow_countries: Vec<String>,
    ) -> Self {
        let path = db_path.as_ref();
        let reader = match Reader::open_readfile(path) {
            Ok(r) => {
                info!(path = %path.display(), "GeoIP database loaded");
                Some(r)
            }
            Err(e) => {
                error!(
                    path = %path.display(),
                    "GeoIP database not found or unreadable ({e}) — COUNTRY FILTERING IS NOT \
                     ENFORCED for this site. Every address resolves to Unknown, so configured \
                     block/allow country rules pass all traffic. Supply a MaxMind \
                     GeoLite2-Country.mmdb and point SENTINEL_GEOIP_DB / waf_policy.geoip.db_path \
                     at it. Queryable at /healthz -> geoip.inert."
                );
                None
            }
        };
        Self {
            reader,
            block_countries: block_countries
                .into_iter()
                .map(|s| s.to_uppercase())
                .collect(),
            allow_countries: allow_countries
                .into_iter()
                .map(|s| s.to_uppercase())
                .collect(),
        }
    }

    /// Look up the country for `ip` and apply block/allow rules.
    pub fn check(&self, ip: IpAddr) -> GeoVerdict {
        self.classify(self.country(ip).as_deref())
    }

    /// Resolve an IP's ISO-3166-1 alpha-2 country code, independent of policy.
    ///
    /// [`check`](Self::check) answers "may this country in?", and its `Allow`
    /// variant deliberately carries no country — so a caller that wants to
    /// *record* where a request came from (logging, analytics, the dashboard map)
    /// cannot obtain it from a verdict at all. Exposing the lookup separately
    /// lets the request logger attribute allowed traffic, not just blocked
    /// traffic, without duplicating the mmdb read.
    pub fn country(&self, ip: IpAddr) -> Option<String> {
        let reader = self.reader.as_ref()?;
        match reader.lookup::<geoip2::Country>(ip) {
            Ok(result) => result
                .country
                .and_then(|c| c.iso_code)
                .map(|code| code.to_uppercase()),
            Err(maxminddb::MaxMindDBError::AddressNotFoundError(_)) => None,
            Err(e) => {
                tracing::debug!("GeoIP lookup failed for {ip}: {e}");
                None
            }
        }
    }

    /// Apply country policy to a known country code (or `None` for unknown).
    ///
    /// Separated out so unit tests can verify policy logic without an mmdb file.
    pub fn classify(&self, country_code: Option<&str>) -> GeoVerdict {
        let cc = match country_code {
            Some(c) => c.to_uppercase(),
            None => return GeoVerdict::Unknown,
        };

        // Allow-only mode: if allow_countries is set, reject everything else.
        if !self.allow_countries.is_empty() {
            return if self.allow_countries.contains(&cc) {
                GeoVerdict::Allow
            } else {
                GeoVerdict::Block { country_code: cc }
            };
        }

        // Block-list mode.
        if self.block_countries.contains(&cc) {
            return GeoVerdict::Block { country_code: cc };
        }

        GeoVerdict::Allow
    }

    /// `true` if a database is loaded and country rules are configured.
    pub fn is_active(&self) -> bool {
        self.reader.is_some()
            && (!self.block_countries.is_empty() || !self.allow_countries.is_empty())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn geo_blocklist(countries: &[&str]) -> GeoIp {
        GeoIp {
            reader: None,
            block_countries: countries.iter().map(|s| s.to_uppercase()).collect(),
            allow_countries: HashSet::new(),
        }
    }

    fn geo_allowlist(countries: &[&str]) -> GeoIp {
        GeoIp {
            reader: None,
            block_countries: HashSet::new(),
            allow_countries: countries.iter().map(|s| s.to_uppercase()).collect(),
        }
    }

    #[test]
    fn disabled_returns_unknown() {
        let geo = GeoIp::disabled();
        assert_eq!(geo.check("1.2.3.4".parse().unwrap()), GeoVerdict::Unknown);
    }

    #[test]
    fn nonexistent_db_path_is_graceful() {
        let geo = GeoIp::from_path("/nonexistent/path/GeoLite2-Country.mmdb", vec![], vec![]);
        assert_eq!(geo.check("8.8.8.8".parse().unwrap()), GeoVerdict::Unknown);
        assert!(!geo.is_active());
    }

    #[test]
    fn blocklist_blocks_matching_country() {
        let geo = geo_blocklist(&["CN", "RU"]);
        assert_eq!(
            geo.classify(Some("CN")),
            GeoVerdict::Block {
                country_code: "CN".into()
            }
        );
        assert_eq!(
            geo.classify(Some("RU")),
            GeoVerdict::Block {
                country_code: "RU".into()
            }
        );
    }

    #[test]
    fn blocklist_allows_non_blocked_country() {
        let geo = geo_blocklist(&["CN", "RU"]);
        assert_eq!(geo.classify(Some("US")), GeoVerdict::Allow);
        assert_eq!(geo.classify(Some("DE")), GeoVerdict::Allow);
    }

    #[test]
    fn allowlist_blocks_unlisted_country() {
        let geo = geo_allowlist(&["US", "DE", "GB"]);
        assert_eq!(
            geo.classify(Some("CN")),
            GeoVerdict::Block {
                country_code: "CN".into()
            }
        );
        assert_eq!(
            geo.classify(Some("RU")),
            GeoVerdict::Block {
                country_code: "RU".into()
            }
        );
    }

    #[test]
    fn allowlist_permits_listed_country() {
        let geo = geo_allowlist(&["US", "DE"]);
        assert_eq!(geo.classify(Some("US")), GeoVerdict::Allow);
        assert_eq!(geo.classify(Some("DE")), GeoVerdict::Allow);
    }

    #[test]
    fn allowlist_takes_priority_over_blocklist() {
        // allow_countries non-empty → block_countries ignored.
        let geo = GeoIp {
            reader: None,
            block_countries: vec!["US".to_string()].into_iter().collect(),
            allow_countries: vec!["US".to_string()].into_iter().collect(),
        };
        // US is in allow_countries → Allow (even though also in block_countries).
        assert_eq!(geo.classify(Some("US")), GeoVerdict::Allow);
        // DE is not in allow_countries → Block.
        assert_eq!(
            geo.classify(Some("DE")),
            GeoVerdict::Block {
                country_code: "DE".into()
            }
        );
    }

    #[test]
    fn unknown_country_code_is_unknown() {
        let geo = geo_blocklist(&["CN"]);
        assert_eq!(geo.classify(None), GeoVerdict::Unknown);
    }

    #[test]
    fn country_codes_are_case_insensitive() {
        let geo = geo_blocklist(&["cn"]);
        assert_eq!(
            geo.classify(Some("CN")),
            GeoVerdict::Block {
                country_code: "CN".into()
            }
        );
        assert_eq!(
            geo.classify(Some("cn")),
            GeoVerdict::Block {
                country_code: "CN".into()
            }
        );
    }
}

#[cfg(test)]
mod synthetic_db_tests {
    use super::*;
    use std::net::IpAddr;
    use std::path::PathBuf;

    /// A SYNTHETIC database, built by `tools/mkgeoip-testdb` using MaxMind's
    /// Apache-2.0 writer and containing no MaxMind data — only RFC 5737
    /// documentation ranges and RFC 1918 private space mapped to arbitrary
    /// country codes.
    ///
    /// It exists because the enforcement path had NO test: a real GeoLite2 file
    /// cannot be committed (MaxMind requires an account and forbids
    /// redistribution), so "country blocking blocks" was an assumption for the
    /// entire life of the feature. It is useless for real geolocation and
    /// sufficient to prove the path.
    fn test_db() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/GeoLite2-Country-test.mmdb")
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test ip")
    }

    #[test]
    fn the_reader_loads_the_database_and_resolves_countries() {
        let geo = GeoIp::from_path(test_db(), vec![], vec![]);
        assert!(
            geo.is_active() || geo.country(ip("203.0.113.5")).is_some(),
            "the database did not load — a fixture that cannot be read proves nothing"
        );
        assert_eq!(geo.country(ip("203.0.113.5")).as_deref(), Some("CN"));
        assert_eq!(geo.country(ip("198.51.100.7")).as_deref(), Some("RU"));
        assert_eq!(geo.country(ip("192.0.2.9")).as_deref(), Some("US"));
        // An address outside every mapped range must be Unknown, not a guess.
        assert_eq!(geo.country(ip("8.8.8.8")), None);
    }

    /// The claim the product makes and never tested: a configured country block
    /// actually blocks.
    #[test]
    fn a_blocked_country_is_blocked_and_others_are_not() {
        let geo = GeoIp::from_path(test_db(), vec!["CN".into(), "RU".into()], vec![]);
        assert!(geo.is_active(), "database + rules should be active");

        assert!(
            matches!(geo.check(ip("203.0.113.5")), GeoVerdict::Block { .. }),
            "CN is on the block list and must be blocked"
        );
        assert!(
            matches!(geo.check(ip("198.51.100.7")), GeoVerdict::Block { .. }),
            "RU is on the block list and must be blocked"
        );
        assert!(
            matches!(geo.check(ip("192.0.2.9")), GeoVerdict::Allow),
            "US is not on the block list and must pass"
        );
        // Unknown must NOT be treated as blocked — that would turn a lookup miss
        // into an outage for anyone the database does not cover.
        assert!(matches!(geo.check(ip("8.8.8.8")), GeoVerdict::Unknown));
    }

    /// Allow-only mode is the stricter posture and inverts the default.
    #[test]
    fn allow_only_mode_rejects_everything_else() {
        let geo = GeoIp::from_path(test_db(), vec![], vec!["US".into()]);
        assert!(geo.is_active());
        assert!(
            matches!(geo.check(ip("192.0.2.9")), GeoVerdict::Allow),
            "US is allowed"
        );
        assert!(
            matches!(geo.check(ip("203.0.113.5")), GeoVerdict::Block { .. }),
            "CN is not on the allow list and must be blocked"
        );
    }

    /// Case-insensitivity, because an operator will type "cn".
    #[test]
    fn country_codes_are_case_insensitive() {
        let geo = GeoIp::from_path(test_db(), vec!["cn".into()], vec![]);
        assert!(matches!(
            geo.check(ip("203.0.113.5")),
            GeoVerdict::Block { .. }
        ));
    }

    /// The inert case, against the SAME code path — rules configured, database
    /// absent. This is what every deployment has actually been running.
    #[test]
    fn rules_without_a_database_are_inert_and_say_so() {
        let geo = GeoIp::from_path(
            "/nonexistent/GeoLite2-Country.mmdb",
            vec!["CN".into()],
            vec![],
        );
        assert!(
            !geo.is_active(),
            "no database means not active, however many rules are configured"
        );
        assert_eq!(geo.country(ip("203.0.113.5")), None);
        assert!(
            matches!(geo.check(ip("203.0.113.5")), GeoVerdict::Unknown),
            "a blocked country passes when there is no database — the defect this reports"
        );
    }
}

#[cfg(test)]
mod fixture_guard {
    use std::path::PathBuf;

    /// The enforcement tests above are only meaningful if the fixture is present
    /// AND non-trivial. A missing file made four of them fail loudly the first
    /// time, which was the right outcome — but a TRUNCATED or empty file could
    /// plausibly load and resolve nothing, and then the tests would pass while
    /// asserting nothing. Pin the shape.
    #[test]
    fn the_synthetic_fixture_is_present_and_plausible() {
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/GeoLite2-Country-test.mmdb");
        let meta = std::fs::metadata(&p).unwrap_or_else(|e| {
            panic!(
                "GeoIP test fixture missing at {}: {e}. Rebuild it with \
                 tools/mkgeoip-testdb — without it the country-blocking tests \
                 prove nothing.",
                p.display()
            )
        });
        assert!(
            meta.len() > 512,
            "fixture is {} bytes — too small to contain the 5 networks it should",
            meta.len()
        );
        let bytes = std::fs::read(&p).expect("read fixture");
        // Every mmdb ends with this marker followed by the metadata section.
        assert!(
            bytes.windows(14).any(|w| w == b"\xab\xcd\xefMaxMind.com"),
            "fixture has no MaxMind metadata marker — not a valid mmdb"
        );
    }
}
