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
use tracing::{info, warn};

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
    /// If the file doesn't exist or can't be read, logs a warning and falls
    /// back to `disabled()` — the proxy continues to start normally.
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
                warn!(
                    path = %path.display(),
                    "GeoIP database not found or unreadable ({e}) — country filtering disabled"
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
        let reader = match &self.reader {
            Some(r) => r,
            None => return GeoVerdict::Unknown,
        };

        let country_code: Option<String> = {
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
        };

        self.classify(country_code.as_deref())
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
        assert_eq!(
            geo.check("1.2.3.4".parse().unwrap()),
            GeoVerdict::Unknown
        );
    }

    #[test]
    fn nonexistent_db_path_is_graceful() {
        let geo = GeoIp::from_path("/nonexistent/path/GeoLite2-Country.mmdb", vec![], vec![]);
        assert_eq!(
            geo.check("8.8.8.8".parse().unwrap()),
            GeoVerdict::Unknown
        );
        assert!(!geo.is_active());
    }

    #[test]
    fn blocklist_blocks_matching_country() {
        let geo = geo_blocklist(&["CN", "RU"]);
        assert_eq!(
            geo.classify(Some("CN")),
            GeoVerdict::Block { country_code: "CN".into() }
        );
        assert_eq!(
            geo.classify(Some("RU")),
            GeoVerdict::Block { country_code: "RU".into() }
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
            GeoVerdict::Block { country_code: "CN".into() }
        );
        assert_eq!(
            geo.classify(Some("RU")),
            GeoVerdict::Block { country_code: "RU".into() }
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
            GeoVerdict::Block { country_code: "DE".into() }
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
            GeoVerdict::Block { country_code: "CN".into() }
        );
        assert_eq!(
            geo.classify(Some("cn")),
            GeoVerdict::Block { country_code: "CN".into() }
        );
    }
}
