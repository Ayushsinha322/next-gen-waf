//! sentinel-modules — Phase 2 security modules.
//!
//! Five modules are available:
//! - [`ip_reputation`] — CIDR-based block/allowlists and feed ingestion.
//! - [`rate_limit`]    — Token-bucket rate limiter (per-IP, per-site, global).
//! - [`bot_detect`]    — User-Agent classification and JA4 fingerprint matching.
//! - [`geoip`]         — Country-level IP filtering via MaxMind GeoLite2.
//! - [`anti_ddos`]     — Connection-rate DDoS protection with auto-blocking.
//!
//! All modules are wired into the sentinel-proxy Phase 0/1 pipeline.

pub mod anti_ddos;
pub mod bot_detect;
pub mod geoip;
pub mod ip_reputation;
pub mod rate_limit;
pub mod smuggling;
pub mod threat_intel;

pub use anti_ddos::{AntiDdos, DdosVerdict};
pub use bot_detect::{BotDetector, BotVerdict};
pub use geoip::{GeoIp, GeoVerdict};
pub use ip_reputation::{IpReputation, IpVerdict};
pub use rate_limit::RateLimiter;
pub use smuggling::{detect as detect_smuggling, SmugglingVerdict};
pub use threat_intel::{RawTier, ThreatFeed, ThreatVerdict};
