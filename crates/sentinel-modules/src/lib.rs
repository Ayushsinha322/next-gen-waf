//! sentinel-modules — Phase 2 security modules.
//!
//! Five modules are available:
//! - [`ip_reputation`] — CIDR-based block/allowlists and feed ingestion.
//! - [`rate_limit`]    — Token-bucket rate limiter (per-IP, per-site, global).
//! - [`bot_detect`]    — User-Agent classification and JA4 fingerprint matching.
//! - [`dlp`]           — Response-body DLP: PII/secret detection + length-preserving redaction.
//! - [`geoip`]         — Country-level IP filtering via MaxMind GeoLite2.
//! - [`anti_ddos`]     — Connection-rate DDoS protection with auto-blocking.
//! - [`jwt_auth`]      — Edge JWT (bearer-token) validation for customer APIs.
//! - [`grpc`]          — gRPC firewall: reflection/method gating and frame limits.
//!
//! All modules are wired into the sentinel-proxy Phase 0/1 pipeline.

pub mod anti_ddos;
pub mod bot_detect;
pub mod dlp;
pub mod geoip;
pub mod graphql;
pub mod grpc;
pub mod ip_reputation;
pub mod jwt_auth;
pub mod rate_limit;
pub mod smuggling;
pub mod threat_intel;
pub mod tls_fingerprint;

pub use anti_ddos::{AntiDdos, DdosVerdict};
pub use bot_detect::{
    good_bot_name, good_bot_verify_domains, BotDetector, BotScore, BotSignals, BotTier, BotVerdict,
};
pub use dlp::DlpEngine;
pub use geoip::{GeoDb, GeoIp, GeoVerdict};
pub use graphql::{inspect as inspect_graphql, GraphqlLimits};
pub use grpc::{
    check_body as check_grpc_body, check_request as check_grpc_request, is_grpc, GrpcLimits,
};
pub use ip_reputation::{IpReputation, IpVerdict};
pub use jwt_auth::{
    decoding_keys_from_jwks, decoding_keys_from_jwks_diag, token_header, validate as validate_jwt,
    JwksParse, JwtPolicy,
};
pub use rate_limit::{BreakerState, DistributedGuard, DistributedStatus, RateLimiter};
pub use smuggling::{detect as detect_smuggling, SmugglingVerdict};
pub use threat_intel::{RawTier, ThreatFeed, ThreatVerdict};
pub use tls_fingerprint::{
    client_hello_needed_len, ja4, ja4_from_client_hello, parse_client_hello, ClientHelloInfo,
    NotHandshake,
};
