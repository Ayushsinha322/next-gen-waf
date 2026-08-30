//! sentinel-core — engine, configuration, and per-request transaction context.
//!
//! This crate is the heart of the Sentinel data plane.  All other crates depend
//! on it for shared types; it intentionally has no dependency on any other
//! sentinel-* crate.

pub mod config;
pub mod context;
pub mod error;
/// One definition of "this value must never be written down", shared by the
/// rule VM (matched-value capture) and the proxy (access-log query strings).
pub mod redact;

// Flatten the most-used types to the crate root for ergonomics.
pub use config::{ConfigHandle, ConfigLoader, SentinelConfig};
pub use context::{Phase, RequestContext, RuleMatch, Severity, WafDecision};
pub use error::{Result, SentinelError};
