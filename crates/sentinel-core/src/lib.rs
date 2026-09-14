//! sentinel-core — engine, configuration, and per-request transaction context.
//!
//! This crate is the heart of the Sentinel data plane.  All other crates depend
//! on it for shared types; it intentionally has no dependency on any other
//! sentinel-* crate.

/// The product's name, as customers read it.
///
/// `sentinel` is the codename for this source tree — the crates, the binaries,
/// the image tags, the log targets. It is not what the product is called, and
/// the data plane in particular must not leak it: the browser-check page and
/// the CAPTCHA page are served to the PROTECTED SITE'S OWN VISITORS, members of
/// the public who have never heard of either name, and both carried the
/// codename as their logo. So did the 429 body.
///
/// A macro rather than only a constant, because those pages are `const &str`
/// built at compile time and `concat!` takes literals, not constants. Use
/// `product_name!()` inside `concat!`, and [`PRODUCT_NAME`] everywhere else.
/// Both expand from this one definition, so they cannot drift.
///
/// The console has the same rule enforced by dashboard/lib/__tests__/branding.test.ts.
#[macro_export]
macro_rules! product_name {
    () => {
        "Swaraj Kavach"
    };
}

/// The product's name. See [`product_name!`].
pub const PRODUCT_NAME: &str = product_name!();

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
