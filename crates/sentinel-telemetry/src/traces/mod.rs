//! Lightweight span/trace implementation for the Sentinel WAF.
//!
//! Provides [`TraceId`], [`SpanId`], [`Span`], and [`Tracer`] with a global
//! [`TRACER`] singleton.  When a span is finished via [`Span::finish`] it
//! emits a structured `tracing` event so that any installed subscriber
//! (including the JSON one from `sentinel-telemetry::logs`) picks it up.
//!
//! # Example
//!
//! ```rust,no_run
//! use sentinel_telemetry::traces::{start_span, start_child_span};
//!
//! let root = start_span("proxy.handle_request");
//! let child = start_child_span("rules.evaluate", &root);
//! child.finish();
//! root.finish();
//! ```

use std::{
    collections::HashMap,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use once_cell::sync::Lazy;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// IDs
// ---------------------------------------------------------------------------

/// 16-byte (128-bit) trace identifier, displayed as a 32-character hex string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TraceId(String);

impl TraceId {
    /// Generate a new random trace ID.
    pub fn new() -> Self {
        // Use two UUIDs concatenated so we get 128 bits without extra deps.
        let id = Uuid::new_v4().simple().to_string();
        Self(id)
    }

    /// Return the hex string representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for TraceId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for TraceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// 8-byte (64-bit) span identifier, displayed as a 16-character hex string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SpanId(String);

impl SpanId {
    /// Generate a new random span ID (first 16 hex chars of a UUID v4).
    pub fn new() -> Self {
        let full = Uuid::new_v4().simple().to_string();
        Self(full[..16].to_owned())
    }

    /// Return the hex string representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for SpanId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SpanId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// Span
// ---------------------------------------------------------------------------

/// A single unit of work within a distributed trace.
///
/// Create spans via [`Tracer::start_span`] / [`Tracer::start_child_span`] or
/// the module-level [`start_span`] / [`start_child_span`] convenience
/// functions.  Call [`Span::finish`] when the work completes.
pub struct Span {
    /// Trace this span belongs to.
    pub trace_id: TraceId,
    /// Unique identifier for this span.
    pub span_id: SpanId,
    /// Parent span identifier, if any.
    pub parent_span_id: Option<SpanId>,
    /// Human-readable operation name.
    pub name: String,
    /// Wall-clock start time (for log output).
    start_wall: u64,
    /// Monotonic start for accurate duration measurement.
    start_time: Instant,
    /// Free-form key→value attributes.
    pub attributes: HashMap<String, String>,
}

impl Span {
    fn new(
        name: impl Into<String>,
        trace_id: TraceId,
        parent_span_id: Option<SpanId>,
    ) -> Self {
        let start_wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            trace_id,
            span_id: SpanId::new(),
            parent_span_id,
            name: name.into(),
            start_wall,
            start_time: Instant::now(),
            attributes: HashMap::new(),
        }
    }

    /// Set an attribute on the span.  Returns `self` for chaining.
    pub fn set_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Add an attribute by mutable reference (for post-creation use).
    pub fn add_attribute(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.attributes.insert(key.into(), value.into());
    }

    /// Finish the span: compute duration and emit a structured tracing event.
    pub fn finish(self) {
        let duration_us = self.start_time.elapsed().as_micros();
        let parent = self
            .parent_span_id
            .as_ref()
            .map(|s| s.as_str().to_owned())
            .unwrap_or_default();

        // Serialise attributes to a JSON string for the log field.
        let attrs_json = serde_json::to_string(&self.attributes)
            .unwrap_or_else(|_| "{}".to_owned());

        tracing::info!(
            target: "sentinel_trace",
            trace_id    = %self.trace_id,
            span_id     = %self.span_id,
            parent_span_id = %parent,
            name        = %self.name,
            start_ms    = self.start_wall,
            duration_us = duration_us,
            attributes  = %attrs_json,
            "span finished"
        );
    }
}

// ---------------------------------------------------------------------------
// Tracer
// ---------------------------------------------------------------------------

/// Factory for creating [`Span`] instances.
pub struct Tracer;

impl Tracer {
    pub const fn new() -> Self {
        Self
    }

    /// Start a new root span (new trace ID).
    pub fn start_span(&self, name: impl Into<String>) -> Span {
        Span::new(name, TraceId::new(), None)
    }

    /// Start a child span that shares `parent`'s trace ID.
    pub fn start_child_span(&self, name: impl Into<String>, parent: &Span) -> Span {
        Span::new(name, parent.trace_id.clone(), Some(parent.span_id.clone()))
    }
}

impl Default for Tracer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Global singleton
// ---------------------------------------------------------------------------

/// Global [`Tracer`] instance.  Use the module-level helpers [`start_span`]
/// and [`start_child_span`] for the common case.
pub static TRACER: Lazy<Tracer> = Lazy::new(Tracer::new);

/// Start a new root span using the global tracer.
pub fn start_span(name: &str) -> Span {
    TRACER.start_span(name)
}

/// Start a child span using the global tracer.
pub fn start_child_span(name: &str, parent: &Span) -> Span {
    TRACER.start_child_span(name, parent)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_and_span_ids_differ() {
        let t1 = TraceId::new();
        let t2 = TraceId::new();
        assert_ne!(t1, t2);

        let s1 = SpanId::new();
        let s2 = SpanId::new();
        assert_ne!(s1, s2);
    }

    #[test]
    fn span_id_is_16_hex_chars() {
        let id = SpanId::new();
        assert_eq!(id.as_str().len(), 16);
        assert!(id.as_str().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn trace_id_is_32_hex_chars() {
        let id = TraceId::new();
        assert_eq!(id.as_str().len(), 32);
        assert!(id.as_str().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn child_span_inherits_trace_id() {
        let tracer = Tracer::new();
        let root = tracer.start_span("root");
        let child = tracer.start_child_span("child", &root);
        assert_eq!(root.trace_id, child.trace_id);
        assert_eq!(child.parent_span_id.as_ref().unwrap(), &root.span_id);
        child.finish();
        root.finish();
    }

    #[test]
    fn span_attributes() {
        let span = start_span("test_op")
            .set_attribute("http.method", "GET")
            .set_attribute("http.status", "200");
        assert_eq!(span.attributes["http.method"], "GET");
        span.finish();
    }

    #[test]
    fn global_start_span_works() {
        let s = start_span("global_test");
        assert!(!s.trace_id.as_str().is_empty());
        s.finish();
    }
}
