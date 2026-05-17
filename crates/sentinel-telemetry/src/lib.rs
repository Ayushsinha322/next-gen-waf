//! sentinel-telemetry — structured event logging and observability for the
//! Sentinel WAF data plane.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use sentinel_telemetry::logs::{EventLogger, AccessEvent};
//!
//! let logger = EventLogger::from_env().expect("event logger init");
//! logger.log_access(AccessEvent::new(
//!     "api.acme.com", "GET", "/api/v1/health", "10.0.0.1",
//!     200, 512, 1.2, "sentinel-proxy/1.0",
//! ));
//! ```

pub mod logs;
pub mod metrics;
pub mod traces;
pub mod audit;

pub use logs::{
    AccessEvent, AuditEvent, ErrorEvent, EventLogger, MlEvent, ModsecEvent, WafEvent,
};

pub use metrics::{
    Counter, Gauge, Histogram, MetricsRegistry, MetricsSnapshot, MetricLine,
    inc_requests, inc_blocked, observe_duration, set_active_connections,
    inc_rule_hits, inc_ebpf_drops, prometheus_text, snapshot,
};

pub use traces::{
    TraceId, SpanId, Span, Tracer, TRACER,
    start_span, start_child_span,
};

pub use audit::{AuditEntry, AuditLogger};
