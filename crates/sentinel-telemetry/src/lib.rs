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

pub mod audit;
pub mod logs;
pub mod metrics;
pub mod traces;

pub use logs::{AccessEvent, AuditEvent, ErrorEvent, EventLogger, MlEvent, ModsecEvent, WafEvent};

pub use metrics::{
    dec_active_connections, history_shed_total, inc_active_connections, inc_blocked,
    inc_ebpf_drops, inc_history_shed, inc_load_shed_connections, inc_load_shed_requests,
    inc_requests, inc_rule_hits, observe_duration, prometheus_text, set_active_connections,
    snapshot, Counter, Gauge, Histogram, MetricLine, MetricsRegistry, MetricsSnapshot,
};

pub use traces::{start_child_span, start_span, Span, SpanId, TraceId, Tracer, TRACER};

pub use audit::{AuditEntry, AuditLogger};
