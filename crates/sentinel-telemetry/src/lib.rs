//! sentinel-telemetry — metrics and tracing for the Sentinel WAF data plane.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use sentinel_telemetry::{inc_requests, prometheus_text};
//!
//! inc_requests();
//! let scrape = prometheus_text();
//! assert!(scrape.contains("sentinel_requests_total"));
//! ```
//!
//! # What used to live here
//!
//! This crate also carried `logs` (an `EventLogger` writing access/waf/modsec/ml
//! NDJSON) and `audit` (a second HMAC-chained audit log). Both were removed in
//! 2026-08: neither had a single caller anywhere in the workspace, and both had
//! DRIFTED from the implementations that are real — the proxy writes access.log
//! and waf.log itself (`crates/sentinel-proxy`, with request_id/tenant/mode and
//! RFC-3339 timestamps), and the audit chain lives in the control plane
//! (`control-plane/internal/db`, append-only enforced by Postgres grants).
//!
//! The removed `WafEvent` had no `request_id`, no `tenant` and no `mode`, spelled
//! severity `sev`, and stamped second-precision timestamps with no timezone —
//! so wiring up the "obvious" logger would have silently broken Support-ID
//! correlation while looking like an improvement. Dead code that appears
//! load-bearing is a trap, not an asset; if this functionality is ever wanted
//! again, extend the writer that ships.

pub mod metrics;
pub mod traces;

pub use metrics::{
    bot_good_bot_allowed_total, dec_active_connections, graphql_blocked_total,
    graphql_inspected_total, grpc_inspected_total, history_shed_total, inc_active_connections,
    inc_blocked, inc_ebpf_drops, inc_history_shed, inc_load_shed_connections,
    inc_load_shed_requests, inc_log_lines_dropped, inc_requests, inc_rule_hits, ja4_attempts_total,
    ja4_no_hello_total, ja4_success_total, log_lines_dropped_total, note_good_bot_allowed,
    note_graphql_blocked, note_graphql_inspected, note_grpc_inspected, note_ja4_attempt,
    note_ja4_no_hello, note_ja4_success, note_smuggling_evaluated, note_smuggling_rejected_framing,
    note_smuggling_rejected_header, observe_duration, prometheus_text, set_active_connections,
    smuggling_evaluated_total, smuggling_rejected_framing_total, smuggling_rejected_header_total,
    snapshot, Counter, Gauge, Histogram, MetricLine, MetricsRegistry, MetricsSnapshot,
};

pub use traces::{start_child_span, start_span, Span, SpanId, TraceId, Tracer, TRACER};
