//! Prometheus-style in-memory metrics for the Sentinel WAF.
//!
//! Uses only `std::sync::atomic` and `std::sync::Mutex` — no external metrics
//! crate required.  A global [`WAF_METRICS`] registry is pre-populated with
//! the WAF-specific counters, gauges, and histograms listed below.
//!
//! # Prometheus text format
//!
//! Call [`prometheus_text()`] to get a scrape-ready string.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicI64, AtomicU64, Ordering},
        Arc, Mutex, MutexGuard, PoisonError,
    },
};

use once_cell::sync::Lazy;

// ---------------------------------------------------------------------------
// Primitive metric types
// ---------------------------------------------------------------------------

/// A monotonically-increasing unsigned counter.
#[derive(Clone)]
pub struct Counter {
    name: String,
    help: String,
    value: Arc<AtomicU64>,
}

impl Counter {
    fn new(name: impl Into<String>, help: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            help: help.into(),
            value: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Increment by 1.
    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment by `n`.
    pub fn inc_by(&self, n: u64) {
        self.value.fetch_add(n, Ordering::Relaxed);
    }

    /// Current value.
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

/// A signed gauge that can go up or down.
#[derive(Clone)]
pub struct Gauge {
    name: String,
    help: String,
    value: Arc<AtomicI64>,
}

impl Gauge {
    fn new(name: impl Into<String>, help: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            help: help.into(),
            value: Arc::new(AtomicI64::new(0)),
        }
    }

    /// Set to an absolute value.
    pub fn set(&self, v: i64) {
        self.value.store(v, Ordering::Relaxed);
    }

    /// Increment by 1.
    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement by 1.
    pub fn dec(&self) {
        self.value.fetch_sub(1, Ordering::Relaxed);
    }

    /// Current value.
    pub fn get(&self) -> i64 {
        self.value.load(Ordering::Relaxed)
    }
}

/// Upper bounds (inclusive, "le") of the latency buckets, in milliseconds.
///
/// Chosen to span a WAF's realistic range: sub-millisecond fast paths through to
/// multi-second upstream stalls. Everything above the last bound lands in the
/// overflow bucket.
const HISTOGRAM_BOUNDS: [f64; 15] = [
    0.5, 1.0, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, 10_000.0,
    30_000.0,
];

/// Number of counters: one per bound plus an overflow bucket for +Inf.
const HISTOGRAM_BUCKETS: usize = HISTOGRAM_BOUNDS.len() + 1;

/// Fixed-point scale for the running sum. `sum` has to be atomic and there is no
/// stable `AtomicF64`, so observations are accumulated as micro-units of the
/// recorded value (milliseconds here) and converted back on read.
const SUM_SCALE: f64 = 1_000.0;

struct HistogramInner {
    buckets: [AtomicU64; HISTOGRAM_BUCKETS],
    count: AtomicU64,
    /// Sum of observations in micro-units (see [`SUM_SCALE`]).
    sum_scaled: AtomicU64,
}

/// A lock-free histogram over fixed buckets, with percentile estimation.
///
/// The previous implementation kept every observation in a `Mutex<Vec<f64>>`. That
/// had three separate problems, all on the hot path:
///
///  1. Every single request took a process-wide mutex just to record its latency,
///     serializing all worker threads through one cache line and capping
///     multi-core scaling regardless of core count.
///  2. The `Vec` was never drained, so it grew without bound for the lifetime of
///     the process — an unbounded memory leak proportional to total requests
///     served.
///  3. `percentile()` sorted that ever-growing `Vec` **while holding the lock**,
///     and a single `/metrics` scrape called it three times plus `count()` and
///     `sum()` — five lock acquisitions and three full sorts, each O(n log n) in
///     total requests ever served, blocking every request in flight.
///
/// Recording is now a couple of relaxed atomic adds into a fixed-size array, so
/// memory is constant and threads never block each other. Percentiles are
/// estimated by interpolating within the bucket that contains the target rank —
/// the same approach as Prometheus `histogram_quantile`, accurate to the bucket
/// width rather than exact.
#[derive(Clone)]
pub struct Histogram {
    name: String,
    help: String,
    inner: Arc<HistogramInner>,
}

impl Histogram {
    fn new(name: impl Into<String>, help: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            help: help.into(),
            inner: Arc::new(HistogramInner {
                buckets: std::array::from_fn(|_| AtomicU64::new(0)),
                count: AtomicU64::new(0),
                sum_scaled: AtomicU64::new(0),
            }),
        }
    }

    /// Index of the bucket a value falls into.
    fn bucket_of(value: f64) -> usize {
        // NaN would compare false against every bound; treat it as overflow rather
        // than silently landing in bucket 0 and skewing low percentiles.
        if value.is_nan() {
            return HISTOGRAM_BUCKETS - 1;
        }
        for (i, bound) in HISTOGRAM_BOUNDS.iter().enumerate() {
            if value <= *bound {
                return i;
            }
        }
        HISTOGRAM_BUCKETS - 1
    }

    /// Record a single observation. Wait-free: two relaxed atomic adds.
    pub fn observe(&self, value: f64) {
        self.inner.buckets[Self::bucket_of(value)].fetch_add(1, Ordering::Relaxed);
        self.inner.count.fetch_add(1, Ordering::Relaxed);
        // Negative values would wrap the unsigned accumulator; clamp at zero. A
        // duration is never negative, and a bogus one must not corrupt the sum.
        let scaled = (value.max(0.0) * SUM_SCALE) as u64;
        self.inner.sum_scaled.fetch_add(scaled, Ordering::Relaxed);
    }

    /// Estimate the given percentile (0.0 – 100.0) over all observations.
    ///
    /// Returns `None` if nothing has been recorded. The result is interpolated
    /// within the containing bucket, so it is an estimate bounded by that bucket's
    /// width — not an exact order statistic.
    pub fn percentile(&self, p: f64) -> Option<f64> {
        let total = self.inner.count.load(Ordering::Relaxed);
        if total == 0 {
            return None;
        }
        let counts: [u64; HISTOGRAM_BUCKETS] =
            std::array::from_fn(|i| self.inner.buckets[i].load(Ordering::Relaxed));

        // Rank of the target observation, 0-based, matching the previous
        // implementation's indexing so callers see comparable values.
        let target = ((p.clamp(0.0, 100.0) / 100.0) * (total as f64 - 1.0)).round() as u64;

        let mut cumulative = 0u64;
        for (i, &c) in counts.iter().enumerate() {
            if c == 0 {
                continue;
            }
            if cumulative + c > target {
                let lower = if i == 0 { 0.0 } else { HISTOGRAM_BOUNDS[i - 1] };
                // Overflow bucket is unbounded above; report its lower edge, the
                // only defensible value without retaining raw samples.
                let upper = match HISTOGRAM_BOUNDS.get(i) {
                    Some(&u) => u,
                    None => return Some(lower),
                };
                // Linear interpolation across the bucket by position within it.
                let within = (target - cumulative) as f64 / c as f64;
                return Some(lower + (upper - lower) * within);
            }
            cumulative += c;
        }
        // Unreachable while count > 0, but degrade to the top bound rather than
        // panicking if a concurrent update makes the walk fall through.
        Some(*HISTOGRAM_BOUNDS.last().unwrap_or(&0.0))
    }

    /// Number of observations.
    pub fn count(&self) -> usize {
        self.inner.count.load(Ordering::Relaxed) as usize
    }

    /// Sum of all observations.
    pub fn sum(&self) -> f64 {
        self.inner.sum_scaled.load(Ordering::Relaxed) as f64 / SUM_SCALE
    }

    /// Cumulative bucket counts as `(upper_bound, cumulative_count)` pairs, with
    /// `f64::INFINITY` for the overflow bucket. This is the real Prometheus
    /// histogram representation, exposed so `/metrics` can emit `_bucket` lines
    /// instead of only summary quantiles.
    pub fn buckets(&self) -> Vec<(f64, u64)> {
        let mut out = Vec::with_capacity(HISTOGRAM_BUCKETS);
        let mut cumulative = 0u64;
        for i in 0..HISTOGRAM_BUCKETS {
            cumulative += self.inner.buckets[i].load(Ordering::Relaxed);
            let bound = HISTOGRAM_BOUNDS.get(i).copied().unwrap_or(f64::INFINITY);
            out.push((bound, cumulative));
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Snapshot
// ---------------------------------------------------------------------------

/// A single line in a [`MetricsSnapshot`].
#[derive(Debug, Clone)]
pub struct MetricLine {
    pub name: String,
    pub kind: &'static str,
    pub help: String,
    /// Serialised value, e.g. `"42"`, `"3.14"`.
    pub value: String,
    pub labels: HashMap<String, String>,
}

/// A point-in-time snapshot of all registered metrics.
pub type MetricsSnapshot = Vec<MetricLine>;

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Registry that owns a set of named metrics and can produce snapshots.
pub struct MetricsRegistry {
    counters: Mutex<Vec<Counter>>,
    gauges: Mutex<Vec<Gauge>>,
    histograms: Mutex<Vec<Histogram>>,
}

/// Lock a registry list, recovering it if a panic poisoned the mutex.
///
/// Every critical section here is a plain `push` or read, so a poisoned list is
/// still whole. Refusing it would turn one panic into a `/metrics` endpoint that
/// panics on every scrape — the moment the counters matter most.
fn locked<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self {
            counters: Mutex::new(Vec::new()),
            gauges: Mutex::new(Vec::new()),
            histograms: Mutex::new(Vec::new()),
        }
    }

    /// Register and return a new counter.
    pub fn register_counter(&self, name: impl Into<String>, help: impl Into<String>) -> Counter {
        let c = Counter::new(name, help);
        locked(&self.counters).push(c.clone());
        c
    }

    /// Register and return a new gauge.
    pub fn register_gauge(&self, name: impl Into<String>, help: impl Into<String>) -> Gauge {
        let g = Gauge::new(name, help);
        locked(&self.gauges).push(g.clone());
        g
    }

    /// Register and return a new histogram.
    pub fn register_histogram(
        &self,
        name: impl Into<String>,
        help: impl Into<String>,
    ) -> Histogram {
        let h = Histogram::new(name, help);
        locked(&self.histograms).push(h.clone());
        h
    }

    /// Take a snapshot of every registered metric.
    pub fn snapshot(&self) -> MetricsSnapshot {
        let mut lines = Vec::new();

        for c in locked(&self.counters).iter() {
            lines.push(MetricLine {
                name: c.name.clone(),
                kind: "counter",
                help: c.help.clone(),
                value: c.get().to_string(),
                labels: HashMap::new(),
            });
        }

        for g in locked(&self.gauges).iter() {
            lines.push(MetricLine {
                name: g.name.clone(),
                kind: "gauge",
                help: g.help.clone(),
                value: g.get().to_string(),
                labels: HashMap::new(),
            });
        }

        for h in locked(&self.histograms).iter() {
            let count = h.count();
            let sum = h.sum();
            let p50 = h.percentile(50.0).unwrap_or(0.0);
            let p90 = h.percentile(90.0).unwrap_or(0.0);
            let p99 = h.percentile(99.0).unwrap_or(0.0);

            // Emit a summary-style entry per quantile.
            for (q_label, q_val) in &[("0.5", p50), ("0.9", p90), ("0.99", p99)] {
                let mut labels = HashMap::new();
                labels.insert("quantile".to_owned(), q_label.to_string());
                lines.push(MetricLine {
                    name: format!("{}_summary", h.name),
                    kind: "summary",
                    help: h.help.clone(),
                    value: format!("{:.4}", q_val),
                    labels,
                });
            }

            // Emit real cumulative buckets alongside the summary quantiles. The
            // quantiles above are computed per-process and cannot be averaged
            // across nodes; `_bucket` lines let Prometheus derive correct
            // fleet-wide quantiles with histogram_quantile().
            for (bound, cumulative) in h.buckets() {
                let mut labels = HashMap::new();
                labels.insert(
                    "le".to_owned(),
                    if bound.is_infinite() {
                        "+Inf".to_owned()
                    } else {
                        format!("{bound}")
                    },
                );
                lines.push(MetricLine {
                    name: format!("{}_bucket", h.name),
                    kind: "histogram",
                    help: h.help.clone(),
                    value: cumulative.to_string(),
                    labels,
                });
            }

            // Also emit _count and _sum.
            lines.push(MetricLine {
                name: format!("{}_count", h.name),
                kind: "counter",
                help: format!("{} (count)", h.help),
                value: count.to_string(),
                labels: HashMap::new(),
            });
            lines.push(MetricLine {
                name: format!("{}_sum", h.name),
                kind: "counter",
                help: format!("{} (sum)", h.help),
                value: format!("{:.4}", sum),
                labels: HashMap::new(),
            });
        }

        lines
    }

    /// Render Prometheus text exposition format.
    pub fn prometheus_text(&self) -> String {
        let mut out = String::new();
        let snap = self.snapshot();

        // Group by base metric name for HELP / TYPE headers.
        // For simplicity we emit a header for each line (prometheus allows it).
        for line in &snap {
            out.push_str(&format!("# HELP {} {}\n", line.name, line.help));
            out.push_str(&format!("# TYPE {} {}\n", line.name, line.kind));
            if line.labels.is_empty() {
                out.push_str(&format!("{} {}\n", line.name, line.value));
            } else {
                let label_str = line
                    .labels
                    .iter()
                    .map(|(k, v)| format!("{}=\"{}\"", k, v))
                    .collect::<Vec<_>>()
                    .join(",");
                out.push_str(&format!("{}{{{}}} {}\n", line.name, label_str, line.value));
            }
        }

        out
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// WAF-specific global metrics
// ---------------------------------------------------------------------------

struct WafMetrics {
    pub requests_total: Counter,
    pub blocked_total: Counter,
    pub request_duration_ms: Histogram,
    pub active_connections: Gauge,
    pub rule_hits_total: Counter,
    pub ebpf_drops_total: Counter,
    /// Connections rejected at accept because the global connection limit was
    /// saturated (admission control — see `sentinel_proxy` accept loops).
    pub load_shed_connections_total: Counter,
    /// Requests shed with 503 because the global in-flight request limit was
    /// saturated (admission control — bounds HTTP/2 & HTTP/3 stream fan-out).
    pub load_shed_requests_total: Counter,
    /// Notable WAF events (blocks / learning-mode DETECTs) that were NOT recorded
    /// because the in-memory history buffer was full.
    ///
    /// Unlike the two counters above, this sheds an AUDIT RECORD rather than a
    /// request: the request itself was still inspected and still enforced. Under a
    /// sustained flood every blocked request wants an event row, so the buffer's
    /// 20k cap is reached and the surplus is dropped to protect memory — correct,
    /// but it means "events in ClickHouse" understates "attacks blocked" exactly
    /// when the gap matters most. Non-zero here invalidates any attempt to count
    /// attacks from `waf_events` for that window.
    pub history_shed_total: Counter,
    pub log_lines_dropped_total: Counter,

    // ---- Module reachability -------------------------------------------------
    //
    // Seven module subsystems (bot_detect, jwt_auth, graphql, grpc, smuggling,
    // threat_intel, tls_fingerprint) contained ZERO log statements of any level —
    // ~4,200 lines of security code that could not report its own state. They
    // cannot simply be given log lines: every one of their entry points is a pure
    // function called ONCE PER REQUEST on attacker-controlled input, so an
    // info!/warn! there is both a throughput problem and a log-flood primitive.
    //
    // A counter is the correct production-visible surface for that shape. Each of
    // these answers exactly one question that was previously unanswerable: "did
    // this control actually run?" — as distinct from "did it find anything?".
    // `configured > 0` alongside `inspected == 0` after real traffic is the only
    // way an endpoint-matching or transport mismatch is discoverable at all.
    /// Requests on which desync detection actually ran. Distinguishes "ran and
    /// found nothing" from "never called" — which is not academic: a phase-1 gate
    /// bug meant an over-long URI skipped this check entirely.
    pub smuggling_evaluated_total: Counter,
    /// Desync rejections, split so the framing detections can be told apart from
    /// the header-byte tripwire. Answers "are all of our smuggling blocks
    /// actually one false positive?" without a per-request log line.
    pub smuggling_rejected_framing_total: Counter,
    pub smuggling_rejected_header_total: Counter,
    /// Bodies the GraphQL firewall actually inspected, and blocked. The endpoint
    /// gate is a case-sensitive `contains("graphql")` on POST only, so a site
    /// serving `/GraphQL` or using GET is silently never inspected.
    pub graphql_inspected_total: Counter,
    pub graphql_blocked_total: Counter,
    /// Bodies the gRPC firewall actually inspected, gated on a Content-Type
    /// match; a transport or content-type mismatch shows up here as a zero.
    pub grpc_inspected_total: Counter,
    /// JA4 fingerprinting attempts vs successes. The ratio is the coverage number
    /// nobody could compute: a None fingerprint silently disables every
    /// JA4-dependent control downstream, and HTTP/3 supplies none at all.
    pub ja4_attempts_total: Counter,
    pub ja4_success_total: Counter,
    /// WASM plugin execution. A plugin runs arbitrary operator-supplied code in
    /// the request path, and until 2026-09-07 nothing counted it: its cost and
    /// its failure rate were visible only as log lines, so a plugin degrading
    /// slowly or trapping on a fraction of requests would not show anywhere.
    ///
    /// `traps` is the one that matters most: a trap FAILS OPEN — the request is
    /// allowed — so a plugin that traps on every call is indistinguishable from
    /// one that never blocks anything.
    pub plugin_invocations_total: Counter,
    pub plugin_blocks_total: Counter,
    pub plugin_scores_total: Counter,
    pub plugin_traps_total: Counter,
    /// Connections that never presented a TLS handshake record at all — TCP
    /// probes, port scans, abandoned connections. Kept OUT of
    /// `ja4_attempts_total` so `success / attempts` is real coverage rather than
    /// a number dominated by traffic that was never a TLS client.
    pub ja4_no_hello_total: Counter,
    /// HTTP/3 (QUIC) fingerprinting, counted SEPARATELY from the TCP path.
    ///
    /// Deliberately not folded into the TCP counters: a blind spot in one
    /// transport would otherwise hide behind healthy coverage in the other, and
    /// h3 was blind for its entire existence while TCP looked fine.
    pub ja4_h3_attempts_total: Counter,
    pub ja4_h3_success_total: Counter,
    /// h3 connections that completed a handshake and yielded no fingerprint —
    /// including the case where the decorator is not installed at all.
    pub ja4_h3_absent_total: Counter,
    /// Requests granted the good-bot allowlist — i.e. a crawler claim that was
    /// VERIFIED by reverse DNS (PTR in the operator's published domain,
    /// forward-confirmed) and therefore scored 0.
    ///
    /// It used to count unauthenticated trust, because the User-Agent alone was
    /// enough. Now the grant is impossible without verification, so this is the
    /// number of crawlers actually proven — and from an address that cannot
    /// verify, it must stay 0.
    pub bot_good_bot_allowed_total: Counter,
    /// Panics anywhere in the process, counted by the panic hook. Release builds
    /// aborted on the first one until 2026-10; now a panic is contained to the
    /// request or background loop it happened in, which is exactly why it needs
    /// a number — a contained panic is otherwise invisible from outside.
    pub panics_total: Counter,
    /// Requests answered 500 because their processing panicked. Never forwarded.
    pub request_panics_total: Counter,
    /// Background loops (control-plane sync, ClickHouse writer, listeners, ...)
    /// restarted after a panic. Climbing steadily means one is crash-looping.
    pub task_restarts_total: Counter,

    pub registry: MetricsRegistry,
}

impl WafMetrics {
    fn new() -> Self {
        let registry = MetricsRegistry::new();
        let requests_total = registry.register_counter(
            "sentinel_requests_total",
            "Total number of HTTP requests processed",
        );
        let blocked_total = registry.register_counter(
            "sentinel_blocked_total",
            "Total number of HTTP requests blocked by WAF rules",
        );
        let request_duration_ms = registry.register_histogram(
            "sentinel_request_duration_ms",
            "HTTP request processing time in milliseconds",
        );
        let active_connections = registry.register_gauge(
            "sentinel_active_connections",
            "Current number of active proxy connections",
        );
        let rule_hits_total = registry.register_counter(
            "sentinel_rule_hits_total",
            "Total number of WAF rule match events",
        );
        let ebpf_drops_total = registry.register_counter(
            "sentinel_ebpf_drops_total",
            "Total number of packets dropped at the kernel XDP layer",
        );
        let load_shed_connections_total = registry.register_counter(
            "sentinel_load_shed_connections_total",
            "Total number of connections rejected at accept due to the connection limit",
        );
        let load_shed_requests_total = registry.register_counter(
            "sentinel_load_shed_requests_total",
            "Total number of requests shed with 503 due to the in-flight request limit",
        );
        let history_shed_total = registry.register_counter(
            "sentinel_history_shed_total",
            "Total number of WAF events not recorded because the history buffer was full",
        );
        let log_lines_dropped_total = registry.register_counter(
            "sentinel_log_lines_dropped_total",
            "Total number of NDJSON access/waf log lines dropped because the writer queue was full",
        );

        let smuggling_evaluated_total = registry.register_counter(
            "sentinel_smuggling_evaluated_total",
            "Requests on which HTTP desync detection actually ran (distinguishes ran-and-clean from never-called)",
        );
        let smuggling_rejected_framing_total = registry.register_counter(
            "sentinel_smuggling_rejected_framing_total",
            "Desync rejections from Content-Length / Transfer-Encoding framing checks",
        );
        let smuggling_rejected_header_total = registry.register_counter(
            "sentinel_smuggling_rejected_header_total",
            "Desync rejections from the header-byte tripwire (CR/LF or NUL in a header value)",
        );
        let graphql_inspected_total = registry.register_counter(
            "sentinel_graphql_inspected_total",
            "Request bodies the GraphQL firewall actually inspected",
        );
        let graphql_blocked_total = registry.register_counter(
            "sentinel_graphql_blocked_total",
            "Request bodies the GraphQL firewall rejected on depth / complexity / introspection",
        );
        let grpc_inspected_total = registry.register_counter(
            "sentinel_grpc_inspected_total",
            "Request bodies the gRPC firewall actually inspected",
        );
        let ja4_attempts_total = registry.register_counter(
            "sentinel_ja4_attempts_total",
            "TLS ClientHello peeks attempted for JA4 fingerprinting",
        );
        let ja4_success_total = registry.register_counter(
            "sentinel_ja4_success_total",
            "TLS ClientHello peeks that yielded a JA4 fingerprint (attempts minus this is silent JA4 coverage loss)",
        );
        let plugin_invocations_total = registry.register_counter(
            "sentinel_plugin_invocations_total",
            "WASM plugin evaluations executed in the request path",
        );
        let plugin_blocks_total = registry.register_counter(
            "sentinel_plugin_blocks_total",
            "Requests a WASM plugin blocked or challenged",
        );
        let plugin_scores_total = registry.register_counter(
            "sentinel_plugin_scores_total",
            "Evaluations where a WASM plugin contributed to the anomaly score",
        );
        let plugin_traps_total = registry.register_counter(
            "sentinel_plugin_traps_total",
            "WASM plugin evaluations that failed (trap, fuel exhaustion, instantiation) and therefore FAILED OPEN",
        );
        let ja4_no_hello_total = registry.register_counter(
            "sentinel_ja4_no_hello_total",
            "Connections that never sent a TLS handshake record (probes/scans), excluded from ja4_attempts_total",
        );
        let ja4_h3_attempts_total = registry.register_counter(
            "sentinel_ja4_h3_attempts_total",
            "HTTP/3 connections whose TLS session was inspected for a JA4 fingerprint",
        );
        let ja4_h3_success_total = registry.register_counter(
            "sentinel_ja4_h3_success_total",
            "HTTP/3 connections that yielded a JA4 fingerprint",
        );
        let ja4_h3_absent_total = registry.register_counter(
            "sentinel_ja4_h3_absent_total",
            "HTTP/3 connections with no fingerprint (includes the decorator not being installed)",
        );
        let bot_good_bot_allowed_total = registry.register_counter(
            "sentinel_bot_good_bot_allowlisted_total",
            "Requests granted the good-bot allowlist after reverse-DNS verification (PTR in the operator's domain, forward-confirmed)",
        );
        let panics_total = registry.register_counter(
            "sentinel_panics_total",
            "Panics anywhere in the data-plane process; each is logged with its source location",
        );
        let request_panics_total = registry.register_counter(
            "sentinel_request_panics_total",
            "Requests whose processing panicked and were answered 500 without being forwarded",
        );
        let task_restarts_total = registry.register_counter(
            "sentinel_task_restarts_total",
            "Background loops (control-plane sync, ClickHouse writer, listeners) restarted after a panic",
        );

        Self {
            requests_total,
            blocked_total,
            request_duration_ms,
            active_connections,
            rule_hits_total,
            ebpf_drops_total,
            load_shed_connections_total,
            load_shed_requests_total,
            history_shed_total,
            log_lines_dropped_total,
            smuggling_evaluated_total,
            smuggling_rejected_framing_total,
            smuggling_rejected_header_total,
            graphql_inspected_total,
            graphql_blocked_total,
            grpc_inspected_total,
            ja4_attempts_total,
            ja4_success_total,
            plugin_invocations_total,
            plugin_blocks_total,
            plugin_scores_total,
            plugin_traps_total,
            ja4_no_hello_total,
            ja4_h3_attempts_total,
            ja4_h3_success_total,
            ja4_h3_absent_total,
            bot_good_bot_allowed_total,
            panics_total,
            request_panics_total,
            task_restarts_total,
            registry,
        }
    }
}

static WAF_METRICS: Lazy<WafMetrics> = Lazy::new(WafMetrics::new);

// ---------------------------------------------------------------------------
// Public convenience API
// ---------------------------------------------------------------------------

/// Increment the total-requests counter.
pub fn inc_requests() {
    WAF_METRICS.requests_total.inc();
}

/// Increment the blocked-requests counter.
pub fn inc_blocked() {
    WAF_METRICS.blocked_total.inc();
}

/// Record a request-processing duration observation (milliseconds).
pub fn observe_duration(ms: f64) {
    WAF_METRICS.request_duration_ms.observe(ms);
}

/// Set the absolute number of active proxy connections.
pub fn set_active_connections(n: i64) {
    WAF_METRICS.active_connections.set(n);
}

/// Increment the live active-connection gauge (call on connection admission).
pub fn inc_active_connections() {
    WAF_METRICS.active_connections.inc();
}

/// Decrement the live active-connection gauge (call when a connection ends).
pub fn dec_active_connections() {
    WAF_METRICS.active_connections.dec();
}

/// Increment the load-shed counter for a connection rejected at accept because
/// the global connection limit was saturated.
pub fn inc_load_shed_connections() {
    WAF_METRICS.load_shed_connections_total.inc();
}

/// Increment the load-shed counter for a request shed with 503 because the
/// global in-flight request limit was saturated.
pub fn inc_load_shed_requests() {
    WAF_METRICS.load_shed_requests_total.inc();
}

/// Increment the counter of WAF events dropped because the in-memory history
/// buffer was full, and return the new total.
///
/// Returns the total so the caller can log a rate-limited warning without
/// keeping a second counter of its own — a silent shed is the thing this exists
/// to prevent, so it should be visible in logs as well as in `/metrics`.
pub fn inc_history_shed() -> u64 {
    WAF_METRICS.history_shed_total.inc();
    WAF_METRICS.history_shed_total.get()
}

/// Current total of shed history events. Zero means every block/DETECT in this
/// process's lifetime reached the buffer.
pub fn history_shed_total() -> u64 {
    WAF_METRICS.history_shed_total.get()
}

// ---- Module reachability counters ------------------------------------------
//
// One increment/read pair per question, in the `history_shed_total` mould. Each
// increment site sits INSIDE the branch that was already taken, so none of these
// adds work to a request that was not already doing it.
//
// Read them as ratios and as zeroes, not as totals: `graphql_inspected_total`
// stuck at 0 while a site has GraphQL configured is the finding, and
// `ja4_success_total / ja4_attempts_total` is fingerprint coverage.

/// Desync detection ran on one request.
pub fn note_smuggling_evaluated() {
    WAF_METRICS.smuggling_evaluated_total.inc();
}
pub fn smuggling_evaluated_total() -> u64 {
    WAF_METRICS.smuggling_evaluated_total.get()
}

/// A desync rejection from the CL/TE framing checks — the real primitive.
pub fn note_smuggling_rejected_framing() {
    WAF_METRICS.smuggling_rejected_framing_total.inc();
}
pub fn smuggling_rejected_framing_total() -> u64 {
    WAF_METRICS.smuggling_rejected_framing_total.get()
}

/// A desync rejection from the header-byte tripwire.
pub fn note_smuggling_rejected_header() {
    WAF_METRICS.smuggling_rejected_header_total.inc();
}
pub fn smuggling_rejected_header_total() -> u64 {
    WAF_METRICS.smuggling_rejected_header_total.get()
}

/// The GraphQL firewall inspected one body.
pub fn note_graphql_inspected() {
    WAF_METRICS.graphql_inspected_total.inc();
}
pub fn graphql_inspected_total() -> u64 {
    WAF_METRICS.graphql_inspected_total.get()
}

/// The GraphQL firewall rejected one body.
pub fn note_graphql_blocked() {
    WAF_METRICS.graphql_blocked_total.inc();
}
pub fn graphql_blocked_total() -> u64 {
    WAF_METRICS.graphql_blocked_total.get()
}

/// The gRPC firewall inspected one body.
pub fn note_grpc_inspected() {
    WAF_METRICS.grpc_inspected_total.inc();
}
pub fn grpc_inspected_total() -> u64 {
    WAF_METRICS.grpc_inspected_total.get()
}

/// One WASM plugin evaluation ran. Counted per (plugin, request) pair, so a
/// site selecting three plugins produces three invocations per request.
pub fn note_plugin_invocation() {
    WAF_METRICS.plugin_invocations_total.inc();
}
pub fn plugin_invocations_total() -> u64 {
    WAF_METRICS.plugin_invocations_total.get()
}

/// A plugin set a Block or Challenge decision.
pub fn note_plugin_block() {
    WAF_METRICS.plugin_blocks_total.inc();
}
pub fn plugin_blocks_total() -> u64 {
    WAF_METRICS.plugin_blocks_total.get()
}

/// A plugin added to the anomaly score without deciding on its own.
pub fn note_plugin_score() {
    WAF_METRICS.plugin_scores_total.inc();
}
pub fn plugin_scores_total() -> u64 {
    WAF_METRICS.plugin_scores_total.get()
}

/// A plugin evaluation FAILED — trap, fuel exhaustion, instantiation error.
/// The request is allowed when this happens, so a non-zero rate here means a
/// control that looks enabled is not judging traffic.
pub fn note_plugin_trap() {
    WAF_METRICS.plugin_traps_total.inc();
}
pub fn plugin_traps_total() -> u64 {
    WAF_METRICS.plugin_traps_total.get()
}

/// A JA4 fingerprint was attempted, and whether it produced one. Call the
/// attempt unconditionally at the peek site and the success only on `Some`, so
/// the difference is real coverage loss rather than an absent code path.
pub fn note_ja4_attempt() {
    WAF_METRICS.ja4_attempts_total.inc();
}
pub fn note_ja4_success() {
    WAF_METRICS.ja4_success_total.inc();
}
pub fn ja4_attempts_total() -> u64 {
    WAF_METRICS.ja4_attempts_total.get()
}
pub fn ja4_success_total() -> u64 {
    WAF_METRICS.ja4_success_total.get()
}

/// A connection that never spoke TLS. Not a fingerprinting failure.
pub fn note_ja4_no_hello() {
    WAF_METRICS.ja4_no_hello_total.inc();
}
pub fn ja4_no_hello_total() -> u64 {
    WAF_METRICS.ja4_no_hello_total.get()
}

/// One h3 connection inspected for a fingerprint, and whether it produced one.
/// Always increments `attempts`; `success` or `absent` in addition.
pub fn note_ja4_h3(success: bool) {
    WAF_METRICS.ja4_h3_attempts_total.inc();
    if success {
        WAF_METRICS.ja4_h3_success_total.inc();
    } else {
        WAF_METRICS.ja4_h3_absent_total.inc();
    }
}
pub fn ja4_h3_attempts_total() -> u64 {
    WAF_METRICS.ja4_h3_attempts_total.get()
}
pub fn ja4_h3_success_total() -> u64 {
    WAF_METRICS.ja4_h3_success_total.get()
}
pub fn ja4_h3_absent_total() -> u64 {
    WAF_METRICS.ja4_h3_absent_total.get()
}

/// The good-bot allowlist was granted — only reachable for a VERIFIED claim.
pub fn note_good_bot_allowed() {
    WAF_METRICS.bot_good_bot_allowed_total.inc();
}
pub fn bot_good_bot_allowed_total() -> u64 {
    WAF_METRICS.bot_good_bot_allowed_total.get()
}

/// Record one NDJSON log line dropped because the writer queue was full, and
/// return the new total.
///
/// ClickHouse shedding has always been scrapeable (`sentinel_history_shed_total`)
/// but access/waf log loss was reported only through a rate-limited `warn!`, so
/// it could not be alerted on — and log loss under load is precisely when
/// someone is relying on the logs. Same shape as inc_history_shed: returns the
/// total so the caller needs no counter of its own.
pub fn inc_log_lines_dropped() -> u64 {
    WAF_METRICS.log_lines_dropped_total.inc();
    WAF_METRICS.log_lines_dropped_total.get()
}

/// Current total of dropped NDJSON log lines. Zero means every access/waf line
/// this process produced reached its file.
pub fn log_lines_dropped_total() -> u64 {
    WAF_METRICS.log_lines_dropped_total.get()
}

// ---- Panic containment ------------------------------------------------------

/// A panic happened somewhere in the process. Called by the panic hook only.
pub fn note_panic() {
    WAF_METRICS.panics_total.inc();
}
pub fn panics_total() -> u64 {
    WAF_METRICS.panics_total.get()
}

/// A request's processing panicked and it was answered 500 instead.
pub fn note_request_panic() {
    WAF_METRICS.request_panics_total.inc();
}
pub fn request_panics_total() -> u64 {
    WAF_METRICS.request_panics_total.get()
}

/// A supervised background loop panicked and is being restarted. Returns the
/// new total so the caller can put it on its log line.
pub fn note_task_restart() -> u64 {
    WAF_METRICS.task_restarts_total.inc();
    WAF_METRICS.task_restarts_total.get()
}
pub fn task_restarts_total() -> u64 {
    WAF_METRICS.task_restarts_total.get()
}

/// Increment the rule-hits counter.
pub fn inc_rule_hits() {
    WAF_METRICS.rule_hits_total.inc();
}

/// Increment the eBPF/XDP packet-drop counter.
pub fn inc_ebpf_drops() {
    WAF_METRICS.ebpf_drops_total.inc();
}

/// Render the global WAF metrics in Prometheus text exposition format.
pub fn prometheus_text() -> String {
    WAF_METRICS.registry.prometheus_text()
}

/// Return a snapshot of all global WAF metrics.
pub fn snapshot() -> MetricsSnapshot {
    WAF_METRICS.registry.snapshot()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_increments() {
        let r = MetricsRegistry::new();
        let c = r.register_counter("test_counter", "a test counter");
        c.inc();
        c.inc_by(4);
        assert_eq!(c.get(), 5);
    }

    #[test]
    fn gauge_set_inc_dec() {
        let r = MetricsRegistry::new();
        let g = r.register_gauge("test_gauge", "a test gauge");
        g.set(10);
        g.inc();
        g.dec();
        assert_eq!(g.get(), 10);
    }

    #[test]
    fn histogram_percentile() {
        let r = MetricsRegistry::new();
        let h = r.register_histogram("test_hist", "a test histogram");
        for i in 1..=100 {
            h.observe(i as f64);
        }
        let p50 = h.percentile(50.0).unwrap();
        assert!((p50 - 50.0).abs() < 2.0);
        assert_eq!(h.count(), 100);
    }

    #[test]
    fn prometheus_text_format() {
        let r = MetricsRegistry::new();
        let c = r.register_counter("http_reqs", "total http requests");
        c.inc();
        let text = r.prometheus_text();
        assert!(text.contains("# HELP http_reqs"));
        assert!(text.contains("# TYPE http_reqs counter"));
        assert!(text.contains("http_reqs 1"));
    }

    /// A panic while a registry list is locked poisons it. `/metrics` used to
    /// `expect` on every lock, so from then on every scrape panicked too — the
    /// node's counters went dark right after the event they should have shown.
    #[test]
    fn a_poisoned_registry_still_scrapes_and_registers() {
        let r = std::sync::Arc::new(MetricsRegistry::new());
        r.register_counter("before_poison", "registered before the panic")
            .inc();
        let poisoner = std::sync::Arc::clone(&r);
        let _ = std::thread::spawn(move || {
            let _held = poisoner.counters.lock().unwrap();
            panic!("poisoning the counters list on purpose");
        })
        .join();
        assert!(r.counters.is_poisoned(), "fixture must poison the lock");

        r.register_counter("after_poison", "registered after the panic")
            .inc_by(2);
        let text = r.prometheus_text();
        assert!(text.contains("before_poison 1"), "{text}");
        assert!(text.contains("after_poison 2"), "{text}");
    }

    #[test]
    fn global_api_smoke() {
        inc_requests();
        inc_blocked();
        observe_duration(12.5);
        set_active_connections(42);
        inc_rule_hits();
        inc_ebpf_drops();
        let text = prometheus_text();
        assert!(text.contains("sentinel_requests_total"));
        assert!(text.contains("sentinel_blocked_total"));
    }

    #[test]
    fn load_shed_counters_exposed() {
        inc_load_shed_connections();
        inc_load_shed_requests();
        inc_active_connections();
        dec_active_connections();
        let text = prometheus_text();
        assert!(text.contains("sentinel_load_shed_connections_total"));
        assert!(text.contains("sentinel_load_shed_requests_total"));
        assert!(text.contains("sentinel_active_connections"));
    }

    #[test]
    fn history_shed_counter_is_exposed_and_monotonic() {
        // The counter is global and other tests in this binary may have bumped it,
        // so assert on the DELTA rather than an absolute value.
        let before = history_shed_total();
        let a = inc_history_shed();
        let b = inc_history_shed();
        assert_eq!(a, before + 1, "inc must return the new total");
        assert_eq!(b, before + 2, "counter must be monotonic");
        assert_eq!(history_shed_total(), before + 2);
        let text = prometheus_text();
        assert!(text.contains("sentinel_history_shed_total"));
        assert!(text.contains("# TYPE sentinel_history_shed_total counter"));
    }

    // ── Lock-free histogram ────────────────────────────────────────────────

    #[test]
    fn histogram_memory_is_constant_regardless_of_volume() {
        // The property the old Mutex<Vec<f64>> implementation lacked: it retained
        // every observation forever, so memory grew with total requests served.
        let r = MetricsRegistry::new();
        let h = r.register_histogram("mem", "constant memory");
        let before = std::mem::size_of_val(&*h.inner);
        for i in 0..500_000 {
            h.observe((i % 1000) as f64);
        }
        assert_eq!(h.count(), 500_000);
        assert_eq!(
            std::mem::size_of_val(&*h.inner),
            before,
            "histogram allocated per observation — the leak is back"
        );
    }

    #[test]
    fn histogram_percentiles_are_monotonic_and_bounded() {
        let r = MetricsRegistry::new();
        let h = r.register_histogram("p", "percentiles");
        for i in 1..=1000 {
            h.observe(i as f64 / 10.0); // 0.1 .. 100.0
        }
        let p50 = h.percentile(50.0).unwrap();
        let p90 = h.percentile(90.0).unwrap();
        let p99 = h.percentile(99.0).unwrap();
        assert!(
            p50 <= p90 && p90 <= p99,
            "percentiles not monotonic: {p50} {p90} {p99}"
        );
        // Estimates are bucket-bounded, so assert the containing bucket rather
        // than an exact order statistic.
        assert!((25.0..=50.0).contains(&p50), "p50 {p50} outside its bucket");
        assert!(
            (50.0..=100.0).contains(&p90),
            "p90 {p90} outside its bucket"
        );
        assert!(
            (50.0..=100.0).contains(&p99),
            "p99 {p99} outside its bucket"
        );
    }

    #[test]
    fn histogram_empty_and_edges() {
        let r = MetricsRegistry::new();
        let h = r.register_histogram("edges", "edges");
        assert_eq!(h.percentile(50.0), None, "empty histogram must report None");
        assert_eq!(h.count(), 0);
        assert_eq!(h.sum(), 0.0);

        // Values beyond the top bound land in the overflow bucket and must not
        // panic or be reported below it.
        h.observe(1_000_000.0);
        assert_eq!(h.count(), 1);
        assert!(h.percentile(99.0).unwrap() >= 30_000.0);

        // NaN must not be treated as the smallest value (which would drag low
        // percentiles down); it is counted as overflow.
        h.observe(f64::NAN);
        assert_eq!(h.count(), 2);
        assert!(h.percentile(50.0).unwrap() >= 30_000.0);
    }

    #[test]
    fn histogram_sum_tracks_observations() {
        let r = MetricsRegistry::new();
        let h = r.register_histogram("sum", "sum");
        for _ in 0..1000 {
            h.observe(1.5);
        }
        assert!((h.sum() - 1500.0).abs() < 1.0, "sum = {}", h.sum());

        // A negative observation must not wrap the unsigned accumulator.
        h.observe(-5.0);
        assert!(
            h.sum() >= 1499.0,
            "negative value corrupted the sum: {}",
            h.sum()
        );
    }

    #[test]
    fn histogram_buckets_are_cumulative_and_exposed() {
        let r = MetricsRegistry::new();
        let h = r.register_histogram("hist_buckets", "buckets");
        for v in [0.4, 0.9, 3.0, 40.0, 90_000.0] {
            h.observe(v);
        }
        let buckets = h.buckets();
        // Cumulative counts must be non-decreasing and end at the total.
        let mut prev = 0u64;
        for (_, c) in &buckets {
            assert!(*c >= prev, "bucket counts not cumulative");
            prev = *c;
        }
        assert_eq!(prev, 5, "final cumulative bucket must equal total count");
        assert!(
            buckets.last().unwrap().0.is_infinite(),
            "missing +Inf bucket"
        );

        let text = r.prometheus_text();
        assert!(
            text.contains("hist_buckets_bucket"),
            "no _bucket lines emitted"
        );
        assert!(text.contains(r#"le="+Inf""#), "no +Inf bucket line");
    }

    #[test]
    fn histogram_observe_is_thread_safe_without_a_lock() {
        // Concurrent recording from many threads must not lose or double-count.
        // This is the access pattern that previously serialized on one mutex.
        let r = MetricsRegistry::new();
        let h = r.register_histogram("concurrent", "concurrent");
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let h = h.clone();
                std::thread::spawn(move || {
                    for i in 0..10_000 {
                        h.observe((i % 100) as f64);
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().expect("worker panicked");
        }
        assert_eq!(h.count(), 80_000);
        assert_eq!(
            h.buckets().last().unwrap().1,
            80_000,
            "bucket counts disagree with total — lost updates"
        );
    }
}
