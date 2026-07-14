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
        Arc, Mutex,
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

/// A histogram that records `f64` samples and can compute percentiles.
#[derive(Clone)]
pub struct Histogram {
    name: String,
    help: String,
    samples: Arc<Mutex<Vec<f64>>>,
}

impl Histogram {
    fn new(name: impl Into<String>, help: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            help: help.into(),
            samples: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Record a single observation.
    pub fn observe(&self, value: f64) {
        let mut s = self.samples.lock().expect("histogram poisoned");
        s.push(value);
    }

    /// Compute the given percentile (0.0 – 100.0) over all observed samples.
    /// Returns `None` if no samples have been recorded.
    pub fn percentile(&self, p: f64) -> Option<f64> {
        let mut s = self.samples.lock().expect("histogram poisoned");
        if s.is_empty() {
            return None;
        }
        s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let idx = ((p / 100.0) * (s.len() as f64 - 1.0)).round() as usize;
        Some(s[idx])
    }

    /// Number of observations.
    pub fn count(&self) -> usize {
        self.samples.lock().expect("histogram poisoned").len()
    }

    /// Sum of all observations.
    pub fn sum(&self) -> f64 {
        self.samples
            .lock()
            .expect("histogram poisoned")
            .iter()
            .sum()
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
        self.counters
            .lock()
            .expect("counters poisoned")
            .push(c.clone());
        c
    }

    /// Register and return a new gauge.
    pub fn register_gauge(&self, name: impl Into<String>, help: impl Into<String>) -> Gauge {
        let g = Gauge::new(name, help);
        self.gauges.lock().expect("gauges poisoned").push(g.clone());
        g
    }

    /// Register and return a new histogram.
    pub fn register_histogram(
        &self,
        name: impl Into<String>,
        help: impl Into<String>,
    ) -> Histogram {
        let h = Histogram::new(name, help);
        self.histograms
            .lock()
            .expect("histograms poisoned")
            .push(h.clone());
        h
    }

    /// Take a snapshot of every registered metric.
    pub fn snapshot(&self) -> MetricsSnapshot {
        let mut lines = Vec::new();

        for c in self.counters.lock().expect("counters poisoned").iter() {
            lines.push(MetricLine {
                name: c.name.clone(),
                kind: "counter",
                help: c.help.clone(),
                value: c.get().to_string(),
                labels: HashMap::new(),
            });
        }

        for g in self.gauges.lock().expect("gauges poisoned").iter() {
            lines.push(MetricLine {
                name: g.name.clone(),
                kind: "gauge",
                help: g.help.clone(),
                value: g.get().to_string(),
                labels: HashMap::new(),
            });
        }

        for h in self.histograms.lock().expect("histograms poisoned").iter() {
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

        Self {
            requests_total,
            blocked_total,
            request_duration_ms,
            active_connections,
            rule_hits_total,
            ebpf_drops_total,
            load_shed_connections_total,
            load_shed_requests_total,
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
}
