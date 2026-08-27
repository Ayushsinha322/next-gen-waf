// Package logs provides an SSE fan-out hub that tails NDJSON log files
// produced by the Sentinel data plane and streams new entries to all
// connected dashboard clients.
//
// Log directory: $SENTINEL_LOG_DIR (default /tmp/sentinel-logs).
// One file per kind: access.log, waf.log, error.log, audit.log
// Each file contains one JSON object per line (NDJSON).
package logs

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Source identifies where an Entry came from. It exists so that fabricated data
// can never be mistaken for observed traffic.
//
// Previously Entry carried only Kind and Data, so simulator output travelled the
// exact same path as real data-plane logs and arrived at the dashboard
// indistinguishable from it — nobody looking at a screen could tell whether an
// "attack" had actually happened. Every Entry now declares its provenance, and
// the stream marks it explicitly.
type Source string

const (
	// SourceLive is real, observed data (tailed data-plane logs, real alerts,
	// real audit events). This is the only value ever seen in production.
	SourceLive Source = "live"
	// SourceSimulated is fabricated data from the development simulator. It only
	// exists when SENTINEL_DEV_SIMULATOR=1 is set explicitly.
	SourceSimulated Source = "simulated"
)

// Entry is a single log line emitted to subscribers.
type Entry struct {
	Kind string          `json:"kind"`
	Data json.RawMessage `json:"data"`
	// Source is "live" for observed data and "simulated" for generated data.
	// Empty is treated as "live" by normalize() so no real emitter can
	// accidentally omit it, but simulated data must always set it.
	Source Source `json:"source"`
}

// normalize defaults an unset Source to live. Called on the publish path so
// every Entry that reaches a subscriber carries explicit provenance.
func (e Entry) normalize() Entry {
	if e.Source == "" {
		e.Source = SourceLive
	}
	return e
}

// IsSimulated reports whether this entry is fabricated.
func (e Entry) IsSimulated() bool { return e.Source == SourceSimulated }

// Snapshot holds a point-in-time view of live metrics derived from the
// event stream.  It is safe to read without locking.
type Snapshot struct {
	RPS float64 `json:"rps"`
	// P99LatencyMs is END-TO-END request latency (the data plane's own
	// elapsed_ms, upstream time included), taken as the p99 of the most recent
	// samples read from access.log.
	P99LatencyMs float64 `json:"p99_latency_ms"`
	// P99Samples is how many samples that p99 was computed from. 0 means NO
	// MEASUREMENT, which is not the same as a fast one: the latency ring is fed
	// by tailing access.log from its end, so it is empty after a restart until
	// traffic arrives. Without this the UI could not tell "no data" from
	// "sub-millisecond" and rendered the absence of measurement as the best
	// possible value.
	P99Samples       int   `json:"p99_samples"`
	TotalRequests    int64 `json:"total_requests"`
	BlockedRequests  int64 `json:"blocked_requests"`
	MLAnomalies      int64 `json:"ml_anomalies"`
	ErrorCount       int64 `json:"error_count"`
	EbpfDrops        int64 `json:"ebpf_drops"`
	ConnectedClients int   `json:"connected_clients"`

	// Derived aggregates (all real — computed from the proxy NDJSON stream).
	UniqueBlockedIPs int64 `json:"unique_blocked_ips"`
	Status2xx        int64 `json:"status_2xx"`
	Status3xx        int64 `json:"status_3xx"`
	Status4xx        int64 `json:"status_4xx"`
	Status5xx        int64 `json:"status_5xx"`
	// AttackBreakdown maps an attack category (sqli, xss, rfi_lfi, rce, …) to
	// the number of waf.log events that matched a rule in that category.
	AttackBreakdown map[string]int64 `json:"attack_breakdown"`
	// ByCountry maps an ISO-3166-1 alpha-2 code to blocked-request count.
	// Empty until a GeoIP database is loaded (geoip_loaded=false) — never faked.
	ByCountry   map[string]int64 `json:"by_country"`
	GeoIPLoaded bool             `json:"geoip_loaded"`

	// Host resource usage (Linux /proc/meminfo; zero when unavailable).
	MemUsedBytes  uint64 `json:"mem_used_bytes"`
	MemTotalBytes uint64 `json:"mem_total_bytes"`
}

// SiteStat is a cumulative per-site request/block counter, derived from the
// proxy NDJSON stream (real — not simulated when the data plane is running).
type SiteStat struct {
	Total   int64 `json:"total"`
	Blocked int64 `json:"blocked"`
	S4xx    int64 `json:"status_4xx"`
	S5xx    int64 `json:"status_5xx"`
}

// LearningStat aggregates a single rule's would-have-blocked detections while a
// site runs in WAF Learning mode. Derived from waf.log entries the data plane
// marks with action="DETECT" / would_block=true — these are requests that
// passed through but *would* have been blocked in Blocking mode. This is the
// raw material for the tuning workflow: review what each rule would block,
// then add an exclusion for the false positives before flipping to Blocking.
type LearningStat struct {
	RuleID   string   `json:"rule_id"`
	Category string   `json:"category"`
	Severity string   `json:"severity"`
	Message  string   `json:"message"`
	Count    int64    `json:"count"`
	LastSeen string   `json:"last_seen"`
	Samples  []string `json:"samples"` // up to learningSampleCap distinct request paths
}

// learningSampleCap bounds the number of distinct sample paths retained per
// rule so a noisy rule can't grow the aggregate unboundedly.
const learningSampleCap = 5

// TrafficBucket captures one second of traffic metrics for the history chart.
type TrafficBucket struct {
	TS      int64   `json:"ts"`
	Reqs    int64   `json:"reqs"`
	Blocked int64   `json:"blocked"`
	P99Ms   float64 `json:"p99_ms"`
}

// Hub tails log files and fans entries out to SSE subscribers.
type Hub struct {
	mu   sync.RWMutex
	subs map[chan Entry]struct{}
	buf  []Entry // ring buffer of last 200 entries

	// Paths already being tailed, so per-node discovery never double-tails a
	// file (which would duplicate every line into the stream).
	tailMu sync.Mutex
	tailed map[string]struct{}

	// Metrics counters (atomic — updated on every publish).
	totalRequests   atomic.Int64
	blockedRequests atomic.Int64
	mlAnomalies     atomic.Int64
	errorCount      atomic.Int64
	ebpfDrops       atomic.Int64

	// HTTP status-class counters (from access.log).
	status2xx atomic.Int64
	status3xx atomic.Int64
	status4xx atomic.Int64
	status5xx atomic.Int64

	// Distinct blocked client IPs and per-category attack counts.
	aggMu       sync.Mutex
	blockedIPs  map[string]struct{}
	attackCats  map[string]int64
	byCountry   map[string]int64
	geoipLoaded bool

	// Per-site request/block counters (keyed by the site label in the NDJSON).
	siteStats map[string]*SiteStat

	// Learning-mode would-have-blocked aggregation: site label → rule ID →
	// stat. Guarded by aggMu (same lock as the other waf.log aggregates).
	learnStats map[string]map[string]*LearningStat

	// Host memory (sampled from /proc/meminfo).
	memUsed  atomic.Uint64
	memTotal atomic.Uint64

	// Rolling window for RPS: timestamps of recent access events.
	rpsMu   sync.Mutex
	rpsWin  []time.Time
	rpsLock sync.Mutex

	// Latency ring for p99 (last 1000 values from access logs).
	latMu  sync.Mutex
	latBuf []float64

	// Per-second traffic history (last 120 buckets = 2 minutes).
	histMu  sync.RWMutex
	histBuf []TrafficBucket

	done chan struct{}
}

// LogDir returns the log directory from the environment, defaulting to
// /tmp/sentinel-logs.
func LogDir() string {
	if d := os.Getenv("SENTINEL_LOG_DIR"); d != "" {
		return d
	}
	// Real disk, not /tmp (tmpfs/RAM). Mirrors the proxy's resolve_log_dir().
	if home := os.Getenv("HOME"); home != "" {
		return filepath.Join(home, ".local/share/sentinel/logs")
	}
	return "/var/log/sentinel"
}

// NewHub creates a Hub and starts background file tailers for every known
// log kind.
func NewHub() *Hub {
	h := &Hub{
		subs:       make(map[chan Entry]struct{}),
		done:       make(chan struct{}),
		latBuf:     make([]float64, 0, 1000),
		blockedIPs: make(map[string]struct{}),
		attackCats: make(map[string]int64),
		byCountry:  make(map[string]int64),
		siteStats:  make(map[string]*SiteStat),
		learnStats: make(map[string]map[string]*LearningStat),
		tailed:     make(map[string]struct{}),
	}

	dir := LogDir()

	// modsec.log and ml.log are deliberately absent: NOTHING writes them.
	// They were produced only by sentinel-telemetry's EventLogger, which had no
	// callers and was removed in 2026-08. Tailing them cost a goroutine polling a
	// never-existing path every 200ms — per kind, per node directory, so six
	// pointless tailers on a three-node layout — and offered the operator two
	// permanently-empty views in the console's file picker. Re-add a kind only
	// alongside something that writes it.
	kinds := []string{"access", "waf", "error", "audit"}

	// Single-node layout: the data plane writes straight into $SENTINEL_LOG_DIR.
	for _, kind := range kinds {
		h.tailOnce(kind, filepath.Join(dir, kind+".log"))
	}

	// HA layout: each data-plane node writes into its OWN subdirectory
	// ($SENTINEL_LOG_DIR/<node>/access.log). Per-node directories are required,
	// not cosmetic — three nodes appending to one file would each hold an open
	// handle, and the moment one of them rotated access.log the other two would
	// keep writing into the now-renamed file, so two thirds of the traffic would
	// silently stop appearing in the live view.
	//
	// Node directories appear when their container starts, which can be after
	// this process, so rescan rather than globbing once at boot.
	go h.discoverNodeLogs(dir, kinds)

	go h.runBucketSampler()
	go h.runMemSampler()

	return h
}

// tailOnce starts a tail for path unless one is already running for it.
func (h *Hub) tailOnce(kind, path string) {
	h.tailMu.Lock()
	if _, dup := h.tailed[path]; dup {
		h.tailMu.Unlock()
		return
	}
	h.tailed[path] = struct{}{}
	h.tailMu.Unlock()
	h.tailKind(kind, path)
}

// discoverNodeLogs periodically picks up per-node log directories. A tail is
// cheap (one goroutine polling a path that may not exist yet) and tailOnce
// dedupes, so rescanning is safe to repeat forever.
func (h *Hub) discoverNodeLogs(dir string, kinds []string) {
	scan := func() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			for _, kind := range kinds {
				h.tailOnce(kind, filepath.Join(dir, e.Name(), kind+".log"))
			}
		}
	}
	scan()
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-h.done:
			return
		case <-t.C:
			scan()
		}
	}
}

// Subscribe registers a new SSE client and returns its delivery channel.
// The last 200 buffered entries are delivered first.
func (h *Hub) Subscribe() chan Entry {
	ch := make(chan Entry, 64)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	buf := make([]Entry, len(h.buf))
	copy(buf, h.buf)
	h.mu.Unlock()

	go func() {
		for _, e := range buf {
			select {
			case ch <- e:
			default:
			}
		}
	}()
	return ch
}

// Unsubscribe removes a subscriber and closes its channel.
func (h *Hub) Unsubscribe(ch chan Entry) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
	close(ch)
}

// Stop shuts down all background goroutines.
func (h *Hub) Stop() { close(h.done) }

// Publish sends an entry to all subscribers and appends to the ring buffer.
// It also updates live metrics counters.
func (h *Hub) publish(e Entry) {
	// Stamp provenance once, here, so it is impossible for an entry to reach a
	// subscriber or the ring buffer without it.
	e = e.normalize()
	h.updateMetrics(e)

	h.mu.Lock()
	defer h.mu.Unlock()

	h.buf = append(h.buf, e)
	if len(h.buf) > 200 {
		h.buf = h.buf[len(h.buf)-200:]
	}

	for ch := range h.subs {
		select {
		case ch <- e:
		default:
			// slow subscriber: drop to avoid blocking
		}
	}
}

// PublishDirect allows external callers (e.g. the audit handler) to inject
// entries directly into the hub so they appear in the live stream.
func (h *Hub) PublishDirect(e Entry) { h.publish(e) }

// ConnectedClients returns the number of active SSE subscribers.
func (h *Hub) ConnectedClients() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.subs)
}

// GetSnapshot returns a point-in-time metrics snapshot.
func (h *Hub) GetSnapshot() Snapshot {
	rps := h.computeRPS()
	p99 := h.computeP99()

	h.aggMu.Lock()
	uniqueBlocked := int64(len(h.blockedIPs))
	attacks := make(map[string]int64, len(h.attackCats))
	for k, v := range h.attackCats {
		attacks[k] = v
	}
	country := make(map[string]int64, len(h.byCountry))
	for k, v := range h.byCountry {
		country[k] = v
	}
	geoLoaded := h.geoipLoaded
	h.aggMu.Unlock()

	return Snapshot{
		RPS:              rps,
		P99LatencyMs:     p99,
		P99Samples:       h.latSamples(),
		TotalRequests:    h.totalRequests.Load(),
		BlockedRequests:  h.blockedRequests.Load(),
		MLAnomalies:      h.mlAnomalies.Load(),
		ErrorCount:       h.errorCount.Load(),
		EbpfDrops:        h.ebpfDrops.Load(),
		ConnectedClients: h.ConnectedClients(),
		UniqueBlockedIPs: uniqueBlocked,
		Status2xx:        h.status2xx.Load(),
		Status3xx:        h.status3xx.Load(),
		Status4xx:        h.status4xx.Load(),
		Status5xx:        h.status5xx.Load(),
		AttackBreakdown:  attacks,
		ByCountry:        country,
		GeoIPLoaded:      geoLoaded,
		MemUsedBytes:     h.memUsed.Load(),
		MemTotalBytes:    h.memTotal.Load(),
	}
}

// GetSiteStats returns a copy of the cumulative per-site request/block counters.
func (h *Hub) GetSiteStats() map[string]SiteStat {
	h.aggMu.Lock()
	defer h.aggMu.Unlock()
	out := make(map[string]SiteStat, len(h.siteStats))
	for k, v := range h.siteStats {
		out[k] = *v
	}
	return out
}

// recordLearningLocked folds one would-have-blocked detection into the
// per-site/per-rule aggregate. Caller must hold aggMu.
func (h *Hub) recordLearningLocked(site, rule, cat, sev, msg, path, ts string) {
	bySite := h.learnStats[site]
	if bySite == nil {
		bySite = make(map[string]*LearningStat)
		h.learnStats[site] = bySite
	}
	st := bySite[rule]
	if st == nil {
		st = &LearningStat{RuleID: rule, Category: cat, Severity: sev, Message: msg}
		bySite[rule] = st
	}
	st.Count++
	st.LastSeen = ts
	if sev != "" {
		st.Severity = sev
	}
	if msg != "" {
		st.Message = msg
	}
	// Keep a small set of distinct sample paths.
	if path != "" && len(st.Samples) < learningSampleCap {
		for _, p := range st.Samples {
			if p == path {
				return
			}
		}
		st.Samples = append(st.Samples, path)
	}
}

// GetLearningStats returns the would-have-blocked aggregation for a site,
// sorted by count descending. An empty/"" site returns the aggregate across
// all sites (rules with the same ID merged). Always returns a non-nil slice.
func (h *Hub) GetLearningStats(site string) []LearningStat {
	h.aggMu.Lock()
	defer h.aggMu.Unlock()

	merged := make(map[string]*LearningStat)
	fold := func(src map[string]*LearningStat) {
		for rule, st := range src {
			dst := merged[rule]
			if dst == nil {
				cp := *st
				cp.Samples = append([]string(nil), st.Samples...)
				merged[rule] = &cp
				continue
			}
			dst.Count += st.Count
			if st.LastSeen > dst.LastSeen {
				dst.LastSeen = st.LastSeen
				dst.Message = st.Message
			}
			for _, p := range st.Samples {
				if len(dst.Samples) >= learningSampleCap {
					break
				}
				dst.Samples = append(dst.Samples, p)
			}
		}
	}

	if site == "" {
		for _, bySite := range h.learnStats {
			fold(bySite)
		}
	} else if bySite, ok := h.learnStats[site]; ok {
		fold(bySite)
	}

	out := make([]LearningStat, 0, len(merged))
	for _, st := range merged {
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

// ---------------------------------------------------------------------------
// Metrics helpers
// ---------------------------------------------------------------------------

func (h *Hub) updateMetrics(e Entry) {
	switch e.Kind {
	case "access":
		h.totalRequests.Add(1)
		h.rpsMu.Lock()
		h.rpsWin = append(h.rpsWin, time.Now())
		// Trim events older than 10 s
		cutoff := time.Now().Add(-10 * time.Second)
		i := sort.Search(len(h.rpsWin), func(i int) bool { return h.rpsWin[i].After(cutoff) })
		h.rpsWin = h.rpsWin[i:]
		h.rpsMu.Unlock()

		// Extract latency, status class and block action from the data.
		var row struct {
			Latency interface{} `json:"latency"`
			Status  int         `json:"status"`
			Action  string      `json:"action"`
			IP      string      `json:"ip"`
			Site    string      `json:"site"`
		}
		if json.Unmarshal(e.Data, &row) == nil {
			var ms float64
			switch v := row.Latency.(type) {
			case float64:
				ms = v
			case string:
				// The data plane writes latency as a STRING —
				// `format!("{:.2}", ...)` in the proxy's access.log — so this is
				// the branch that actually runs in production.
				//
				// It used to do json.Unmarshal(`"1.2"`, &float64), which cannot
				// succeed: that is a JSON string, not a number, and the error
				// was discarded. So `ms` stayed 0, no sample was ever recorded,
				// and p99 has read 0 on every deployment since the field became
				// a string. The UI then rendered 0 as "<1ms", which is how the
				// top bar could claim sub-millisecond p99 while the Logs page
				// showed 7-18ms on the same requests.
				if f, err := strconv.ParseFloat(v, 64); err == nil {
					ms = f
				}
			}
			if ms > 0 {
				h.latMu.Lock()
				h.latBuf = append(h.latBuf, ms)
				if len(h.latBuf) > 1000 {
					h.latBuf = h.latBuf[len(h.latBuf)-1000:]
				}
				h.latMu.Unlock()
			}
			switch {
			case row.Status >= 500:
				h.status5xx.Add(1)
			case row.Status >= 400:
				h.status4xx.Add(1)
			case row.Status >= 300:
				h.status3xx.Add(1)
			case row.Status >= 200:
				h.status2xx.Add(1)
			}
			h.aggMu.Lock()
			if row.Action == "BLOCK" && row.IP != "" {
				h.blockedIPs[row.IP] = struct{}{}
			}
			if row.Site != "" && row.Site != "-" {
				ss := h.siteStats[row.Site]
				if ss == nil {
					ss = &SiteStat{}
					h.siteStats[row.Site] = ss
				}
				ss.Total++
				if row.Status >= 500 {
					ss.S5xx++
				} else if row.Status >= 400 {
					ss.S4xx++
				}
			}
			h.aggMu.Unlock()
		}

	case "waf":
		var row struct {
			Action     string `json:"action"`
			Rule       string `json:"rule"`
			IP         string `json:"ip"`
			Site       string `json:"site"`
			Path       string `json:"path"`
			Sev        string `json:"sev"`
			Attack     string `json:"attack"`
			TS         string `json:"ts"`
			WouldBlock bool   `json:"would_block"`
		}
		if json.Unmarshal(e.Data, &row) == nil {
			blocked := row.Action == "BLOCK" || row.Action == "BLOCKED"
			if blocked {
				h.blockedRequests.Add(1)
			}
			cat := attackCategory(row.Rule)
			h.aggMu.Lock()
			// The attack breakdown counts what the WAF actually blocked — not
			// every rule match (a PASSed match isn't an attack that got through)
			// nor learning-mode DETECTs (surfaced separately in the learning
			// report).
			if blocked {
				h.attackCats[cat]++
			}
			if blocked && row.IP != "" {
				h.blockedIPs[row.IP] = struct{}{}
			}
			if blocked && row.Site != "" && row.Site != "-" {
				ss := h.siteStats[row.Site]
				if ss == nil {
					ss = &SiteStat{}
					h.siteStats[row.Site] = ss
				}
				ss.Blocked++
			}
			// Learning mode: aggregate would-have-blocked detections per rule.
			if (row.Action == "DETECT" || row.WouldBlock) && row.Rule != "" && row.Rule != "-" &&
				row.Site != "" && row.Site != "-" {
				h.recordLearningLocked(row.Site, row.Rule, cat, row.Sev, row.Attack, row.Path, row.TS)
			}
			h.aggMu.Unlock()
		}

	case "ml":
		var row struct {
			Verdict string `json:"verdict"`
		}
		if json.Unmarshal(e.Data, &row) == nil {
			v := row.Verdict
			if len(v) > 0 && (containsAny(v, []string{"ANOMALY", "INJECT", "SUSPECT", "BRUTE", "SCAN"})) {
				h.mlAnomalies.Add(1)
			}
		}

	case "error":
		var row struct {
			Lvl string `json:"lvl"`
		}
		if json.Unmarshal(e.Data, &row) == nil {
			if row.Lvl == "ERROR" || row.Lvl == "FATAL" {
				h.errorCount.Add(1)
			}
		}
	}
}

// attackCategory maps a (CRS or native) rule ID to a coarse attack category for
// the dashboard breakdown. Mapping follows the OWASP CRS rule-ID numbering:
//
//	911 method · 913 scanner/bot · 920/921 protocol · 930 LFI · 931 RFI
//	932 RCE · 933 PHP · 934 generic/SSRF · 941 XSS · 942 SQLi · 943 session
//	944 Java.
//
// Unknown / native rule IDs fall through to "other".
// AttackCategory maps a rule id (or one of the data plane's synthetic non-rule
// labels) onto a coarse attack category. Exported because the learning report
// is now also built from stored ClickHouse events, which carry the rule id but
// not the category — both paths must classify identically or the same rule
// would appear under different categories depending on which source served it.
func AttackCategory(rule string) string { return attackCategory(rule) }

func attackCategory(rule string) string {
	// Synthetic labels the data plane emits for non-rule blocks (see
	// classify_nonrule_block in the proxy).
	switch rule {
	case "GEOIP":
		return "geoip"
	case "RATELIMIT":
		return "ratelimit"
	case "SMUGGLING":
		return "protocol"
	case "BOT":
		return "bot"
	case "ANOMALY":
		return "anomaly"
	// Connection-layer blocks. Previously the data plane had no label for these
	// and emitted ANOMALY, so threat-intel and IP-reputation blocks were
	// miscounted as scoring-engine blocks in every rollup built on this
	// function. Kept in step with classify_nonrule_block in the proxy.
	case "THREATINTEL":
		return "threat_intel"
	case "IPREP":
		return "ip_reputation"
	case "DDOS":
		return "ddos"
	}
	if len(rule) < 3 {
		return "other"
	}
	switch rule[:3] {
	case "942":
		return "sqli"
	case "941":
		return "xss"
	case "930", "931":
		return "rfi_lfi"
	case "932", "933", "944":
		return "rce"
	case "934":
		return "ssrf"
	case "913":
		return "bot"
	case "911", "920", "921":
		return "protocol"
	default:
		return "other"
	}
}

// runMemSampler refreshes host memory usage from /proc/meminfo every 5 s.
// Non-Linux hosts (no /proc/meminfo) simply leave the gauges at zero.
func (h *Hub) runMemSampler() {
	sample := func() {
		data, err := os.ReadFile("/proc/meminfo")
		if err != nil {
			return
		}
		var total, available, free, buffers, cached uint64
		haveAvailable := false
		for _, line := range bytes.Split(data, []byte("\n")) {
			fields := bytes.Fields(line)
			if len(fields) < 2 {
				continue
			}
			// values are in kB
			var kb uint64
			for _, c := range fields[1] {
				if c < '0' || c > '9' {
					break
				}
				kb = kb*10 + uint64(c-'0')
			}
			switch string(fields[0]) {
			case "MemTotal:":
				total = kb * 1024
			case "MemAvailable:":
				available = kb * 1024
				haveAvailable = true
			case "MemFree:":
				free = kb * 1024
			case "Buffers:":
				buffers = kb * 1024
			case "Cached:":
				cached = kb * 1024
			}
		}
		// Older kernels / some containers omit MemAvailable; estimate it from
		// MemFree+Buffers+Cached rather than treating it as 0 (which would report
		// memUsed == total, i.e. a permanent 100%).
		if !haveAvailable {
			available = free + buffers + cached
		}
		if total > 0 && (haveAvailable || available > 0) {
			h.memTotal.Store(total)
			if available <= total {
				h.memUsed.Store(total - available)
			}
		}
	}
	sample()
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-h.done:
			return
		case <-tick.C:
			sample()
		}
	}
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

func (h *Hub) computeRPS() float64 {
	h.rpsLock.Lock()
	defer h.rpsLock.Unlock()
	h.rpsMu.Lock()
	n := len(h.rpsWin)
	h.rpsMu.Unlock()
	if n == 0 {
		return 0
	}
	// RPS = events in last 10 s / 10
	return math.Round(float64(n)/10.0*10) / 10
}

// latSamples reports how many latency samples the p99 is based on.
func (h *Hub) latSamples() int {
	h.latMu.Lock()
	defer h.latMu.Unlock()
	return len(h.latBuf)
}

func (h *Hub) computeP99() float64 {
	h.latMu.Lock()
	n := len(h.latBuf)
	if n == 0 {
		h.latMu.Unlock()
		return 0
	}
	cp := make([]float64, n)
	copy(cp, h.latBuf)
	h.latMu.Unlock()

	sort.Float64s(cp)
	idx := int(math.Ceil(float64(n)*0.99)) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= n {
		idx = n - 1
	}
	return math.Round(cp[idx]*10) / 10
}

// ---------------------------------------------------------------------------
// File tailer
// ---------------------------------------------------------------------------

// tailKind starts a goroutine that continuously tails `path`, publishing any
// new complete JSON lines as Entry{Kind: kind, Data: rawJSON}.
//
// On startup the tailer seeks to the current end of file so only new events
// are emitted — not historical ones already on disk before the process started.
func (h *Hub) tailKind(kind, path string) {
	go func() {
		var offset int64
		var pending []byte
		started := false

		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-h.done:
				return
			case <-ticker.C:
			}

			f, err := os.Open(path)
			if err != nil {
				// File may not exist yet if the data plane has never started.
				continue
			}

			fi, err := f.Stat()
			if err != nil {
				f.Close()
				continue
			}

			// On first open, start from the end of the file so we only stream
			// events that arrive after this process started.
			if !started {
				offset = fi.Size()
				started = true
				f.Close()
				continue
			}

			// Log rotation: file shrunk — restart from beginning.
			if fi.Size() < offset {
				offset = 0
				pending = pending[:0]
			}

			if fi.Size() == offset {
				f.Close()
				continue
			}

			// Read new bytes since last offset.
			if _, err := f.Seek(offset, io.SeekStart); err != nil {
				f.Close()
				continue
			}
			chunk, err := io.ReadAll(f)
			f.Close()
			if err != nil || len(chunk) == 0 {
				continue
			}
			offset += int64(len(chunk))

			pending = append(pending, chunk...)

			// Process all complete lines.
			for {
				idx := bytes.IndexByte(pending, '\n')
				if idx < 0 {
					break
				}
				line := bytes.TrimSpace(pending[:idx])
				pending = pending[idx+1:]

				if len(line) == 0 {
					continue
				}
				var data json.RawMessage
				if json.Unmarshal(line, &data) != nil {
					continue // malformed — skip
				}
				h.publish(Entry{Kind: kind, Data: data})
			}
		}
	}()
}

// ---------------------------------------------------------------------------
// Traffic history bucket sampler
// ---------------------------------------------------------------------------

// runBucketSampler captures a one-second snapshot of deltas every second and
// appends it to histBuf (capped at 120 entries = 2 minutes).
func (h *Hub) runBucketSampler() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var prevTotal, prevBlocked int64
	for {
		select {
		case <-h.done:
			return
		case <-tick.C:
			cur := h.totalRequests.Load()
			blk := h.blockedRequests.Load()
			reqs := cur - prevTotal
			bl := blk - prevBlocked
			prevTotal = cur
			prevBlocked = blk
			bucket := TrafficBucket{
				TS:      time.Now().Unix(),
				Reqs:    reqs,
				Blocked: bl,
				P99Ms:   h.computeP99(),
			}
			h.histMu.Lock()
			h.histBuf = append(h.histBuf, bucket)
			if len(h.histBuf) > 120 {
				h.histBuf = h.histBuf[len(h.histBuf)-120:]
			}
			h.histMu.Unlock()
		}
	}
}

// GetTrafficHistory returns the last n traffic buckets (or all if n > available).
func (h *Hub) GetTrafficHistory(n int) []TrafficBucket {
	h.histMu.RLock()
	defer h.histMu.RUnlock()
	if len(h.histBuf) == 0 {
		return []TrafficBucket{}
	}
	if n <= 0 || n >= len(h.histBuf) {
		out := make([]TrafficBucket, len(h.histBuf))
		copy(out, h.histBuf)
		return out
	}
	out := make([]TrafficBucket, n)
	copy(out, h.histBuf[len(h.histBuf)-n:])
	return out
}
