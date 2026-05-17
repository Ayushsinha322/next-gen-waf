// Package logs provides an SSE fan-out hub that tails NDJSON log files
// produced by the Sentinel data plane and streams new entries to all
// connected dashboard clients.
//
// Log directory: $SENTINEL_LOG_DIR (default /tmp/sentinel-logs).
// One file per kind: access.log, waf.log, error.log, audit.log, modsec.log, ml.log
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
	"sync"
	"sync/atomic"
	"time"
)

// Entry is a single log line emitted to subscribers.
type Entry struct {
	Kind string          `json:"kind"`
	Data json.RawMessage `json:"data"`
}

// Snapshot holds a point-in-time view of live metrics derived from the
// event stream.  It is safe to read without locking.
type Snapshot struct {
	RPS              float64 `json:"rps"`
	P99LatencyMs     float64 `json:"p99_latency_ms"`
	TotalRequests    int64   `json:"total_requests"`
	BlockedRequests  int64   `json:"blocked_requests"`
	MLAnomalies      int64   `json:"ml_anomalies"`
	ErrorCount       int64   `json:"error_count"`
	EbpfDrops        int64   `json:"ebpf_drops"`
	ConnectedClients int     `json:"connected_clients"`
}

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

	// Metrics counters (atomic — updated on every publish).
	totalRequests   atomic.Int64
	blockedRequests atomic.Int64
	mlAnomalies     atomic.Int64
	errorCount      atomic.Int64
	ebpfDrops       atomic.Int64

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
	return "/tmp/sentinel-logs"
}

// NewHub creates a Hub and starts background file tailers for every known
// log kind.
func NewHub() *Hub {
	h := &Hub{
		subs:   make(map[chan Entry]struct{}),
		done:   make(chan struct{}),
		latBuf: make([]float64, 0, 1000),
	}

	dir := LogDir()

	kinds := []string{"access", "waf", "error", "audit", "modsec", "ml"}
	for _, kind := range kinds {
		h.tailKind(kind, filepath.Join(dir, kind+".log"))
	}

	go h.runBucketSampler()

	return h
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
	return Snapshot{
		RPS:              rps,
		P99LatencyMs:     p99,
		TotalRequests:    h.totalRequests.Load(),
		BlockedRequests:  h.blockedRequests.Load(),
		MLAnomalies:      h.mlAnomalies.Load(),
		ErrorCount:       h.errorCount.Load(),
		EbpfDrops:        h.ebpfDrops.Load(),
		ConnectedClients: h.ConnectedClients(),
	}
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

		// Extract latency from the data.
		var row struct {
			Latency interface{} `json:"latency"`
		}
		if json.Unmarshal(e.Data, &row) == nil {
			var ms float64
			switch v := row.Latency.(type) {
			case float64:
				ms = v
			case string:
				// parse "1.2" → 1.2
				json.Unmarshal(json.RawMessage(`"`+v+`"`), &ms) //nolint
			}
			if ms > 0 {
				h.latMu.Lock()
				h.latBuf = append(h.latBuf, ms)
				if len(h.latBuf) > 1000 {
					h.latBuf = h.latBuf[len(h.latBuf)-1000:]
				}
				h.latMu.Unlock()
			}
		}

	case "waf":
		var row struct {
			Action string `json:"action"`
		}
		if json.Unmarshal(e.Data, &row) == nil && row.Action == "BLOCKED" {
			h.blockedRequests.Add(1)
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
