package logs

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The hub used to tail modsec.log and ml.log. Nothing has ever written them:
// they were produced only by sentinel-telemetry's EventLogger, which had no
// callers anywhere in the workspace and was deleted in 2026-08. The cost was
// not just wasted goroutines (one per kind per node directory, polling a
// non-existent path every 200ms) — the console offered both in its file picker,
// so an operator could select a pane that stays empty forever, which reads as
// "the WAF stopped logging" rather than "this file does not exist".
//
// This test fails if a kind is added back without something that writes it.
func TestTailedKindsAllHaveAWriter(t *testing.T) {
	// The data plane writes exactly these (crates/sentinel-proxy enqueue_log →
	// access.log / waf.log) plus error.log and audit.log.
	written := map[string]bool{
		"access": true,
		"waf":    true,
		"error":  true,
		"audit":  true,
	}

	dir := t.TempDir()
	t.Setenv("SENTINEL_LOG_DIR", dir)

	h := NewHub()
	defer close(h.done)

	// Let NewHub's tailers register themselves.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		h.tailMu.Lock()
		n := len(h.tailed)
		h.tailMu.Unlock()
		if n >= len(written) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	h.tailMu.Lock()
	defer h.tailMu.Unlock()
	if len(h.tailed) == 0 {
		t.Fatal("no tailers registered — the test cannot prove anything")
	}
	for path := range h.tailed {
		kind := filepath.Base(path)
		kind = kind[:len(kind)-len(filepath.Ext(kind))]
		if !written[kind] {
			t.Errorf("hub tails %q, but nothing in this product writes %s.log — "+
				"either wire up a writer or drop the kind (see the kinds list in NewHub)",
				path, kind)
		}
	}
}

// The simulator must not invent kinds either: a simulated entry whose kind the
// console cannot display is data with nowhere to go, and the simulator already
// caused real confusion once by producing attacks indistinguishable from live
// ones (hence SENTINEL_DEV_SIMULATOR gating).
func TestSimulatorOnlyPublishesDisplayableKinds(t *testing.T) {
	if os.Getenv("SENTINEL_DEV_SIMULATOR") != "" {
		t.Skip("simulator env set externally; skipping to avoid interference")
	}
	displayable := map[string]bool{"access": true, "waf": true, "error": true, "audit": true}

	h := newTestHub()
	h.done = make(chan struct{})
	h.subs = make(map[chan Entry]struct{})
	ch := h.Subscribe()

	go h.runSimulator()
	defer close(h.done)

	seen := map[string]bool{}
	timeout := time.After(3 * time.Second)
	for i := 0; i < 12; i++ {
		select {
		case e := <-ch:
			seen[e.Kind] = true
			if !displayable[e.Kind] {
				t.Fatalf("simulator published kind %q, which the console has no view for", e.Kind)
			}
		case <-timeout:
			i = 12
		}
	}
	if len(seen) == 0 {
		t.Fatal("simulator produced nothing — the assertion above never ran")
	}
}

// p99 read 0 on every deployment because the access-log `latency` field is a
// STRING (`format!("{:.2}", …)` in the proxy) and the hub tried to
// json.Unmarshal it into a float64 — which cannot succeed, and the error was
// discarded. The UI then rendered 0 as "<1ms", so the top bar advertised
// sub-millisecond p99 while the Logs page showed 7-18ms for the same requests.
func TestLatencyIsSampledFromTheStringTheProxyActuallyWrites(t *testing.T) {
	h := newTestHub()
	h.latBuf = make([]latSample, 0, 8)

	// Exactly the shape the data plane emits.
	for _, lat := range []string{"7.08", "18.82", "2.94"} {
		h.updateMetrics(Entry{Kind: "access", Data: []byte(`{"latency":"` + lat + `","status":200}`)})
	}
	if got := h.latSamples(); got != 3 {
		t.Fatalf("string latencies must be sampled, got %d samples", got)
	}
	if p := h.computeP99(); p < 7.0 {
		t.Fatalf("p99 should reflect the samples, got %v", p)
	}

	// A numeric latency (any future writer) must keep working.
	h2 := newTestHub()
	h2.latBuf = make([]latSample, 0, 8)
	h2.updateMetrics(Entry{Kind: "access", Data: []byte(`{"latency":12.5,"status":200}`)})
	if got := h2.latSamples(); got != 1 {
		t.Fatalf("numeric latency must still be sampled, got %d", got)
	}

	// Garbage must be ignored rather than recorded as 0, which would drag the
	// percentile down and understate real latency.
	h3 := newTestHub()
	h3.latBuf = make([]latSample, 0, 8)
	h3.updateMetrics(Entry{Kind: "access", Data: []byte(`{"latency":"n/a","status":200}`)})
	if got := h3.latSamples(); got != 0 {
		t.Fatalf("unparseable latency must not become a 0 sample, got %d", got)
	}
}

// The console's latency badge read "24387.9ms" on a healthy deployment. The
// metric was correct and the display was honest — but the NUMBER was dominated
// by Juice Shop's socket.io long-poll, which holds a request open ~25s. A WAF
// status badge showing 24 seconds reads as "the WAF is broken" when nothing is.
//
// So the badge now reports the WAF's OWN processing time, which a slow or
// long-polling origin cannot inflate, and WebSocket relays are excluded from
// both rings because what they measure is connection lifetime, not latency.
func TestWafOwnTimeIsSampledAndSlowOriginsCannotInflateIt(t *testing.T) {
	h := newTestHub()
	h.latBuf = make([]latSample, 0, 8)
	h.wafLatBuf = make([]latSample, 0, 8)

	// A long-poll: 24s end-to-end, but the WAF only spent 1.2ms on it.
	h.updateMetrics(Entry{Kind: "access", Data: []byte(
		`{"latency":"24387.85","waf_ms":"1.20","status":200}`)})
	// An ordinary request.
	h.updateMetrics(Entry{Kind: "access", Data: []byte(
		`{"latency":"15.51","waf_ms":"2.10","status":304}`)})

	if got := h.computeP99(); got < 100 {
		t.Fatalf("end-to-end p99 should still include the slow origin (it is real), got %v", got)
	}
	if got := h.computeP99Waf(); got > 10 {
		t.Fatalf("WAF p99 must not be inflated by a slow origin, got %v", got)
	}
	if h.latWafSamples() != 2 {
		t.Fatalf("both requests should contribute WAF samples, got %d", h.latWafSamples())
	}

	// A WebSocket relay measures how long the connection LIVED. Excluded from
	// both rings — clamping would silently invent a value instead.
	h2 := newTestHub()
	h2.latBuf = make([]latSample, 0, 8)
	h2.wafLatBuf = make([]latSample, 0, 8)
	h2.updateMetrics(Entry{Kind: "access", Data: []byte(
		`{"latency":"3600000.00","waf_ms":"3600000.00","status":101}`)})
	if h2.latSamples() != 0 || h2.latWafSamples() != 0 {
		t.Fatalf("a 101 upgrade must not be sampled: e2e=%d waf=%d",
			h2.latSamples(), h2.latWafSamples())
	}

	// A cheap pass can legitimately cost ~0ms of WAF time; that must record,
	// unlike end-to-end where 0 only ever meant "not parsed".
	h3 := newTestHub()
	h3.latBuf = make([]latSample, 0, 8)
	h3.wafLatBuf = make([]latSample, 0, 8)
	h3.updateMetrics(Entry{Kind: "access", Data: []byte(
		`{"latency":"5.00","waf_ms":"0.00","status":200}`)})
	if h3.latWafSamples() != 1 {
		t.Fatalf("a near-zero WAF time is a real measurement and must record, got %d", h3.latWafSamples())
	}

	// An access line with no waf_ms at all (a data plane older than this field)
	// must not fabricate a sample.
	h4 := newTestHub()
	h4.latBuf = make([]latSample, 0, 8)
	h4.wafLatBuf = make([]latSample, 0, 8)
	h4.updateMetrics(Entry{Kind: "access", Data: []byte(`{"latency":"5.00","status":200}`)})
	if h4.latWafSamples() != 0 {
		t.Fatalf("absent waf_ms must not become a sample, got %d", h4.latWafSamples())
	}
	if h4.latSamples() != 1 {
		t.Fatalf("end-to-end must still be sampled from an older data plane, got %d", h4.latSamples())
	}
}

// The console badge read "p99 8617.2ms" on an idle deploy VM while the data
// plane's own summary said 90ms and real requests took 10-39ms.
//
// Two separate causes, both fixed here:
//
//  1. A 502 means the origin never answered and the request sat waiting for
//     the upstream timeout. The data plane attributes that whole wait to
//     waf_ms, so a dead origin reads as ten seconds of WAF processing. One
//     such request was in the ring: GET / with waf_ms 9918.7.
//
//  2. The ring had no age bound, so that sample stayed the headline latency
//     for as long as the process lived. With 38 samples the "99th percentile"
//     index lands on the maximum, so the badge was reporting the single
//     slowest request ever seen, presented as current performance.
func TestGatewayErrorsDoNotCountAsWafProcessingTime(t *testing.T) {
	h := newTestHub()
	h.latBuf = make([]latSample, 0, 8)
	h.wafLatBuf = make([]latSample, 0, 8)

	// The real shape from the deploy VM: a 502 whose entire upstream wait was
	// recorded against the WAF.
	h.updateMetrics(Entry{Kind: "access", Data: []byte(
		`{"latency":"9918.69","waf_ms":"9918.70","status":502}`)})
	// And an ordinary request.
	h.updateMetrics(Entry{Kind: "access", Data: []byte(
		`{"latency":"12.40","waf_ms":"0.60","status":200}`)})

	if got := h.latWafSamples(); got != 1 {
		t.Fatalf("the 502 must not contribute a WAF sample, got %d samples", got)
	}
	if got := h.computeP99Waf(); got > 5 {
		t.Fatalf("WAF p99 is inflated by a dead origin: %v", got)
	}
	// The user really did wait ten seconds, so end-to-end still counts it.
	if got := h.computeP99(); got < 1000 {
		t.Fatalf("end-to-end p99 must still include the 502 — it is what the user got: %v", got)
	}
	if got := h.latSamples(); got != 2 {
		t.Fatalf("both requests contribute end-to-end samples, got %d", got)
	}
}

// A slow request stops being reported once it ages out, so the badge describes
// the recent past rather than the worst thing ever seen.
func TestLatencySamplesAgeOut(t *testing.T) {
	h := newTestHub()
	h.latBuf = make([]latSample, 0, 8)
	h.wafLatBuf = make([]latSample, 0, 8)

	h.updateMetrics(Entry{Kind: "access", Data: []byte(
		`{"latency":"8600.00","waf_ms":"8600.00","status":200}`)})
	if h.latSamples() != 1 || h.computeP99() < 1000 {
		t.Fatal("the slow sample should be counted while it is recent")
	}

	// Push it outside the window without waiting for wall-clock time.
	h.latMu.Lock()
	for i := range h.latBuf {
		h.latBuf[i].at = h.latBuf[i].at.Add(-latencyWindow - time.Minute)
	}
	for i := range h.wafLatBuf {
		h.wafLatBuf[i].at = h.wafLatBuf[i].at.Add(-latencyWindow - time.Minute)
	}
	h.latMu.Unlock()

	if got := h.latSamples(); got != 0 {
		t.Fatalf("an aged-out sample must be dropped, got %d", got)
	}
	if got := h.computeP99(); got != 0 {
		t.Fatalf("with no recent samples the p99 is not a measurement, got %v", got)
	}
	if got := h.latWafSamples(); got != 0 {
		t.Fatalf("aged-out WAF sample must be dropped, got %d", got)
	}

	// A fresh request re-establishes the measurement at its real value.
	h.updateMetrics(Entry{Kind: "access", Data: []byte(
		`{"latency":"11.20","waf_ms":"0.40","status":200}`)})
	if got := h.computeP99(); got > 50 {
		t.Fatalf("the badge should now reflect the recent request, got %v", got)
	}
}
