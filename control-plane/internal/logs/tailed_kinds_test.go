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
