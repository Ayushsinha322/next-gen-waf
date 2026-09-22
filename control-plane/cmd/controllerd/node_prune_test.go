package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// classifyNode is the whole reason the cluster page stopped calling a removed
// container "down" for ever. Each row below is a state that was observed on a
// real install (the ghost, the degraded live node, the freshly-late heartbeat).
func TestClassifyNode(t *testing.T) {
	down, stale := 30*time.Second, 24*time.Hour
	cases := []struct {
		name      string
		reported  string
		sinceSeen time.Duration
		want      string
	}{
		{"fresh healthy heartbeat", "healthy", 8 * time.Second, "healthy"},
		{"fresh degraded heartbeat (all origins down)", "degraded", 8 * time.Second, "degraded"},
		{"fresh but unknown status is not trusted", "weird", 8 * time.Second, "down"},
		{"fresh empty status is not trusted", "", 8 * time.Second, "down"},
		{"late by a minute is down, not stale", "healthy", 61 * time.Second, "down"},
		{"exactly at the down window is still up", "healthy", 30 * time.Second, "healthy"},
		{"an hour silent is down", "healthy", time.Hour, "down"},
		{"4.8 days silent — the ghost — is stale", "down", 414000 * time.Second, "stale"},
		{"just past the stale window is stale", "healthy", 24*time.Hour + time.Second, "stale"},
		{"exactly the stale window is still down", "healthy", 24 * time.Hour, "down"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyNode(tc.reported, tc.sinceSeen, down, stale); got != tc.want {
				t.Fatalf("classifyNode(%q, %s) = %q, want %q", tc.reported, tc.sinceSeen, got, tc.want)
			}
		})
	}
}

// A zero or negative stale window must never be honoured: it would classify
// every node as stale the instant its heartbeat was late, emptying the fleet.
func TestClassifyNodeIgnoresNonPositiveStaleWindow(t *testing.T) {
	if got := classifyNode("healthy", 5*time.Second, 30*time.Second, 0); got != "healthy" {
		t.Fatalf("stale window 0 must be ignored, got %q", got)
	}
	if got := classifyNode("healthy", 5*time.Second, 30*time.Second, -time.Hour); got != "healthy" {
		t.Fatalf("negative stale window must be ignored, got %q", got)
	}
}

func TestNodeStaleAfterEnv(t *testing.T) {
	prev, had := os.LookupEnv("SENTINEL_NODE_STALE_HOURS")
	t.Cleanup(func() {
		if had {
			os.Setenv("SENTINEL_NODE_STALE_HOURS", prev)
		} else {
			os.Unsetenv("SENTINEL_NODE_STALE_HOURS")
		}
	})
	os.Unsetenv("SENTINEL_NODE_STALE_HOURS")
	if got := nodeStaleAfter(); got != 24*time.Hour {
		t.Fatalf("default = %s, want 24h", got)
	}
	os.Setenv("SENTINEL_NODE_STALE_HOURS", "72")
	if got := nodeStaleAfter(); got != 72*time.Hour {
		t.Fatalf("72 -> %s, want 72h", got)
	}
	for _, bad := range []string{"0", "-3", "soon", ""} {
		os.Setenv("SENTINEL_NODE_STALE_HOURS", bad)
		if got := nodeStaleAfter(); got != 24*time.Hour {
			t.Fatalf("%q must fall back to 24h, got %s", bad, got)
		}
	}
}

// The prune job is only useful if main actually starts it — the same shape as
// last_login_at, which was created, selected and rendered but never written.
// Read the source, because main() needs a live database to exercise.
func TestNodePruneIsWiredIntoMain(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	if !regexp.MustCompile(`startNodePrune\(\s*store\s*,\s*cl\s*,\s*log\s*\)`).Match(src) {
		t.Fatal("main.go does not call startNodePrune(store, cl, log) — stale nodes would never be pruned")
	}
	if !strings.Contains(string(src), "stops = append(stops, startNodePrune(") {
		t.Fatal("startNodePrune's stop function is not registered in stops — it would outlive shutdown")
	}
	hs, err := os.ReadFile("node_handlers.go")
	if err != nil {
		t.Fatalf("read node_handlers.go: %v", err)
	}
	if !strings.Contains(string(hs), "classifyNode(n.Status, sinceSeen, downAfter, staleAfter)") {
		t.Fatal("handleClusterHealth does not classify nodes through classifyNode — stale rows would count as down again")
	}
	if !strings.Contains(string(hs), `"stale":             dpStale,`) {
		t.Fatal("handleClusterHealth does not report the stale count — the console cannot show it")
	}
}
