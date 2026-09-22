package main

import (
	"os"
	"strings"
	"testing"
)

// The case this table exists for is line 2: one node, alive, inspecting every
// request, but every origin behind it unreachable. The old rule counted only
// healthy nodes, so that state reported protection_active=false and painted a
// red "Protection inactive" badge on every page of the console — while the WAF
// was working exactly as configured and the application was the thing that was
// down. Whatever else changes here, a degraded node must keep protection active.
func TestFleetVerdict(t *testing.T) {
	cases := []struct {
		name                             string
		total, healthy, degraded, down   int
		cpEnabled, cpWritable, cpUnreach bool
		wantOverall                      string
		wantProtection                   bool
	}{
		{"one healthy node", 1, 1, 0, 0, true, true, false, "healthy", true},
		{"one degraded node — origins down, WAF inspecting", 1, 0, 1, 0, true, true, false, "degraded", true},
		{"one node down — nothing inspecting", 1, 0, 0, 1, true, true, false, "critical", false},
		{"no nodes deployed yet", 0, 0, 0, 0, true, true, false, "healthy", true},
		{"healthy plus a dead peer", 2, 1, 0, 1, true, true, false, "degraded", true},
		{"healthy plus a degraded peer", 2, 1, 1, 0, true, true, false, "degraded", true},
		{"every node degraded", 3, 0, 3, 0, true, true, false, "degraded", true},
		{"every node down", 3, 0, 0, 3, true, true, false, "critical", false},
		{"writes unavailable outranks healthy nodes", 1, 1, 0, 0, true, false, false, "critical", true},
		{"control-plane peer unreachable", 2, 2, 0, 0, true, true, true, "degraded", true},
		{"standalone control plane, not writable, is not judged", 1, 1, 0, 0, false, false, false, "healthy", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			overall, protection := fleetVerdict(tc.total, tc.healthy, tc.degraded, tc.down, tc.cpEnabled, tc.cpWritable, tc.cpUnreach)
			if overall != tc.wantOverall {
				t.Errorf("overall = %q, want %q", overall, tc.wantOverall)
			}
			if protection != tc.wantProtection {
				t.Errorf("protection_active = %v, want %v", protection, tc.wantProtection)
			}
		})
	}
}

// Protection and the overall verdict must never contradict each other: the only
// states that may report protection inactive are the critical ones.
func TestFleetVerdictProtectionAgreesWithOverall(t *testing.T) {
	for total := 0; total <= 3; total++ {
		for healthy := 0; healthy <= total; healthy++ {
			for degraded := 0; degraded <= total-healthy; degraded++ {
				down := total - healthy - degraded
				for _, cpWritable := range []bool{true, false} {
					overall, protection := fleetVerdict(total, healthy, degraded, down, true, cpWritable, false)
					if !protection && overall != "critical" {
						t.Fatalf("total=%d healthy=%d degraded=%d down=%d writable=%v: protection inactive but overall=%q",
							total, healthy, degraded, down, cpWritable, overall)
					}
					if (healthy+degraded) > 0 && !protection {
						t.Fatalf("total=%d healthy=%d degraded=%d: a node is up but protection reads inactive", total, healthy, degraded)
					}
				}
			}
		}
	}
}

// The handler must use the shared function rather than reimplementing the rule —
// that divergence is how the two ended up disagreeing in the first place.
func TestClusterHealthUsesFleetVerdict(t *testing.T) {
	raw, err := os.ReadFile("node_handlers.go")
	if err != nil {
		t.Fatalf("read node_handlers.go: %v", err)
	}
	src := string(raw)
	if !strings.Contains(src, "overall, protectionActive := fleetVerdict(") {
		t.Fatal("handleClusterHealth does not call fleetVerdict — the verdict rule has been reimplemented inline")
	}
	if strings.Contains(src, "protectionActive := dpHealthy >= 1") {
		t.Fatal("the old healthy-only protection rule is back: a degraded node would report protection inactive")
	}
	if !strings.Contains(src, `"upstreams_healthy": dpUpstreamsHealthy`) {
		t.Fatal("the data-plane summary no longer reports aggregate upstream counts — the console cannot explain why the fleet is degraded")
	}
}
