package nodehealth

import (
	"testing"
	"time"

	"github.com/your-org/sentinel-waf/control-plane/internal/db"
)

// The eleven CRITICAL alerts this deployment carried from 13 July existed because
// the monitor only acted on transitions and kept the previous status in memory. A
// control-plane restart emptied that map, so a node that went down before the
// restart and came back after produced no transition and its alert stayed open.
// reconcileAlerts fixes that by comparing against current state, and this is the
// boundary that decides what "current" means.
func TestHealthyNodeIDs(t *testing.T) {
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	const downAfter = 30 * time.Second

	nodes := []db.Node{
		{ID: "waf1", LastSeen: now.Add(-1 * time.Second)},  // fresh
		{ID: "waf2", LastSeen: now.Add(-30 * time.Second)}, // exactly at the boundary
		{ID: "waf3", LastSeen: now.Add(-31 * time.Second)}, // just past it
		{ID: "waf4", LastSeen: now.Add(-48 * time.Hour)},   // long gone
		{ID: "waf5", LastSeen: now},                        // this instant
	}

	got := healthyNodeIDs(nodes, downAfter, now)
	want := []string{"waf1", "waf2", "waf5"}

	if len(got) != len(want) {
		t.Fatalf("healthy set = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("healthy set = %v, want %v", got, want)
		}
	}
}

// The boundary is inclusive: a node last seen exactly downAfter ago is still up.
// Excluding it would resolve and re-raise an alert every sweep for a node sitting
// on the edge, which is worse than either steady state.
func TestHealthyNodeIDsBoundaryIsInclusive(t *testing.T) {
	now := time.Now()
	nodes := []db.Node{{ID: "edge", LastSeen: now.Add(-30 * time.Second)}}
	if got := healthyNodeIDs(nodes, 30*time.Second, now); len(got) != 1 {
		t.Fatalf("node at exactly downAfter should count as healthy, got %v", got)
	}
}

// No nodes must yield an empty set rather than nil-with-length-confusion: an
// empty healthy set means "resolve nothing", and reconcileAlerts relies on that
// to avoid a query whose empty IN-list would match every row.
func TestHealthyNodeIDsEmpty(t *testing.T) {
	if got := healthyNodeIDs(nil, time.Minute, time.Now()); len(got) != 0 {
		t.Fatalf("no nodes should give an empty healthy set, got %v", got)
	}
}
