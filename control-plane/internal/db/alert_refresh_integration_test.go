//go:build integration || !unit

// Integration coverage for RefreshOpenAlert (see alert_resolve_integration_test.go
// for how to run it). A real database because the statement turns on a CTE with
// FOR UPDATE, a jsonb merge, and a details->>key match that a mock would fake.
package db

import (
	"context"
	"encoding/json"
	"testing"
)

func TestRefreshOpenAlertUpdatesInsteadOfDuplicating(t *testing.T) {
	s, pg := resolveTestStore(t)
	ctx := context.Background()

	// Two rows for the same disk, as earlier builds left them, plus one for a
	// different component and one already resolved.
	old := seedAlert(t, pg, "disk_pressure", "open", `{"component":"clickhouse","used_pct":80.4}`)
	newer := seedAlert(t, pg, "disk_pressure", "open", `{"component":"clickhouse","used_pct":80.9}`)
	other := seedAlert(t, pg, "disk_pressure", "open", `{"component":"postgres","used_pct":85}`)
	done := seedAlert(t, pg, "disk_pressure", "resolved", `{"component":"clickhouse"}`)

	row, prev, err := s.RefreshOpenAlert(ctx, resolveTestTenant, "", "disk_pressure", "component", "clickhouse",
		"high", "ClickHouse disk 91.2% full", json.RawMessage(`{"component":"clickhouse","used_pct":91.2}`))
	if err != nil {
		t.Fatal(err)
	}
	if row == nil || row.ID != newer {
		t.Fatalf("refreshed %+v, want the NEWEST open row %s", row, newer)
	}
	if prev != "critical" || row.Severity != "high" || row.Summary != "ClickHouse disk 91.2% full" {
		t.Fatalf("prev=%q row=%+v", prev, row)
	}
	var d map[string]any
	_ = json.Unmarshal(row.Details, &d)
	if d["used_pct"] != 91.2 {
		t.Fatalf("details not merged: %s", row.Details)
	}
	if st, auto := alertState(t, pg, old); st != "resolved" || !auto {
		t.Fatalf("older duplicate: state=%s auto=%v, want resolved as superseded", st, auto)
	}
	if st, _ := alertState(t, pg, other); st != "open" {
		t.Fatalf("a different condition must not be touched: %s", st)
	}
	if st, _ := alertState(t, pg, done); st != "resolved" {
		t.Fatalf("resolved row changed: %s", st)
	}
}

func TestRefreshOpenAlertWithNothingOpenReturnsNil(t *testing.T) {
	s, pg := resolveTestStore(t)
	seedAlert(t, pg, "node_down", "resolved", `{"node":"waf1"}`)
	seedAlert(t, pg, "node_down", "open", `{"node":"waf2"}`)
	row, _, err := s.RefreshOpenAlert(context.Background(), resolveTestTenant, "", "node_down", "node", "waf1",
		"critical", "Data-plane node waf1 is DOWN", json.RawMessage(`{"node":"waf1"}`))
	if err != nil || row != nil {
		t.Fatalf("row=%+v err=%v — a condition with no OPEN alert must return nil so the caller inserts", row, err)
	}
}
