//go:build integration || !unit

// Integration coverage for ResolveAlertsByKind.
//
// Run against a throwaway Postgres with the schema applied:
//
//	SENTINEL_TEST_DB_URL='postgres://sentinel:testpass@127.0.0.1:55433/sentinel?sslmode=disable' \
//	  go test ./internal/db/ -run TestResolveAlertsByKind -v
//
// Skipped when SENTINEL_TEST_DB_URL is unset, matching the other DB tests here.
//
// Why this needs a real database rather than a mock: the query turns on
// Postgres-specific behaviour that a mock would happily fake — a NULL $3 making
// the JSON filter short-circuit, `details->>key = ANY($4)` against a jsonb
// column, and the `||` merge on a row with an empty details object. Every one of
// those is a place the statement could be syntactically fine and still match
// nothing. Running it for real also established that alerts.details is NOT NULL,
// which an earlier version of this test assumed otherwise.
package db

import (
	"context"
	"os"
	"testing"
)

const resolveTestTenant = "00000000-0000-0000-0000-0000000000ab"

func resolveTestStore(t *testing.T) (*Store, *pgxPool) {
	t.Helper()
	url := os.Getenv("SENTINEL_TEST_DB_URL")
	if url == "" {
		t.Skip("SENTINEL_TEST_DB_URL not set — skipping alert-resolve integration test")
	}
	ctx := context.Background()
	pool, err := Open(ctx, Config{URL: url, MaxConns: 4, MinConns: 1})
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(pool.Close)
	pg, ok := pool.(*pgxPool)
	if !ok {
		t.Fatal("expected *pgxPool")
	}
	if _, err := pg.pool.Exec(ctx, `
		INSERT INTO tenants (id, slug, name, plan, status)
		VALUES ($1, 'resolve-test', 'Resolve Test', 'enterprise', 'active')
		ON CONFLICT (id) DO NOTHING`, resolveTestTenant); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if _, err := pg.pool.Exec(ctx, `DELETE FROM alerts WHERE tenant_id = $1`, resolveTestTenant); err != nil {
		t.Fatalf("clean alerts: %v", err)
	}
	return NewStore(pool), pg
}

func seedAlert(t *testing.T, pg *pgxPool, kind, state, details string) string {
	t.Helper()
	var id string
	// alerts.details is NOT NULL (proven by this test failing against a real
	// Postgres when it tried to seed NULL), so the reachable "no details" case is
	// an empty object, which is what the resolver's coalesce and the ->> filter
	// both have to survive.
	d := details
	if d == "" {
		d = "{}"
	}
	err := pg.pool.QueryRow(context.Background(), `
		INSERT INTO alerts (tenant_id, severity, kind, summary, details, state)
		VALUES ($1, 'critical', $2, $2 || ' seeded', $3::jsonb, $4)
		RETURNING id`, resolveTestTenant, kind, d, state).Scan(&id)
	if err != nil {
		t.Fatalf("seed alert %s/%s: %v", kind, state, err)
	}
	return id
}

func alertState(t *testing.T, pg *pgxPool, id string) (state string, autoResolved bool) {
	t.Helper()
	err := pg.pool.QueryRow(context.Background(), `
		SELECT state, coalesce((details->>'auto_resolved')::bool, false)
		  FROM alerts WHERE id = $1`, id).Scan(&state, &autoResolved)
	if err != nil {
		t.Fatalf("read alert %s: %v", id, err)
	}
	return state, autoResolved
}

// The real scenario: node_down rows for nodes that are heart-beating again must
// close, and a row for a node that is still down must not.
func TestResolveAlertsByKindFiltersOnDetail(t *testing.T) {
	s, pg := resolveTestStore(t)
	ctx := context.Background()

	up1 := seedAlert(t, pg, "node_down", "open", `{"node":"waf1"}`)
	up2 := seedAlert(t, pg, "node_down", "acked", `{"node":"waf2"}`)
	stillDown := seedAlert(t, pg, "node_down", "open", `{"node":"waf3"}`)
	otherKind := seedAlert(t, pg, "attack_spike", "open", `{"node":"waf1"}`)

	n, err := s.ResolveAlertsByKind(ctx, resolveTestTenant, "",
		[]string{"node_down"}, "node", []string{"waf1", "waf2"}, "node is heart-beating again")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if n != 2 {
		t.Fatalf("resolved %d rows, want 2 (open and acked for the healthy nodes)", n)
	}
	for _, id := range []string{up1, up2} {
		if st, auto := alertState(t, pg, id); st != "resolved" || !auto {
			t.Fatalf("healthy node's alert: state=%s auto_resolved=%v, want resolved/true", st, auto)
		}
	}
	if st, _ := alertState(t, pg, stillDown); st != "open" {
		t.Fatalf("still-down node's alert became %s, must stay open", st)
	}
	if st, _ := alertState(t, pg, otherKind); st != "open" {
		t.Fatalf("unrelated kind became %s, must be untouched", st)
	}
}

// The orphaned-kind path: an empty detailKey closes every row of those kinds,
// including rows whose details are NULL, which is what the July cp_node_down and
// quorum_at_risk rows look like.
func TestResolveAlertsByKindWithoutDetailFilter(t *testing.T) {
	s, pg := resolveTestStore(t)
	ctx := context.Background()

	a := seedAlert(t, pg, "cp_node_down", "open", `{"node_id":3}`)
	b := seedAlert(t, pg, "quorum_at_risk", "open", "") // empty details object
	keep := seedAlert(t, pg, "node_down", "open", `{"node":"waf1"}`)
	already := seedAlert(t, pg, "cp_node_down", "resolved", `{"node_id":1}`)

	n, err := s.ResolveAlertsByKind(ctx, resolveTestTenant, "",
		[]string{"cp_node_down", "quorum_at_risk"}, "", nil, "stale")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if n != 2 {
		t.Fatalf("resolved %d rows, want 2", n)
	}
	for _, id := range []string{a, b} {
		if st, auto := alertState(t, pg, id); st != "resolved" || !auto {
			t.Fatalf("orphaned alert: state=%s auto=%v, want resolved/true", st, auto)
		}
	}
	if st, _ := alertState(t, pg, keep); st != "open" {
		t.Fatalf("other kind became %s, must be untouched", st)
	}
	if _, auto := alertState(t, pg, already); auto {
		t.Fatal("an already-resolved row must not be re-stamped")
	}
}

// A second sweep must change nothing. Reconciliation runs every ten seconds; if
// it were not idempotent it would rewrite resolved_at forever and the audit trail
// would be worthless.
func TestResolveAlertsByKindIsIdempotent(t *testing.T) {
	s, pg := resolveTestStore(t)
	ctx := context.Background()
	seedAlert(t, pg, "node_down", "open", `{"node":"waf1"}`)

	first, err := s.ResolveAlertsByKind(ctx, resolveTestTenant, "",
		[]string{"node_down"}, "node", []string{"waf1"}, "recovered")
	if err != nil || first != 1 {
		t.Fatalf("first sweep: n=%d err=%v, want 1/nil", first, err)
	}
	second, err := s.ResolveAlertsByKind(ctx, resolveTestTenant, "",
		[]string{"node_down"}, "node", []string{"waf1"}, "recovered")
	if err != nil {
		t.Fatalf("second sweep: %v", err)
	}
	if second != 0 {
		t.Fatalf("second sweep resolved %d rows, want 0 — not idempotent", second)
	}
}

// A detail key with no values must match nothing rather than degenerate into
// "every row of this kind". Guarded in the method; proven here because getting it
// wrong would silently close live alerts.
func TestResolveAlertsByKindEmptyValuesMatchesNothing(t *testing.T) {
	s, pg := resolveTestStore(t)
	ctx := context.Background()
	id := seedAlert(t, pg, "node_down", "open", `{"node":"waf1"}`)

	n, err := s.ResolveAlertsByKind(ctx, resolveTestTenant, "",
		[]string{"node_down"}, "node", nil, "should not happen")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if n != 0 {
		t.Fatalf("resolved %d rows with an empty value list, want 0", n)
	}
	if st, _ := alertState(t, pg, id); st != "open" {
		t.Fatalf("alert became %s with an empty value list, must stay open", st)
	}
}
