//go:build integration || !unit

// A role change or a disable must set the session cut-off IN THE DATABASE, so
// every control-plane node signs the user out — not only the one that ran it.
package db

import (
	"context"
	"testing"
	"time"
)

func cutoff(t *testing.T, pg *pgxPool, id string) *time.Time {
	t.Helper()
	var ts *time.Time
	if err := pg.pool.QueryRow(context.Background(),
		`SELECT sessions_valid_from FROM users WHERE id = $1`, id).Scan(&ts); err != nil {
		t.Fatal(err)
	}
	return ts
}

func TestRoleChangeAndDisableSetTheSessionCutoff(t *testing.T) {
	s, pg := markLoginTestStore(t)
	ctx := context.Background()
	reset := func(id string) {
		if _, err := pg.pool.Exec(ctx, `UPDATE users SET role='admin', status='active', sessions_valid_from=NULL WHERE id=$1`, id); err != nil {
			t.Fatal(err)
		}
	}
	id := seedLoginUser(t, pg, markLoginTestTenant, "signout@example.test")

	reset(id)
	if err := s.UpdateUser(ctx, markLoginTestTenant, "", id, "viewer", ""); err != nil {
		t.Fatal(err)
	}
	if cutoff(t, pg, id) == nil {
		t.Fatal("a role change must set sessions_valid_from — the demoted user kept admin rights in their token")
	}

	reset(id)
	if err := s.UpdateUser(ctx, markLoginTestTenant, "", id, "", "disabled"); err != nil {
		t.Fatal(err)
	}
	if cutoff(t, pg, id) == nil {
		t.Fatal("disabling must set sessions_valid_from")
	}

	// No-op updates and re-enabling do not sign anyone out.
	for _, c := range []struct{ role, status string }{{"admin", ""}, {"", "active"}} {
		reset(id)
		if err := s.UpdateUser(ctx, markLoginTestTenant, "", id, c.role, c.status); err != nil {
			t.Fatal(err)
		}
		if cutoff(t, pg, id) != nil {
			t.Fatalf("role=%q status=%q changed nothing and must not sign the user out", c.role, c.status)
		}
	}

	ids, err := s.UserIDs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ids[id]; !ok {
		t.Fatal("UserIDs must list existing users")
	}
}
