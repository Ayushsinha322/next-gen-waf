//go:build integration || !unit

// Integration coverage for MarkLogin.
//
//	SENTINEL_TEST_DB_URL='postgres://sentinel:testpass@127.0.0.1:55433/sentinel?sslmode=disable' \
//	  go test ./internal/db/ -run TestMarkLogin -v
//
// Skipped when SENTINEL_TEST_DB_URL is unset, matching the other DB tests here.
//
// Why a real database: the statement runs inside BeginTenant, so it is subject
// to row-level security and to the tenant GUC the pool sets. A mock would
// happily report success for an UPDATE that RLS silently filtered to zero rows,
// which is the exact failure this column already suffered — it existed, it was
// selected, it was returned to the console, and nothing ever wrote it, so every
// account read "Never" from the first migration onwards.
package db

import (
	"context"
	"os"
	"testing"
	"time"
)

const markLoginTestTenant = "00000000-0000-0000-0000-0000000000ac"
const markLoginOtherTenant = "00000000-0000-0000-0000-0000000000ad"

func markLoginTestStore(t *testing.T) (*Store, *pgxPool) {
	t.Helper()
	url := os.Getenv("SENTINEL_TEST_DB_URL")
	if url == "" {
		t.Skip("SENTINEL_TEST_DB_URL not set — skipping mark-login integration test")
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
	for _, tn := range []struct{ id, slug string }{
		{markLoginTestTenant, "marklogin-test"},
		{markLoginOtherTenant, "marklogin-other"},
	} {
		if _, err := pg.pool.Exec(ctx, `
			INSERT INTO tenants (id, slug, name, plan, status)
			VALUES ($1, $2, 'Mark Login Test', 'enterprise', 'active')
			ON CONFLICT (id) DO NOTHING`, tn.id, tn.slug); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
	}
	return NewStore(pool), pg
}

func seedLoginUser(t *testing.T, pg *pgxPool, tenant, email string) string {
	t.Helper()
	var id string
	err := pg.pool.QueryRow(context.Background(), `
		INSERT INTO users (tenant_id, email, name, role, status, password_hash)
		VALUES ($1, $2, 'Test User', 'admin', 'active', 'x')
		ON CONFLICT (tenant_id, email) DO UPDATE SET last_login_at = NULL
		RETURNING id`, tenant, email).Scan(&id)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

func lastLogin(t *testing.T, pg *pgxPool, userID string) *time.Time {
	t.Helper()
	var ts *time.Time
	if err := pg.pool.QueryRow(context.Background(),
		`SELECT last_login_at FROM users WHERE id = $1`, userID).Scan(&ts); err != nil {
		t.Fatalf("read last_login_at: %v", err)
	}
	return ts
}

// A fresh account has never signed in, and signing in records when.
func TestMarkLoginStampsTheUser(t *testing.T) {
	store, pg := markLoginTestStore(t)
	id := seedLoginUser(t, pg, markLoginTestTenant, "stamp@example.test")

	if ts := lastLogin(t, pg, id); ts != nil {
		t.Fatalf("a freshly seeded user should have no login recorded, got %v", ts)
	}

	before := time.Now().Add(-time.Minute)
	if err := store.MarkLogin(context.Background(), markLoginTestTenant, id); err != nil {
		t.Fatalf("MarkLogin: %v", err)
	}

	ts := lastLogin(t, pg, id)
	if ts == nil {
		t.Fatal("last_login_at is still NULL after MarkLogin — the column that " +
			"read \"Never\" for every account is still not being written")
	}
	if ts.Before(before) {
		t.Fatalf("last_login_at is not recent: %v", ts)
	}
}

// Signing in again moves the timestamp forward, so the column answers "when
// last", not "when first".
func TestMarkLoginAdvancesOnEachLogin(t *testing.T) {
	store, pg := markLoginTestStore(t)
	id := seedLoginUser(t, pg, markLoginTestTenant, "advance@example.test")
	ctx := context.Background()

	if err := store.MarkLogin(ctx, markLoginTestTenant, id); err != nil {
		t.Fatalf("first MarkLogin: %v", err)
	}
	first := lastLogin(t, pg, id)

	time.Sleep(10 * time.Millisecond)
	if err := store.MarkLogin(ctx, markLoginTestTenant, id); err != nil {
		t.Fatalf("second MarkLogin: %v", err)
	}
	second := lastLogin(t, pg, id)

	if first == nil || second == nil {
		t.Fatal("both logins should be recorded")
	}
	if !second.After(*first) {
		t.Fatalf("second login did not advance the stamp: %v then %v", *first, *second)
	}
}

// The write is scoped by tenant as well as by id. Passing another tenant's id
// must change nothing rather than quietly stamping a stranger's account.
func TestMarkLoginWillNotCrossTenants(t *testing.T) {
	store, pg := markLoginTestStore(t)
	victim := seedLoginUser(t, pg, markLoginOtherTenant, "victim@example.test")

	err := store.MarkLogin(context.Background(), markLoginTestTenant, victim)
	if err == nil {
		t.Fatal("MarkLogin reported success for a user in a different tenant")
	}
	if ts := lastLogin(t, pg, victim); ts != nil {
		t.Fatalf("another tenant's user was stamped: %v", ts)
	}
}

// The console reads this through ListUsers, so the value has to survive that
// path too — the field was being read under the wrong name for a long time.
func TestListUsersReturnsTheRecordedLogin(t *testing.T) {
	store, pg := markLoginTestStore(t)
	id := seedLoginUser(t, pg, markLoginTestTenant, "listed@example.test")
	ctx := context.Background()

	if err := store.MarkLogin(ctx, markLoginTestTenant, id); err != nil {
		t.Fatalf("MarkLogin: %v", err)
	}

	users, err := store.ListUsers(ctx, markLoginTestTenant, id)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	for _, u := range users {
		if u.ID == id {
			if u.LastLoginAt == nil {
				t.Fatal("ListUsers returned no last login for a user who just signed in")
			}
			return
		}
	}
	t.Fatal("seeded user not returned by ListUsers")
}
