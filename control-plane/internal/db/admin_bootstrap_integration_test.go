//go:build integration || !unit

// Integration coverage for the bootstrap administrator and the break-glass
// reset.
//
//	SENTINEL_TEST_DB_URL='postgres://sentinel:testpass@127.0.0.1:55433/sentinel?sslmode=disable' \
//	  go test ./internal/db/ -run 'TestSeed|TestResetAdmin' -v
//
// Skipped when SENTINEL_TEST_DB_URL is unset, matching the other DB tests here.
package db

import (
	"context"
	"os"
	"testing"
)

const resetAdminTestTenant = "00000000-0000-0000-0000-0000000000ae"
const resetAdminOtherTenant = "00000000-0000-0000-0000-0000000000af"

func adminTestStore(t *testing.T) (*Store, *pgxPool) {
	t.Helper()
	url := os.Getenv("SENTINEL_TEST_DB_URL")
	if url == "" {
		t.Skip("SENTINEL_TEST_DB_URL not set — skipping admin bootstrap integration test")
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
		{resetAdminTestTenant, "reset-admin-test"},
		{resetAdminOtherTenant, "reset-admin-other"},
	} {
		if _, err := pg.pool.Exec(ctx, `
			INSERT INTO tenants (id, slug, name, plan, status)
			VALUES ($1, $2, 'Reset Admin Test', 'enterprise', 'active')
			ON CONFLICT (id) DO NOTHING`, tn.id, tn.slug); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
	}
	return NewStore(pool), pg
}

// The bootstrap admin was `ON CONFLICT (id) DO NOTHING` on every boot: delete
// it and the next restart put it back, with the bootstrap password still in
// .env. It is now created only into a tenant with no users at all.
func TestSeedDoesNotRecreateADeletedBootstrapAdmin(t *testing.T) {
	_, pg := adminTestStore(t)
	ctx := context.Background()
	if _, err := pg.pool.Exec(ctx, `DELETE FROM users WHERE tenant_id = $1`, DevTenantID); err != nil {
		t.Fatalf("clear default tenant: %v", err)
	}
	t.Setenv(BootstrapAdminEmailEnvVar, "noc@example.in")
	t.Setenv("SENTINEL_BOOTSTRAP_ADMIN_PASSWORD", "bootstrap-password-for-test")

	if err := SeedDev(ctx, pg); err != nil {
		t.Fatalf("first boot: %v", err)
	}
	var email string
	if err := pg.pool.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, DevAdminID).Scan(&email); err != nil {
		t.Fatalf("the first boot created no administrator: %v", err)
	}
	if email != "noc@example.in" {
		t.Fatalf("the administrator was created as %q, not the configured login", email)
	}

	// The operators take over: their own admin, the bootstrap one deleted.
	if _, err := pg.pool.Exec(ctx, `
		INSERT INTO users (tenant_id, email, name, password_hash, role, status)
		VALUES ($1, 'ops-lead@example.in', 'Ops Lead', 'x', 'admin', 'active')`, DevTenantID); err != nil {
		t.Fatalf("add operator: %v", err)
	}
	if _, err := pg.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, DevAdminID); err != nil {
		t.Fatalf("delete bootstrap admin: %v", err)
	}

	if err := SeedDev(ctx, pg); err != nil {
		t.Fatalf("second boot: %v", err)
	}
	var n int
	if err := pg.pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE id = $1`, DevAdminID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("the deleted bootstrap administrator was re-created on the next boot")
	}
}

func userState(t *testing.T, pg *pgxPool, id string) (role, status string, mfa bool, cut bool) {
	t.Helper()
	var secret *string
	var validFrom any
	if err := pg.pool.QueryRow(context.Background(), `
		SELECT role, status, mfa_secret, sessions_valid_from FROM users WHERE id = $1`, id).
		Scan(&role, &status, &secret, &validFrom); err != nil {
		t.Fatalf("read user %s: %v", id, err)
	}
	return role, status, secret != nil && *secret != "", validFrom != nil
}

func TestResetAdminRestoresAccessToAnExistingAccount(t *testing.T) {
	store, pg := adminTestStore(t)
	ctx := context.Background()
	if _, err := pg.pool.Exec(ctx, `DELETE FROM users WHERE tenant_id IN ($1, $2)`,
		resetAdminTestTenant, resetAdminOtherTenant); err != nil {
		t.Fatal(err)
	}
	var id string
	if err := pg.pool.QueryRow(ctx, `
		INSERT INTO users (tenant_id, email, name, password_hash, role, status, mfa_secret)
		VALUES ($1, 'Lead@Example.in', 'Lead', 'x', 'viewer', 'disabled', 'JBSWY3DPEHPK3PXP')
		RETURNING id`, resetAdminTestTenant).Scan(&id); err != nil {
		t.Fatal(err)
	}
	// The same login in another tenant must not be touched.
	var otherID string
	if err := pg.pool.QueryRow(ctx, `
		INSERT INTO users (tenant_id, email, name, password_hash, role, status)
		VALUES ($1, 'lead@example.in', 'Other', 'x', 'viewer', 'disabled')
		RETURNING id`, resetAdminOtherTenant).Scan(&otherID); err != nil {
		t.Fatal(err)
	}

	pw, created, got, err := store.ResetAdmin(ctx, resetAdminTestTenant, "lead@example.in")
	if err != nil {
		t.Fatalf("reset: %v", err)
	}
	if created || got != id {
		t.Fatalf("expected the existing account %s to be reset, got created=%v id=%s", id, created, got)
	}
	ok, err := store.VerifyUserPassword(ctx, resetAdminTestTenant, id, pw)
	if err != nil || !ok {
		t.Fatalf("the new password does not sign in: ok=%v err=%v", ok, err)
	}
	role, status, mfa, cut := userState(t, pg, id)
	if role != "admin" || status != "active" || mfa || !cut {
		t.Fatalf("after reset: role=%s status=%s mfa=%v sessions-cut=%v", role, status, mfa, cut)
	}
	if role, status, _, _ := userState(t, pg, otherID); role != "viewer" || status != "disabled" {
		t.Fatalf("the other tenant's account changed: role=%s status=%s", role, status)
	}
}

func TestResetAdminKeepsAnOwnerAnOwnerAndCreatesAMissingAccount(t *testing.T) {
	store, pg := adminTestStore(t)
	ctx := context.Background()
	if _, err := pg.pool.Exec(ctx, `DELETE FROM users WHERE tenant_id = $1`, resetAdminTestTenant); err != nil {
		t.Fatal(err)
	}
	var ownerID string
	if err := pg.pool.QueryRow(ctx, `
		INSERT INTO users (tenant_id, email, name, password_hash, role, status)
		VALUES ($1, 'owner@example.in', 'Owner', 'x', 'owner', 'active') RETURNING id`,
		resetAdminTestTenant).Scan(&ownerID); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.ResetAdmin(ctx, resetAdminTestTenant, "owner@example.in"); err != nil {
		t.Fatal(err)
	}
	if role, _, _, _ := userState(t, pg, ownerID); role != "owner" {
		t.Fatalf("an owner was demoted to %s", role)
	}

	pw, created, id, err := store.ResetAdmin(ctx, resetAdminTestTenant, "new-admin@example.in")
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("a login the tenant does not have must be created")
	}
	if ok, _ := store.VerifyUserPassword(ctx, resetAdminTestTenant, id, pw); !ok {
		t.Fatal("the created account's password does not sign in")
	}
	if role, status, _, _ := userState(t, pg, id); role != "admin" || status != "active" {
		t.Fatalf("created as role=%s status=%s", role, status)
	}

	if _, _, _, err := store.ResetAdmin(ctx, resetAdminTestTenant, "not-an-address"); err == nil {
		t.Fatal("a login that is not an email address was accepted")
	}
}
