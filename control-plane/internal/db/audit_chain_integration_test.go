package db

import (
	"context"
	"os"
	"testing"
)

// Integration tests for audit-log tamper evidence.
//
// These need a real Postgres because the property under test is a property of the
// STORED log, not of a hash function: that removing or editing a row is detectable
// after the fact. Unit tests on auditChainMAC cannot show that.
//
// Run with a throwaway database:
//
//	docker run -d --rm --name pg -e POSTGRES_PASSWORD=testpass \
//	  -e POSTGRES_USER=sentinel -e POSTGRES_DB=sentinel -p 55433:5432 postgres:16-alpine
//	# apply internal/db/migrations/*.sql (goose Up sections), then:
//	SENTINEL_TEST_DB_URL='postgres://sentinel:testpass@127.0.0.1:55433/sentinel?sslmode=disable' \
//	  go test ./internal/db/ -run TestAuditChain -v
//
// Skipped when SENTINEL_TEST_DB_URL is unset.

const testTenant = "00000000-0000-0000-0000-0000000000aa"

func auditTestStore(t *testing.T) (*Store, *pgxPool, []byte) {
	t.Helper()
	url := os.Getenv("SENTINEL_TEST_DB_URL")
	if url == "" {
		t.Skip("SENTINEL_TEST_DB_URL not set — skipping audit-chain integration test")
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

	// Isolate each test run: fresh tenant, no audit rows.
	if _, err := pg.pool.Exec(ctx, `DELETE FROM audit_logs WHERE tenant_id = $1`, testTenant); err != nil {
		t.Fatalf("clean audit rows: %v", err)
	}
	if _, err := pg.pool.Exec(ctx, `
		INSERT INTO tenants (id, slug, name, plan, status)
		VALUES ($1, 'audit-test', 'Audit Test', 'enterprise', 'active')
		ON CONFLICT (id) DO NOTHING`, testTenant); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	return NewStore(pool), pg, []byte("integration-key-0123456789abcdef")
}

func writeAuditRows(t *testing.T, s *Store, key []byte, actions ...string) {
	t.Helper()
	for _, a := range actions {
		if err := s.WriteAuditLog(context.Background(), WriteAuditRequest{
			TenantID:   testTenant,
			Action:     a,
			TargetKind: "site",
		}, key); err != nil {
			t.Fatalf("write audit %q: %v", a, err)
		}
	}
}

func TestAuditChainVerifiesCleanLog(t *testing.T) {
	s, _, key := auditTestStore(t)
	writeAuditRows(t, s, key, "site.create", "site.update", "waf.disable", "site.delete")

	rep, err := s.VerifyAuditLog(context.Background(), testTenant, key, 0)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if rep.Checked != 4 {
		t.Errorf("Checked = %d, want 4", rep.Checked)
	}
	if !rep.OK() {
		t.Errorf("clean log failed verification: %+v", rep)
	}
	if rep.Unchained != 0 {
		t.Errorf("Unchained = %d, want 0 (all rows written post-migration)", rep.Unchained)
	}
}

// TestAuditChainDetectsDeletion is the whole point of the change. Under the
// previous per-row-HMAC design this deletion was completely invisible: every
// surviving row still verified, so an attacker could remove the record of their
// own action and the log would report itself intact.
func TestAuditChainDetectsDeletion(t *testing.T) {
	s, pg, key := auditTestStore(t)
	ctx := context.Background()
	writeAuditRows(t, s, key, "site.create", "waf.disable", "site.delete", "user.create")

	// Delete the incriminating middle row, exactly as an attacker with DB access
	// would. (The app role has DELETE revoked by migration 0013; this test
	// connects as the owner precisely to simulate someone who got past that.)
	ct, err := pg.pool.Exec(ctx,
		`DELETE FROM audit_logs WHERE tenant_id = $1 AND action = 'waf.disable'`, testTenant)
	if err != nil {
		t.Fatalf("delete row: %v", err)
	}
	if ct.RowsAffected() != 1 {
		t.Fatalf("expected to delete exactly 1 row, deleted %d", ct.RowsAffected())
	}

	rep, err := s.VerifyAuditLog(ctx, testTenant, key, 0)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if rep.OK() {
		t.Fatalf("DELETION WENT UNDETECTED — report: %+v", rep)
	}
	if len(rep.ChainBroken) == 0 {
		t.Errorf("expected a broken chain link, got none: %+v", rep)
	}
	if len(rep.SeqGaps) == 0 {
		t.Errorf("expected a seq gap, got none: %+v", rep)
	}
	// Every surviving row is byte-identical to when it was written, which is
	// exactly why per-row HMACs could not catch this.
	if len(rep.Altered) != 0 {
		t.Errorf("no row was edited, so Altered should be empty: %v", rep.Altered)
	}
}

// TestAuditChainDetectsTruncation covers removing the tail (the most recent
// entries), which leaves no gap in the middle to notice.
func TestAuditChainDetectsTruncation(t *testing.T) {
	s, pg, key := auditTestStore(t)
	ctx := context.Background()
	writeAuditRows(t, s, key, "a.1", "a.2", "a.3", "a.4")

	// Snapshot the head so we can prove the chain no longer reaches it.
	var headSeqBefore int64
	if err := pg.pool.QueryRow(ctx,
		`SELECT max(seq) FROM audit_logs WHERE tenant_id = $1`, testTenant).Scan(&headSeqBefore); err != nil {
		t.Fatalf("read head: %v", err)
	}

	if _, err := pg.pool.Exec(ctx,
		`DELETE FROM audit_logs WHERE tenant_id = $1 AND seq > $2`, testTenant, headSeqBefore-2); err != nil {
		t.Fatalf("truncate tail: %v", err)
	}

	rep, err := s.VerifyAuditLog(ctx, testTenant, key, 0)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	// The surviving prefix is internally consistent, so chain-link checks alone
	// cannot see a tail truncation. Detection requires comparing the observed head
	// against an independently recorded one — which is what an external anchor is
	// for. Assert the honest limitation rather than pretending otherwise.
	var headSeqAfter int64
	if err := pg.pool.QueryRow(ctx,
		`SELECT COALESCE(max(seq), 0) FROM audit_logs WHERE tenant_id = $1`, testTenant).Scan(&headSeqAfter); err != nil {
		t.Fatalf("read head after: %v", err)
	}
	if headSeqAfter >= headSeqBefore {
		t.Fatalf("tail was not actually truncated: %d -> %d", headSeqBefore, headSeqAfter)
	}
	if !rep.OK() {
		t.Logf("truncation additionally surfaced as %+v", rep)
	} else {
		t.Logf("as expected, a truncated prefix self-verifies (head seq %d -> %d); "+
			"detecting this needs an external head anchor", headSeqBefore, headSeqAfter)
	}
}

func TestAuditChainDetectsRowEdit(t *testing.T) {
	s, pg, key := auditTestStore(t)
	ctx := context.Background()
	writeAuditRows(t, s, key, "site.create", "waf.disable", "site.delete")

	// Rewrite history in place: make the damaging action look benign.
	if _, err := pg.pool.Exec(ctx,
		`UPDATE audit_logs SET action = 'site.view' WHERE tenant_id = $1 AND action = 'waf.disable'`,
		testTenant); err != nil {
		t.Fatalf("edit row: %v", err)
	}

	rep, err := s.VerifyAuditLog(ctx, testTenant, key, 0)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if rep.OK() {
		t.Fatalf("row edit went undetected: %+v", rep)
	}
	if len(rep.Altered) != 1 {
		t.Errorf("expected exactly 1 altered row, got %v", rep.Altered)
	}
}

func TestAuditChainDetectsReordering(t *testing.T) {
	s, pg, key := auditTestStore(t)
	ctx := context.Background()
	writeAuditRows(t, s, key, "first", "second")

	// Swap the two rows' positions in the chain.
	var s1, s2 int64
	if err := pg.pool.QueryRow(ctx,
		`SELECT min(seq), max(seq) FROM audit_logs WHERE tenant_id = $1`, testTenant).Scan(&s1, &s2); err != nil {
		t.Fatalf("read seqs: %v", err)
	}
	if _, err := pg.pool.Exec(ctx, `
		UPDATE audit_logs SET seq = -1 WHERE tenant_id = $1 AND seq = $2`, testTenant, s1); err != nil {
		t.Fatalf("park row: %v", err)
	}
	if _, err := pg.pool.Exec(ctx, `
		UPDATE audit_logs SET seq = $2 WHERE tenant_id = $1 AND seq = $3`, testTenant, s1, s2); err != nil {
		t.Fatalf("move row: %v", err)
	}
	if _, err := pg.pool.Exec(ctx, `
		UPDATE audit_logs SET seq = $2 WHERE tenant_id = $1 AND seq = -1`, testTenant, s2); err != nil {
		t.Fatalf("restore row: %v", err)
	}

	rep, err := s.VerifyAuditLog(ctx, testTenant, key, 0)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if rep.OK() {
		t.Fatalf("reordering went undetected: %+v", rep)
	}
}

// TestAuditChainConcurrentAppendsDoNotFork proves the advisory lock works: without
// it, two writers could read the same chain head and both link to it, silently
// forking the chain and making later verification meaningless.
func TestAuditChainConcurrentAppendsDoNotFork(t *testing.T) {
	s, _, key := auditTestStore(t)
	ctx := context.Background()

	const writers = 12
	errCh := make(chan error, writers)
	for i := 0; i < writers; i++ {
		go func() {
			errCh <- s.WriteAuditLog(ctx, WriteAuditRequest{
				TenantID:   testTenant,
				Action:     "concurrent.write",
				TargetKind: "site",
			}, key)
		}()
	}
	for i := 0; i < writers; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("concurrent write failed: %v", err)
		}
	}

	rep, err := s.VerifyAuditLog(ctx, testTenant, key, 0)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if rep.Checked != writers {
		t.Errorf("Checked = %d, want %d", rep.Checked, writers)
	}
	if !rep.OK() {
		t.Errorf("concurrent appends produced an invalid chain: %+v", rep)
	}
}

// TestAuditChainSurvivesUserDeletion pins migration 0025. audit_logs referenced
// users with ON DELETE SET NULL, so removing a user rewrote that user's past
// rows: their HMACs stopped recomputing and verification reported them ALTERED —
// a tamper alarm from an ordinary leaver removal, and the actor erased from the
// very rows that record what they did. Found on a fresh 1.1.20 stack 2026-10-19.
func TestAuditChainSurvivesUserDeletion(t *testing.T) {
	s, pg, key := auditTestStore(t)
	ctx := context.Background()

	var userID string
	if err := pg.pool.QueryRow(ctx, `
		INSERT INTO users (tenant_id, email, name, role, status)
		VALUES ($1, 'leaver@audit.test', 'Leaver', 'editor', 'active')
		ON CONFLICT DO NOTHING
		RETURNING id`, testTenant).Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	for _, a := range []string{"user.login", "site.update", "user.password.change"} {
		if err := s.WriteAuditLog(ctx, WriteAuditRequest{
			TenantID: testTenant, ActorUserID: &userID, Action: a, TargetKind: "user", TargetID: &userID,
		}, key); err != nil {
			t.Fatalf("write audit %q: %v", a, err)
		}
	}

	email, role, err := s.DeleteUser(ctx, testTenant, userID, userID)
	if err != nil {
		t.Fatalf("delete user: %v", err)
	}
	if email != "leaver@audit.test" || role != "editor" {
		t.Errorf("DeleteUser returned (%q, %q); the user.delete entry needs both", email, role)
	}

	rep, err := s.VerifyAuditLog(ctx, testTenant, key, 0)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !rep.OK() {
		t.Fatalf("deleting a user broke the audit chain — report: %+v", rep)
	}
	var stillNamed int
	if err := pg.pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND actor_user_id = $2`,
		testTenant, userID).Scan(&stillNamed); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if stillNamed != 3 {
		t.Errorf("%d of 3 rows still carry the deleted user's id; the actor must not be erased", stillNamed)
	}
}
