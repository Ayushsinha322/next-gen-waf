package db

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

// Integration tests for config snapshot + rollback.
//
// These need a real Postgres: the behaviour under test is what the SQL actually
// does to stored rows (snapshot contents, restore-by-ID, the retention cap), not
// anything a fake pool could demonstrate.
//
//	SENTINEL_TEST_DB_URL='postgres://sentinel:testpass@127.0.0.1:55435/sentinel?sslmode=disable' \
//	  go test ./internal/db/ -run TestConfigVersion -v
//
// Skipped when SENTINEL_TEST_DB_URL is unset.

const cfgTenant = "00000000-0000-0000-0000-0000000000cf"

func cfgTestStore(t *testing.T) (*Store, *pgxPool) {
	t.Helper()
	url := os.Getenv("SENTINEL_TEST_DB_URL")
	if url == "" {
		t.Skip("SENTINEL_TEST_DB_URL not set — skipping config-version integration test")
	}
	ctx := context.Background()
	pool, err := Open(ctx, Config{URL: url, MaxConns: 4, MinConns: 1})
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(pool.Close)
	pg := pool.(*pgxPool)

	for _, stmt := range []string{
		`DELETE FROM config_versions WHERE tenant_id = $1`,
		`DELETE FROM sites WHERE tenant_id = $1`,
	} {
		if _, err := pg.pool.Exec(ctx, stmt, cfgTenant); err != nil {
			t.Fatalf("cleanup %q: %v", stmt, err)
		}
	}
	if _, err := pg.pool.Exec(ctx, `
		INSERT INTO tenants (id, slug, name, plan, status)
		VALUES ($1, 'cfg-test', 'Config Test', 'enterprise', 'active')
		ON CONFLICT (id) DO NOTHING`, cfgTenant); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	return NewStore(pool), pg
}

func insertSite(t *testing.T, pg *pgxPool, name, mode string) string {
	t.Helper()
	var id string
	err := pg.pool.QueryRow(context.Background(), `
		INSERT INTO sites (tenant_id, name, domains, upstream, waf_policy, status)
		VALUES ($1, $2, $3, $4, $5, 'active')
		RETURNING id`,
		cfgTenant, name, []string{name},
		json.RawMessage(`{"servers":["10.0.0.1:80"],"lb":"round_robin"}`),
		json.RawMessage(`{"mode":"`+mode+`","paranoia_level":2,"anomaly_threshold":5}`),
	).Scan(&id)
	if err != nil {
		t.Fatalf("insert site %s: %v", name, err)
	}
	return id
}

func siteMode(t *testing.T, pg *pgxPool, id string) string {
	t.Helper()
	var raw json.RawMessage
	if err := pg.pool.QueryRow(context.Background(),
		`SELECT waf_policy FROM sites WHERE id = $1`, id).Scan(&raw); err != nil {
		t.Fatalf("read site policy: %v", err)
	}
	var p struct {
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("decode policy: %v", err)
	}
	return p.Mode
}

// TestConfigVersionRollbackRestoresPolicy is the core scenario: a tenant pushes a
// policy that breaks their site, and needs to get back to what worked. Before this
// existed there was no undo at all.
func TestConfigVersionRollbackRestoresPolicy(t *testing.T) {
	store, pg := cfgTestStore(t)
	ctx := context.Background()
	siteID := insertSite(t, pg, "rollback.example.com", "blocking")

	// Snapshot the good state, then break it — the same order the handlers use.
	versionID, err := store.SnapshotConfig(ctx, cfgTenant, "", "site.update")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if versionID == 0 {
		t.Fatal("snapshot returned no id")
	}
	if _, err := pg.pool.Exec(ctx,
		`UPDATE sites SET waf_policy = $2 WHERE id = $1`,
		siteID, json.RawMessage(`{"mode":"off"}`)); err != nil {
		t.Fatalf("break policy: %v", err)
	}
	if got := siteMode(t, pg, siteID); got != "off" {
		t.Fatalf("precondition failed: mode = %q", got)
	}

	restored, skipped, err := store.RestoreConfigVersion(ctx, cfgTenant, "", versionID)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if restored != 1 {
		t.Errorf("restored = %d, want 1", restored)
	}
	if len(skipped) != 0 {
		t.Errorf("unexpected skips: %v", skipped)
	}
	if got := siteMode(t, pg, siteID); got != "blocking" {
		t.Errorf("policy not restored: mode = %q, want blocking", got)
	}
}

// A rollback must not destroy sites added since the snapshot. Silently deleting
// unrelated sites while "undoing a policy change" would be far worse than the
// mistake being undone.
func TestConfigVersionRollbackLeavesNewerSitesAlone(t *testing.T) {
	store, pg := cfgTestStore(t)
	ctx := context.Background()
	oldID := insertSite(t, pg, "old.example.com", "blocking")

	versionID, err := store.SnapshotConfig(ctx, cfgTenant, "", "site.update")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	newID := insertSite(t, pg, "new.example.com", "learning")

	restored, skipped, err := store.RestoreConfigVersion(ctx, cfgTenant, "", versionID)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if restored != 1 {
		t.Errorf("restored = %d, want 1 (only the snapshotted site)", restored)
	}

	// The newer site must still exist, untouched, and be reported as skipped.
	var count int
	if err := pg.pool.QueryRow(ctx, `SELECT count(*) FROM sites WHERE id = $1`, newID).Scan(&count); err != nil {
		t.Fatalf("count new site: %v", err)
	}
	if count != 1 {
		t.Fatal("rollback DELETED a site created after the snapshot")
	}
	if got := siteMode(t, pg, newID); got != "learning" {
		t.Errorf("newer site was modified: mode = %q", got)
	}
	if len(skipped) == 0 {
		t.Error("the untouched newer site should have been reported in `skipped`")
	}
	_ = oldID
}

// A site deleted since the snapshot must not be resurrected, and the caller must
// be told rather than left assuming a complete revert.
func TestConfigVersionRollbackReportsDeletedSites(t *testing.T) {
	store, pg := cfgTestStore(t)
	ctx := context.Background()
	keepID := insertSite(t, pg, "keep.example.com", "blocking")
	goneID := insertSite(t, pg, "gone.example.com", "blocking")

	versionID, err := store.SnapshotConfig(ctx, cfgTenant, "", "site.delete")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if _, err := pg.pool.Exec(ctx, `DELETE FROM sites WHERE id = $1`, goneID); err != nil {
		t.Fatalf("delete site: %v", err)
	}

	restored, skipped, err := store.RestoreConfigVersion(ctx, cfgTenant, "", versionID)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if restored != 1 {
		t.Errorf("restored = %d, want 1", restored)
	}
	var count int
	if err := pg.pool.QueryRow(ctx, `SELECT count(*) FROM sites WHERE id = $1`, goneID).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Error("rollback resurrected a deliberately deleted site")
	}
	if len(skipped) == 0 {
		t.Error("the deleted site should have been reported in `skipped`")
	}
	_ = keepID
}

func TestConfigVersionListNewestFirst(t *testing.T) {
	store, pg := cfgTestStore(t)
	ctx := context.Background()
	insertSite(t, pg, "list.example.com", "blocking")

	for _, reason := range []string{"first", "second", "third"} {
		if _, err := store.SnapshotConfig(ctx, cfgTenant, "", reason); err != nil {
			t.Fatalf("snapshot %s: %v", reason, err)
		}
	}
	versions, err := store.ListConfigVersions(ctx, cfgTenant, "", 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(versions) != 3 {
		t.Fatalf("got %d versions, want 3", len(versions))
	}
	if versions[0].Reason != "third" {
		t.Errorf("newest-first ordering broken: %q first", versions[0].Reason)
	}
	if versions[0].SiteCount != 1 {
		t.Errorf("site_count = %d, want 1", versions[0].SiteCount)
	}
}

// History is bounded, or it would grow with write volume rather than with anything
// an operator cares about.
func TestConfigVersionRetentionCapEnforced(t *testing.T) {
	store, pg := cfgTestStore(t)
	ctx := context.Background()
	insertSite(t, pg, "cap.example.com", "blocking")

	for i := 0; i < maxConfigVersionsPerTenant+10; i++ {
		if _, err := store.SnapshotConfig(ctx, cfgTenant, "", "bulk"); err != nil {
			t.Fatalf("snapshot %d: %v", i, err)
		}
	}
	var count int
	if err := pg.pool.QueryRow(ctx,
		`SELECT count(*) FROM config_versions WHERE tenant_id = $1`, cfgTenant).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count > maxConfigVersionsPerTenant {
		t.Errorf("retained %d snapshots, cap is %d", count, maxConfigVersionsPerTenant)
	}
}

func TestConfigVersionRestoreUnknownIDFails(t *testing.T) {
	store, _ := cfgTestStore(t)
	if _, _, err := store.RestoreConfigVersion(context.Background(), cfgTenant, "", 999999); err == nil {
		t.Error("restoring a nonexistent version silently succeeded")
	}
}
