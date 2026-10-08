//go:build integration || !unit

//	SENTINEL_TEST_DB_URL='postgres://sentinel:testpass@127.0.0.1:55433/sentinel?sslmode=disable' \
//	  go test ./internal/db/ -run TestSeedAlertEmail -v
package db

import (
	"context"
	"testing"
)

func TestSeedAlertEmailChannelOnceOnly(t *testing.T) {
	_, pg := adminTestStore(t)
	ctx := context.Background()
	if err := SeedDev(ctx, pg); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := pg.pool.Exec(ctx, `DELETE FROM notification_channels WHERE tenant_id = $1`, DevTenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.pool.Exec(ctx, `DELETE FROM global_settings WHERE tenant_id = $1 AND key = $2`, DevTenantID, alertEmailSeededKey); err != nil {
		t.Fatal(err)
	}

	created, err := SeedAlertEmailChannel(ctx, pg, "noc@example.in")
	if err != nil || !created {
		t.Fatalf("first boot: created=%v err=%v", created, err)
	}
	var typ, sev, to string
	if err := pg.pool.QueryRow(ctx, `
		SELECT type, min_severity, config->>'to' FROM notification_channels
		WHERE tenant_id = $1 AND name = 'Operations email'`, DevTenantID).Scan(&typ, &sev, &to); err != nil {
		t.Fatalf("the channel was not stored (is the email type allowed by the schema?): %v", err)
	}
	if typ != "email" || sev != "high" || to != "noc@example.in" {
		t.Fatalf("stored as %s/%s/%s", typ, sev, to)
	}

	// The operator deletes it; the next boot must not bring it back.
	if _, err := pg.pool.Exec(ctx, `DELETE FROM notification_channels WHERE tenant_id = $1`, DevTenantID); err != nil {
		t.Fatal(err)
	}
	created, err = SeedAlertEmailChannel(ctx, pg, "noc@example.in")
	if err != nil || created {
		t.Fatalf("second boot re-created a deleted channel: created=%v err=%v", created, err)
	}
}
