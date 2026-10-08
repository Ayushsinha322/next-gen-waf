package db

import (
	"context"
	"encoding/json"
	"fmt"
)

// alertEmailSeededKey marks, in global_settings, that the installer's alert
// address has been turned into a channel. Not a registered setting: Snapshot
// ignores keys it does not know, and the console never lists it.
const alertEmailSeededKey = "alerts.email_channel_seeded"

// SeedAlertEmailChannel creates the "Operations email" channel for the address
// the installer asked for (SENTINEL_ALERT_EMAIL), the first time the control
// plane boots with it. Once only: like the bootstrap administrator, a channel
// an operator deleted or changed must not come back on the next restart, so a
// marker records that it was done. Reports whether a channel was created.
func SeedAlertEmailChannel(ctx context.Context, pool Pool, to string) (bool, error) {
	pg, ok := pool.(*pgxPool)
	if !ok {
		return false, fmt.Errorf("seed alert email: pool is not a *pgxPool")
	}
	tx, err := pg.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)

	var done bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM global_settings WHERE tenant_id = $1 AND key = $2)`,
		DevTenantID, alertEmailSeededKey).Scan(&done); err != nil {
		return false, fmt.Errorf("seed alert email: %w", err)
	}
	if done {
		return false, nil
	}
	cfg, _ := json.Marshal(map[string]string{"to": to})
	tag, err := tx.Exec(ctx, `
		INSERT INTO notification_channels (tenant_id, name, type, config, min_severity, enabled)
		VALUES ($1, 'Operations email', 'email', $2, 'high', true)
		ON CONFLICT (tenant_id, name) DO NOTHING`, DevTenantID, cfg)
	if err != nil {
		return false, fmt.Errorf("seed alert email: channel: %w", err)
	}
	marker, _ := json.Marshal(to)
	if _, err := tx.Exec(ctx, `
		INSERT INTO global_settings (tenant_id, key, value) VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id, key) DO NOTHING`, DevTenantID, alertEmailSeededKey, marker); err != nil {
		return false, fmt.Errorf("seed alert email: marker: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}
