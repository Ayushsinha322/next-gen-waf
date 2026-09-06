package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// SettingRow is one operator-set global value. Keys are dotted, namespaced by
// subsystem (alerting.spike_threshold, threat_intel.feed.tor). Values are JSON so
// a key can be an int, bool or string without a schema change per key.
type SettingRow struct {
	Key       string          `json:"key"`
	Value     json.RawMessage `json:"value"`
	UpdatedAt time.Time       `json:"updated_at"`
	UpdatedBy *string         `json:"updated_by,omitempty"`
}

// EnsureSettingsSchema idempotently creates global_settings (+ RLS) so the
// Global Settings page works even when goose migrations were not run by hand.
// Same pattern as EnsureNotificationSchema; mirrored in 0021_global_settings.sql.
func EnsureSettingsSchema(ctx context.Context, pool Pool) error {
	pg, ok := pool.(*pgxPool)
	if !ok {
		return fmt.Errorf("settings schema: pool is not a *pgxPool")
	}
	const ddl = `
CREATE TABLE IF NOT EXISTS global_settings (
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key         TEXT NOT NULL,
    value       JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (tenant_id, key)
);
ALTER TABLE global_settings ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'global_settings' AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON global_settings
            USING  (tenant_id::text = current_setting('app.current_tenant', true))
            WITH CHECK (tenant_id::text = current_setting('app.current_tenant', true));
    END IF;
END $$;`
	if _, err := pg.pool.Exec(ctx, ddl); err != nil {
		return fmt.Errorf("settings schema: %w", err)
	}
	return nil
}

// ListSettings returns every operator-set value for the tenant, keyed by name.
func (s *Store) ListSettings(ctx context.Context, tenantID, userID string) (map[string]SettingRow, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx,
		`SELECT key, value, updated_at, updated_by FROM global_settings WHERE tenant_id = $1`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("store: list settings: %w", err)
	}
	defer rows.Close()
	out := map[string]SettingRow{}
	for rows.Next() {
		var r SettingRow
		if err := rows.Scan(&r.Key, &r.Value, &r.UpdatedAt, &r.UpdatedBy); err != nil {
			return nil, err
		}
		out[r.Key] = r
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	tx.Commit(ctx)
	return out, nil
}

// PutSettings upserts the given keys in one transaction. Validation of keys and
// values is the caller's job (see internal/settings); this only stores.
func (s *Store) PutSettings(ctx context.Context, tenantID, userID string, values map[string]json.RawMessage) error {
	if len(values) == 0 {
		return nil
	}
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var by *string
	if userID != "" {
		by = &userID
	}
	for k, v := range values {
		if err := tx.Exec(ctx,
			`INSERT INTO global_settings (tenant_id, key, value, updated_at, updated_by)
			 VALUES ($1, $2, $3, now(), $4)
			 ON CONFLICT (tenant_id, key) DO UPDATE
			   SET value = EXCLUDED.value, updated_at = now(), updated_by = EXCLUDED.updated_by`,
			tenantID, k, v, by); err != nil {
			return fmt.Errorf("store: put setting %s: %w", k, err)
		}
	}
	return tx.Commit(ctx)
}

// DeleteSetting removes an operator override so the key falls back to its
// environment or built-in default.
func (s *Store) DeleteSetting(ctx context.Context, tenantID, userID, key string) error {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := tx.Exec(ctx, `DELETE FROM global_settings WHERE tenant_id = $1 AND key = $2`, tenantID, key); err != nil {
		return fmt.Errorf("store: delete setting: %w", err)
	}
	return tx.Commit(ctx)
}
