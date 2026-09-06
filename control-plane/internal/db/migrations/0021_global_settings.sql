-- Global settings: operator-set values for node-wide subsystems the console
-- could not touch before (alert thresholds, threat-intel feeds). Until now every
-- one of these lived only in the control plane's environment, so changing an
-- alert threshold meant editing .env and recreating the container, with no
-- audit trail. Values are JSONB so one table serves ints, bools and strings;
-- the allowed keys and their validation live in internal/settings.
--
-- Mirrored by db.EnsureSettingsSchema for deployments that never ran goose.

-- +goose Up
CREATE TABLE IF NOT EXISTS global_settings (
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key         TEXT NOT NULL,
    value       JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (tenant_id, key)
);
ALTER TABLE global_settings ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON global_settings
    USING  (tenant_id::text = current_setting('app.current_tenant', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant', true));

-- +goose Down
DROP TABLE IF EXISTS global_settings;
