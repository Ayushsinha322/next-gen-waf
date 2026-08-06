-- Config version snapshots, for one-click rollback of site configuration.
--
-- Before this, a bad policy push had no undo. Config reached the data plane by a
-- 5-second REST poll that blind-merged whatever the control plane served
-- (update_sites in crates/sentinel-core/src/config/mod.rs), and the only way back
-- from a mistake was to remember the previous values and re-enter them by hand —
-- while the affected site was already misconfigured or unprotected.
--
-- Each row is a point-in-time snapshot of one tenant's site configuration, taken
-- immediately BEFORE a mutation is applied. Snapshotting before rather than after
-- is what makes the most recent snapshot the state to return to: the config that
-- was working a moment ago.
--
-- Scope is deliberately per-tenant site configuration, not the whole database.
-- Restoring arbitrary rows across every table would be a general-purpose
-- point-in-time restore, which is what CloudNativePG backups are for. This targets
-- the specific failure the fix is about: a tenant pushing a policy that breaks
-- their own site.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS config_versions (
    id          bigserial   PRIMARY KEY,
    tenant_id   uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The config_generation value current when this snapshot was taken.
    generation  bigint      NOT NULL,
    -- Full site rows for the tenant, as a JSON array.
    sites       jsonb       NOT NULL,
    -- What was about to happen when this snapshot was taken, e.g. "site.update".
    reason      text        NOT NULL DEFAULT '',
    created_by  uuid,
    created_at  timestamptz NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS config_versions_tenant_time_idx
    ON config_versions(tenant_id, created_at DESC);
-- +goose StatementEnd

-- +goose StatementBegin
-- Tenant-scoped like every other tenant table, so one tenant can never read or
-- restore another's configuration history.
ALTER TABLE config_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE config_versions FORCE ROW LEVEL SECURITY;
-- +goose StatementEnd

-- +goose StatementBegin
-- Same predicate every other tenant table uses (see 0001_init.sql): the tenant is
-- carried in the `app.current_tenant` setting that BeginTenant sets per transaction.
DROP POLICY IF EXISTS tenant_isolation ON config_versions;
CREATE POLICY tenant_isolation ON config_versions
    USING  (tenant_id::text = current_setting('app.current_tenant', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant', true));
-- +goose StatementEnd

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, DELETE ON config_versions TO sentinel_app';
        EXECUTE 'GRANT USAGE, SELECT ON SEQUENCE config_versions_id_seq TO sentinel_app';
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS config_versions;
-- +goose StatementEnd
