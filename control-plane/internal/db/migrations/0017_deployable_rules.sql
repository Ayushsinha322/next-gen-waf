-- Cross-tenant carve-out so the data-plane config sync can read operator-authored
-- rules, mirroring sentinel_active_sites() from migration 0004.
--
-- Why a SECURITY DEFINER function rather than a plain SELECT: /internal/config is
-- node-global — one data plane serves every tenant's sites — but FORCE RLS (0003)
-- scopes `rules` to the session's tenant. A direct query returns ZERO rows under
-- the non-superuser sentinel_app role, and zero rows is indistinguishable from
-- "this deployment has no custom rules". That failure mode is silent and it fails
-- OPEN: the rules simply stop being enforced with nothing logged. The carve-out
-- makes the cross-tenant read explicit and auditable, exactly as 0004 did for sites.
--
-- WHAT IS DEPLOYABLE, and why the source filter is not optional:
--
--   Rows with source 'crs' or 'community' are NOT returned. Those are demo
--   fixtures seeded only under SENTINEL_DEV_SEED, and they are crude
--   reimplementations that REUSE REAL CRS RULE IDS — 'CRS-942100' is
--   rx("union|select|insert") with a blocking action. Shipping that to the data
--   plane would block any request containing the word "select" while colliding
--   with the genuine 942100 loaded from the CRS conf files. Real CRS rules reach
--   the data plane as files, never through this table.
--
-- Only enabled rows are returned, so the UI's enable/disable toggle becomes the
-- real kill switch it already appears to be.

-- +goose Up
-- +goose StatementBegin

CREATE OR REPLACE FUNCTION sentinel_deployable_rules()
RETURNS TABLE (tenant_id uuid, name text, dsl text, source text, phase int, severity text)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT r.tenant_id, r.name, r.dsl, r.source, r.phase, r.severity
    FROM rules r
    WHERE r.enabled
      AND r.source NOT IN ('crs', 'community')
    ORDER BY r.tenant_id, r.created_at
$$;

REVOKE ALL ON FUNCTION sentinel_deployable_rules() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinel_deployable_rules() TO sentinel_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP FUNCTION IF EXISTS sentinel_deployable_rules();

-- +goose StatementEnd
