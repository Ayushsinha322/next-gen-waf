-- Scope a custom rule to one site, or leave it deployment-wide.
--
-- `rules` had no site_id, so every operator-authored rule applied to every site
-- in the deployment. That is the right default for the case the feature exists
-- for — a virtual patch for a CVE should cover everything, not one hostname —
-- but it is wrong for the other half of the job. Tuning is inherently per-site:
-- a rule written to catch abuse of one application's checkout flow has no
-- business being evaluated against every other site, where it can only cost
-- latency and risk false positives.
--
-- NULL means deployment-wide, which is why the column is nullable rather than
-- defaulted: the existing rows genuinely are deployment-wide and must stay that
-- way, so this migration changes no behaviour for anything already stored.
--
-- ON DELETE CASCADE, not SET NULL: a rule written for a site that no longer
-- exists should go with it. Silently promoting it to deployment-wide would apply
-- a narrow, app-specific rule to every remaining site — the opposite of what its
-- author asked for, and a false-positive source nobody would think to look for.

-- +goose Up
-- +goose StatementBegin

ALTER TABLE rules
    ADD COLUMN IF NOT EXISTS site_id UUID REFERENCES sites(id) ON DELETE CASCADE;

COMMENT ON COLUMN rules.site_id IS
    'Site this rule applies to. NULL = every site in the deployment (use for virtual patches).';

-- Deployable-rule lookups filter on site, so index the column. Partial index:
-- the NULL (deployment-wide) rows are read on every sync regardless and gain
-- nothing from being indexed.
CREATE INDEX IF NOT EXISTS rules_site_idx ON rules(site_id) WHERE site_id IS NOT NULL;

-- Rebuild the carve-out to expose site_id. Same exclusions as 0017: 'crs' and
-- 'community' rows are demo fixtures that reuse real CRS ids (CRS-942100 is
-- rx /union|select|insert/ with a blocking action) and must never be delivered.
CREATE OR REPLACE FUNCTION sentinel_deployable_rules()
RETURNS TABLE (tenant_id uuid, site_id uuid, name text, dsl text,
               source text, phase int, severity text)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT r.tenant_id, r.site_id, r.name, r.dsl, r.source, r.phase, r.severity
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

DROP INDEX IF EXISTS rules_site_idx;
ALTER TABLE rules DROP COLUMN IF EXISTS site_id;

-- +goose StatementEnd
