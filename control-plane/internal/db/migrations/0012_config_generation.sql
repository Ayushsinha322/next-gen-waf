-- Config generation counter — a single source of truth for the data-plane
-- config-freshness signal.
--
-- Previously the /internal/config "version" was a per-process atomic.Int64 that
-- was bumped ONLY inside the Raft leader's write handlers and never replicated
-- (the FSM Apply hook is a no-op) or persisted. After any leader change the node
-- the data plane polls froze its counter, so new/edited/deleted sites silently
-- stopped reaching the proxy (R4), and round-robin across nodes returned
-- oscillating values causing constant redundant re-syncs (R8).
--
-- A statement-level trigger on sites+rules increments a single shared row on
-- EVERY mutation path (dashboard API, Config-as-Code import, geoip, exclusions,
-- rule CRUD — which previously bumped nothing) with no per-handler bookkeeping.
-- Read via a SECURITY DEFINER function so the non-superuser sentinel_app runtime
-- role (FORCE RLS, see 0003/0004) can read it. Any control-plane node now returns
-- the same monotonic, restart-surviving value derived from shared Postgres.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS config_generation (
    id  boolean PRIMARY KEY DEFAULT true CHECK (id),
    gen bigint  NOT NULL DEFAULT 1
);
INSERT INTO config_generation (id, gen) VALUES (true, 1) ON CONFLICT DO NOTHING;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION bump_config_generation() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    UPDATE config_generation SET gen = gen + 1 WHERE id = true;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION sentinel_config_version() RETURNS bigint
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT gen FROM config_generation WHERE id = true
$$;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TRIGGER IF EXISTS trg_sites_cfggen ON sites;
CREATE TRIGGER trg_sites_cfggen AFTER INSERT OR UPDATE OR DELETE ON sites
    FOR EACH STATEMENT EXECUTE FUNCTION bump_config_generation();
-- +goose StatementEnd

-- +goose StatementBegin
DROP TRIGGER IF EXISTS trg_rules_cfggen ON rules;
CREATE TRIGGER trg_rules_cfggen AFTER INSERT OR UPDATE OR DELETE ON rules
    FOR EACH STATEMENT EXECUTE FUNCTION bump_config_generation();
-- +goose StatementEnd

-- +goose StatementBegin
GRANT EXECUTE ON FUNCTION sentinel_config_version() TO sentinel_app;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS trg_sites_cfggen ON sites;
DROP TRIGGER IF EXISTS trg_rules_cfggen ON rules;
DROP FUNCTION IF EXISTS sentinel_config_version();
DROP FUNCTION IF EXISTS bump_config_generation();
DROP TABLE IF EXISTS config_generation;
-- +goose StatementEnd
