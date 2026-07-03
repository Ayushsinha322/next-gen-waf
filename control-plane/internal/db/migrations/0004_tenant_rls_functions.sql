-- =====================================================================
-- Sentinel WAF — RLS carve-outs + non-superuser application role
--
-- With FORCE ROW LEVEL SECURITY (0003), a non-superuser app role is fully
-- tenant-isolated by the existing policies — EXCEPT for two operations that
-- legitimately span tenants:
--   1. Pre-auth user lookup by email (login does not yet know the tenant).
--   2. Node-global active-site list (the shared data plane serves every
--      tenant's sites).
--
-- Both are exposed as SECURITY DEFINER functions owned by the migration
-- (superuser) role, so they bypass RLS in a tightly-scoped, auditable way with
-- a pinned search_path. Everything else the app touches stays tenant-scoped by
-- RLS + the WHERE tenant_id predicates.
-- =====================================================================

-- +goose Up
-- +goose StatementBegin

CREATE OR REPLACE FUNCTION sentinel_auth_lookup(p_email text)
RETURNS TABLE (id uuid, tenant_id uuid, role text, password_hash text)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT u.id, u.tenant_id, u.role, u.password_hash
    FROM users u
    WHERE u.email = p_email
      AND u.status = 'active'
      AND u.password_hash IS NOT NULL
    LIMIT 1
$$;

CREATE OR REPLACE FUNCTION sentinel_active_sites()
RETURNS TABLE (id uuid, tenant_id uuid, name text, domains text[],
               upstream jsonb, waf_policy jsonb, status text,
               created_at timestamptz, updated_at timestamptz)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT s.id, s.tenant_id, s.name, s.domains, s.upstream, s.waf_policy,
           s.status, s.created_at, s.updated_at
    FROM sites s
    WHERE s.status <> 'deleted'
    ORDER BY s.created_at DESC
$$;

-- Non-superuser application role. Isolation comes from FORCE RLS (0003); the
-- two functions above are the only cross-tenant carve-outs. Created with LOGIN
-- but NO password — set it out-of-band and point the RUNTIME DSN at it:
--   ALTER ROLE sentinel_app PASSWORD '<strong-random>';
--   SENTINEL_DB_URL=postgres://sentinel_app:<pw>@postgres:5432/sentinel
-- Keep goose migrations running as the owner/superuser role.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_app') THEN
        CREATE ROLE sentinel_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
    END IF;
END $$;

GRANT USAGE ON SCHEMA public TO sentinel_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO sentinel_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sentinel_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO sentinel_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO sentinel_app;
GRANT EXECUTE ON FUNCTION sentinel_auth_lookup(text)  TO sentinel_app;
GRANT EXECUTE ON FUNCTION sentinel_active_sites()     TO sentinel_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP FUNCTION IF EXISTS sentinel_auth_lookup(text);
DROP FUNCTION IF EXISTS sentinel_active_sites();
-- The sentinel_app role is left in place (dropping a role in use elsewhere can
-- fail). To remove it manually:
--   DROP OWNED BY sentinel_app; DROP ROLE sentinel_app;
-- +goose StatementEnd
