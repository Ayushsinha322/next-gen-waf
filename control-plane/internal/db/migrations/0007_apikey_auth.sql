-- =====================================================================
-- Sentinel WAF — real API-key auth support
--
-- Adds a per-key RBAC role and a pre-auth lookup-by-hash carve-out. Like
-- sentinel_auth_lookup (login), machine auth by API key must find the key
-- BEFORE the tenant is known, which a tenant-scoped query under the
-- non-superuser sentinel_app role (FORCE RLS) cannot do — so it goes through a
-- SECURITY DEFINER function, tightly scoped to non-revoked, non-expired keys.
-- =====================================================================

-- +goose Up
-- +goose StatementBegin

-- Each API key carries an RBAC role, reusing the existing 5-role model so the
-- middleware can synthesize Claims{Role: ...} and the normal Enforcer applies.
ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS role text NOT NULL DEFAULT 'viewer'
    CHECK (role IN ('owner','admin','editor','viewer','auditor'));

CREATE OR REPLACE FUNCTION sentinel_apikey_lookup(p_hash text)
RETURNS TABLE (id uuid, tenant_id uuid, created_by uuid, role text, scopes text[])
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT k.id, k.tenant_id, k.created_by, k.role, k.scopes
    FROM api_keys k
    WHERE k.key_hash = p_hash
      AND k.revoked_at IS NULL
      AND (k.expires_at IS NULL OR k.expires_at > now())
    LIMIT 1
$$;

-- Best-effort last-used stamp (write, so it can't live in the STABLE lookup fn).
CREATE OR REPLACE FUNCTION sentinel_apikey_touch(p_id uuid)
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    UPDATE api_keys SET last_used_at = now() WHERE id = p_id
$$;

GRANT EXECUTE ON FUNCTION sentinel_apikey_lookup(text) TO sentinel_app;
GRANT EXECUTE ON FUNCTION sentinel_apikey_touch(uuid)  TO sentinel_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP FUNCTION IF EXISTS sentinel_apikey_lookup(text);
DROP FUNCTION IF EXISTS sentinel_apikey_touch(uuid);
ALTER TABLE api_keys DROP COLUMN IF EXISTS role;
-- +goose StatementEnd
