-- =====================================================================
-- Sentinel WAF — SSO (OIDC) user lookup carve-out
--
-- sentinel_auth_lookup requires password_hash IS NOT NULL, so it deliberately
-- excludes SSO users (who have no password). OIDC login must map the verified
-- identity to a REAL provisioned user (its tenant + role) rather than minting a
-- fixed dev-tenant editor. This SECURITY DEFINER lookup finds an active user by
-- email across tenants (pre-auth, tenant unknown) under FORCE RLS, mirroring
-- sentinel_auth_lookup.
-- =====================================================================

-- +goose Up
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION sentinel_sso_lookup(p_email text)
RETURNS TABLE (id uuid, tenant_id uuid, role text)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT u.id, u.tenant_id, u.role
    FROM users u
    WHERE u.email = p_email
      AND u.status = 'active'
    LIMIT 1
$$;

GRANT EXECUTE ON FUNCTION sentinel_sso_lookup(text) TO sentinel_app;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP FUNCTION IF EXISTS sentinel_sso_lookup(text);
-- +goose StatementEnd
