-- =====================================================================
-- Sentinel WAF — tenant provisioning
--
-- Creating/suspending a tenant is a PLATFORM operation that legitimately spans
-- tenants and cannot satisfy an existing session's app.current_tenant WITH
-- CHECK. So it goes through SECURITY DEFINER functions (owner-owned, pinned
-- search_path), like the login + active-sites carve-outs — not the per-request
-- BeginTenant flow. App-layer authorization gates these to a platform admin.
-- =====================================================================

-- +goose Up
-- +goose StatementBegin

-- Create a tenant and its initial owner user in one atomic call.
CREATE OR REPLACE FUNCTION sentinel_create_tenant(
    p_slug text, p_name text, p_plan text,
    p_owner_email text, p_owner_name text, p_owner_pw_hash text)
RETURNS TABLE (tenant_id uuid, user_id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE t_id uuid; u_id uuid;
BEGIN
    INSERT INTO tenants (slug, name, plan)
    VALUES (p_slug, p_name, COALESCE(NULLIF(p_plan, ''), 'free'))
    RETURNING id INTO t_id;

    INSERT INTO users (tenant_id, email, name, password_hash, role, status)
    VALUES (t_id, p_owner_email, p_owner_name, p_owner_pw_hash, 'owner', 'active')
    RETURNING id INTO u_id;

    RETURN QUERY SELECT t_id, u_id;
END
$$;

-- Change a tenant's lifecycle status (active | suspended | deleted).
CREATE OR REPLACE FUNCTION sentinel_set_tenant_status(p_tenant_id uuid, p_status text)
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    UPDATE tenants SET status = p_status, updated_at = now() WHERE id = p_tenant_id
$$;

-- Platform-wide tenant list (excludes soft-deleted).
CREATE OR REPLACE FUNCTION sentinel_list_tenants()
RETURNS TABLE (id uuid, slug text, name text, plan text, status text, created_at timestamptz)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT id, slug, name, plan, status, created_at
    FROM tenants
    WHERE status <> 'deleted'
    ORDER BY created_at ASC
$$;

GRANT EXECUTE ON FUNCTION sentinel_create_tenant(text, text, text, text, text, text) TO sentinel_app;
GRANT EXECUTE ON FUNCTION sentinel_set_tenant_status(uuid, text)                     TO sentinel_app;
GRANT EXECUTE ON FUNCTION sentinel_list_tenants()                                    TO sentinel_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP FUNCTION IF EXISTS sentinel_create_tenant(text, text, text, text, text, text);
DROP FUNCTION IF EXISTS sentinel_set_tenant_status(uuid, text);
DROP FUNCTION IF EXISTS sentinel_list_tenants();
-- +goose StatementEnd
