-- =====================================================================
-- Sentinel WAF — Tenant-isolation hardening
--
-- The tenant_isolation RLS policies from 0001/0002 are correct, but two gaps
-- made them a no-op as originally deployed:
--   1. Tables used ENABLE (not FORCE) ROW LEVEL SECURITY, so the *table owner*
--      bypassed RLS entirely.
--   2. The control plane connected as the table-owning superuser, which
--      bypasses RLS regardless of ENABLE/FORCE.
--
-- This migration closes gap #1 by FORCE-ing RLS on every tenant-scoped table.
-- Gap #2 is closed operationally: the control plane must connect as a
-- NON-superuser, NON-owner role. A runbook for that is at the bottom of this
-- file, kept as comments so it does not run automatically and lock out the
-- current deployment.
--
-- Safe to apply as-is: while the app still connects as a superuser, FORCE RLS
-- is bypassed (no behavior change); once it connects as sentinel_app, the
-- existing per-tenant policies begin enforcing isolation.
-- =====================================================================

-- +goose Up
-- +goose StatementBegin
ALTER TABLE users        FORCE ROW LEVEL SECURITY;
ALTER TABLE api_keys     FORCE ROW LEVEL SECURITY;
ALTER TABLE sites        FORCE ROW LEVEL SECURITY;
ALTER TABLE rules        FORCE ROW LEVEL SECURITY;
ALTER TABLE plugins      FORCE ROW LEVEL SECURITY;
ALTER TABLE ml_profiles  FORCE ROW LEVEL SECURITY;
ALTER TABLE ip_lists     FORCE ROW LEVEL SECURITY;
ALTER TABLE alerts       FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_logs   FORCE ROW LEVEL SECURITY;

-- notification_channels is created by 0002; guard in case ordering differs.
DO $$ BEGIN
    IF to_regclass('public.notification_channels') IS NOT NULL THEN
        EXECUTE 'ALTER TABLE notification_channels FORCE ROW LEVEL SECURITY';
    END IF;
END $$;
-- +goose StatementEnd

-- ---------------------------------------------------------------------
-- OPERATOR RUNBOOK (manual — intentionally NOT executed by this migration)
--
-- FORCE RLS above only takes effect for a non-superuser role. Create a
-- dedicated application role and point SENTINEL_DB_URL at it (keep migrations
-- running as the owner/superuser role):
--
--   CREATE ROLE sentinel_app LOGIN PASSWORD '<strong-random>' NOSUPERUSER NOBYPASSRLS;
--   GRANT CONNECT ON DATABASE sentinel TO sentinel_app;
--   GRANT USAGE ON SCHEMA public TO sentinel_app;
--   GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO sentinel_app;
--   GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sentinel_app;
--   ALTER DEFAULT PRIVILEGES IN SCHEMA public
--       GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO sentinel_app;
--   -- then set: SENTINEL_DB_URL=postgres://sentinel_app:<pw>@postgres:5432/sentinel
--
-- NOTE: full multi-tenant isolation also requires login to assign each user's
-- real tenant_id (today it is hardcoded to the dev tenant) and tenant-scoped
-- ClickHouse queries. See the readiness report's Phase 2.
-- ---------------------------------------------------------------------

-- +goose Down
-- +goose StatementBegin
ALTER TABLE users        NO FORCE ROW LEVEL SECURITY;
ALTER TABLE api_keys     NO FORCE ROW LEVEL SECURITY;
ALTER TABLE sites        NO FORCE ROW LEVEL SECURITY;
ALTER TABLE rules        NO FORCE ROW LEVEL SECURITY;
ALTER TABLE plugins      NO FORCE ROW LEVEL SECURITY;
ALTER TABLE ml_profiles  NO FORCE ROW LEVEL SECURITY;
ALTER TABLE ip_lists     NO FORCE ROW LEVEL SECURITY;
ALTER TABLE alerts       NO FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_logs   NO FORCE ROW LEVEL SECURITY;
DO $$ BEGIN
    IF to_regclass('public.notification_channels') IS NOT NULL THEN
        EXECUTE 'ALTER TABLE notification_channels NO FORCE ROW LEVEL SECURITY';
    END IF;
END $$;
-- +goose StatementEnd
