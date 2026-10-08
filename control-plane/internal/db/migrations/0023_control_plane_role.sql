-- =====================================================================
-- A non-superuser login role for the control plane.
--
-- The control plane connected as the Postgres superuser the container was
-- created with, so any SQL-level compromise of it was a superuser one: server
-- file access, COPY ... PROGRAM, ALTER SYSTEM (2026-10-07 review #20).
--
-- sentinel_cp holds the data privileges of sentinel_app (every table's DML,
-- the sequences, the lookup functions) and nothing else: no superuser, no
-- CREATE, no role administration. It BYPASSES row-level security, which suits
-- the dedicated per-customer stack this ships as: several cross-tenant reads
-- (plugin sync, report schedules, notification channels, session checks) run
-- without a tenant context and see nothing under RLS. Moving those to
-- SECURITY DEFINER functions is what lets the control plane run as
-- sentinel_app itself, the multi-tenant posture.
--
-- NOLOGIN here: a migration cannot know the password. The migrate job sets it
-- (LOGIN PASSWORD) from SENTINEL_CP_DB_PASSWORD on every run; see
-- deploy/docker/migrate-entrypoint.sh.
-- =====================================================================

-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_cp') THEN
        CREATE ROLE sentinel_cp NOLOGIN NOSUPERUSER BYPASSRLS NOCREATEDB NOCREATEROLE;
    END IF;
END
$$;
-- +goose StatementEnd
GRANT sentinel_app TO sentinel_cp;

-- +goose Down
REVOKE sentinel_app FROM sentinel_cp;
DROP ROLE IF EXISTS sentinel_cp;
