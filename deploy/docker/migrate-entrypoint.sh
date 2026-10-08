#!/bin/sh
# The migrate job: goose, then the control plane's own database login.
#
# Migration 0023 creates sentinel_cp (not a superuser; sentinel_app's data
# privileges; bypasses row-level security for the single-customer stack) but
# cannot know its password. This sets it from SENTINEL_CP_DB_PASSWORD on every
# `up`, so changing it in .env and re-running the job rotates it. The role is
# created here too when missing: roles are cluster-wide and not in a database
# dump, so a restore into a fresh cluster has the schema and not the role.
# Unset (an installation from before this existed): nothing changes and the
# control plane keeps the login it has.
set -e
goose "$@"
case "${1:-up}" in up|up-to|up-by-one) ;; *) exit 0 ;; esac
[ -n "${SENTINEL_CP_DB_PASSWORD:-}" ] || exit 0
# The password goes in as a psql variable, quoted by psql, on stdin's SQL.
psql "$GOOSE_DBSTRING" -v ON_ERROR_STOP=1 -q -v pw="$SENTINEL_CP_DB_PASSWORD" <<'SQL'
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_cp') THEN
        CREATE ROLE sentinel_cp NOLOGIN NOSUPERUSER BYPASSRLS NOCREATEDB NOCREATEROLE;
    END IF;
END
$$;
GRANT sentinel_app TO sentinel_cp;
ALTER ROLE sentinel_cp WITH LOGIN PASSWORD :'pw';
SQL
echo "control-plane database login (sentinel_cp) ready"
