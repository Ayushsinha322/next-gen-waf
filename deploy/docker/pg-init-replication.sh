#!/usr/bin/env bash
# Primary-side replication setup, run ONCE by the postgres image's initdb hook
# (/docker-entrypoint-initdb.d). Creates the replication role and allows the standby
# host to open a replication connection.
#
# This runs only on a fresh data directory, which is the correct scope: pg_hba and the
# replication role are cluster-level state that must not be rewritten on every boot.
set -euo pipefail

: "${SENTINEL_REPL_USER:?SENTINEL_REPL_USER is required}"
: "${SENTINEL_REPL_PASSWORD:?SENTINEL_REPL_PASSWORD is required}"
# CIDR the standby connects from. Keep it as tight as the network allows — this is a
# replication grant, which streams the entire database.
: "${SENTINEL_STANDBY_CIDR:?SENTINEL_STANDBY_CIDR is required (e.g. 172.16.21.72/32)}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<SQL
  CREATE ROLE "${SENTINEL_REPL_USER}" WITH REPLICATION LOGIN PASSWORD '${SENTINEL_REPL_PASSWORD}';
  -- A physical replication slot so the primary retains WAL the standby has not yet
  -- consumed. Without it, a standby that falls behind (or is briefly down) can miss
  -- WAL that has already been recycled and must be rebuilt from scratch.
  SELECT pg_create_physical_replication_slot('sentinel_standby');
SQL

# Replication connections need their own pg_hba entry; the image's defaults cover
# ordinary connections only. scram-sha-256 so the replication password is never sent
# in the clear, and hostssl so the stream itself is encrypted — the same standard the
# application DSN is held to (sslmode=verify-full).
cat >> "$PGDATA/pg_hba.conf" <<HBA

# ── Sentinel: streaming replication from the passive VM ──────────────────────
# hostssl (not host): the WAL stream carries every row in the database, so it must
# not cross the network unencrypted.
hostssl replication ${SENTINEL_REPL_USER} ${SENTINEL_STANDBY_CIDR} scram-sha-256
HBA

echo "[sentinel] replication role, slot and hostssl pg_hba entry created for ${SENTINEL_STANDBY_CIDR}"
