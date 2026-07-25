#!/usr/bin/env bash
# Standby-side bootstrap for the 2-VM active-passive topology.
#
# Used as the postgres container's entrypoint on the PASSIVE VM. On an empty data
# directory it takes a base backup from the primary and configures streaming
# replication; on a populated one it just starts, so a restart does not re-clone.
#
# Deliberately idempotent and non-destructive: it will NOT wipe an existing data
# directory. If the standby has diverged (e.g. it was promoted and then demoted
# without a rebuild) the operator must remove the volume explicitly. Silently
# re-cloning could destroy the only surviving copy of the data.
set -euo pipefail

: "${SENTINEL_PRIMARY_HOST:?SENTINEL_PRIMARY_HOST is required (active VM address)}"
: "${SENTINEL_REPL_USER:?SENTINEL_REPL_USER is required}"
: "${SENTINEL_REPL_PASSWORD:?SENTINEL_REPL_PASSWORD is required}"
PRIMARY_PORT="${SENTINEL_PRIMARY_PORT:-5432}"
CA_PATH="${SENTINEL_PG_CA:-/etc/sentinel/pki/root.crt}"
PGDATA="${PGDATA:-/var/lib/postgresql/data}"

if [[ -s "$PGDATA/PG_VERSION" ]]; then
  echo "[sentinel] data directory already initialised — starting without re-cloning."
  if [[ -f "$PGDATA/standby.signal" ]]; then
    echo "[sentinel] standby.signal present → resuming as a streaming standby."
  else
    echo "[sentinel] NOTE: no standby.signal. This node will start as a PRIMARY."
    echo "[sentinel]       That is expected after a promotion. To make it a standby"
    echo "[sentinel]       again, rebuild it: stop the container and delete the volume."
  fi
  exec docker-entrypoint.sh postgres "$@"
fi

echo "[sentinel] empty data directory → taking a base backup from ${SENTINEL_PRIMARY_HOST}:${PRIMARY_PORT}"

if [[ ! -r "$CA_PATH" ]]; then
  echo "[sentinel] FATAL: CA not readable at ${CA_PATH}." >&2
  echo "[sentinel]   The replication connection uses sslmode=verify-full, so it fails" >&2
  echo "[sentinel]   closed without the CA. Run issue-postgres-cert.sh on the ACTIVE VM" >&2
  echo "[sentinel]   and copy /opt/sentinel-pki/root.crt to this VM." >&2
  exit 1
fi

# verify-full, matching the application DSN: the WAL stream carries every row, so an
# unverified connection here would undermine the database TLS enforced everywhere else.
# The primary's certificate SAN must therefore include SENTINEL_PRIMARY_HOST — issue it
# with PG_HOSTS covering that address.
export PGPASSWORD="$SENTINEL_REPL_PASSWORD"
export PGSSLMODE=verify-full
export PGSSLROOTCERT="$CA_PATH"

# -R writes postgresql.auto.conf + standby.signal; -S uses the slot the primary
# created, so the primary retains WAL for us; -C would create it (we do not, so a
# missing slot is a loud failure rather than a silent drift into a slot-less standby).
pg_basebackup \
  --host="$SENTINEL_PRIMARY_HOST" \
  --port="$PRIMARY_PORT" \
  --username="$SENTINEL_REPL_USER" \
  --pgdata="$PGDATA" \
  --wal-method=stream \
  --slot=sentinel_standby \
  --write-recovery-conf \
  --checkpoint=fast \
  --progress \
  --verbose

# This VM needs its OWN server cert+key, not just the CA.
#
# Two reasons it cannot be skipped: compose.prod.yml starts Postgres with `-c ssl=on`,
# and a command-line option OVERRIDES postgresql.conf/auto.conf — so there is no way to
# turn TLS back off from inside the data directory. And once promoted, this node serves
# the application over sslmode=verify-full, which requires a certificate whose SAN
# covers this host's address.
#
# Fail loudly now rather than letting Postgres exit with a bare "could not load server
# certificate file" that looks like a replication problem.
if [[ ! -r /etc/sentinel/pg/server.key || ! -r /etc/sentinel/pg/server.crt ]]; then
  echo "[sentinel] FATAL: no server certificate at /etc/sentinel/pg/server.{crt,key}." >&2
  echo "[sentinel]   Postgres is started with -c ssl=on, which cannot be overridden from" >&2
  echo "[sentinel]   the data directory, so it will not start without one." >&2
  echo "[sentinel]" >&2
  echo "[sentinel]   Issue ONE certificate whose SAN covers BOTH VMs and copy it to each:" >&2
  echo "[sentinel]     PG_HOSTS='postgres,<active-ip>,<passive-ip>,localhost' \\" >&2
  echo "[sentinel]     PG_IPS='<active-ip>,<passive-ip>,127.0.0.1' \\" >&2
  echo "[sentinel]       sudo deploy/docker/issue-postgres-cert.sh" >&2
  echo "[sentinel]     scp /opt/sentinel-pki/pg-server.{crt,key} root@<passive>:/opt/sentinel-pki/" >&2
  echo "[sentinel]   The key must be mode 0600 owned by uid 70 on the passive VM too." >&2
  exit 1
fi
echo "[sentinel] local server cert present → standby serves TLS and is promotion-ready."

chmod 700 "$PGDATA"
echo "[sentinel] base backup complete — starting as a streaming standby."
exec docker-entrypoint.sh postgres "$@"
