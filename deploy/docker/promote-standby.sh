#!/usr/bin/env bash
# Promote the passive VM's Postgres standby to primary. Run ON THE PASSIVE VM.
#
# This is the one step in the 2-VM topology that is NOT automatic, and that is a
# deliberate limitation rather than an oversight: a majority of 2 is 2, so nothing can
# safely arbitrate promotion. Automating it without a third opinion is how you get
# split-brain — two primaries accepting divergent writes, which is worse than the
# outage it was meant to avoid.
#
# The script therefore REFUSES to promote while it can still see a healthy primary,
# and requires explicit confirmation.
set -euo pipefail

COMPOSE_FILES=(-f compose.prod.yml -f compose.2vm-passive.yml)
PG_SERVICE=postgres

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
ylw()  { printf '\033[33m%s\033[0m\n' "$*"; }

cd "$(dirname "$0")"

: "${SENTINEL_PRIMARY_HOST:?SENTINEL_PRIMARY_HOST must be set (it is read from .env by compose; export it for this script)}"

echo "── Pre-flight ────────────────────────────────────────────────────────────"

# 1. Is this actually a standby?
if ! docker compose "${COMPOSE_FILES[@]}" exec -T "$PG_SERVICE" \
      psql -U "${POSTGRES_USER:?}" -d "${POSTGRES_DB:?}" -tAc "SELECT pg_is_in_recovery();" 2>/dev/null | grep -q '^t$'; then
  red "This Postgres is NOT in recovery — it is already a primary. Nothing to promote."
  red "If you are trying to recover from a split-brain, STOP and reconcile by hand."
  exit 1
fi
grn "✓ local Postgres is a standby (in recovery)"

# 2. SPLIT-BRAIN GUARD. If the old primary is still serving, promoting here creates a
#    second primary. Two nodes cannot arbitrate this, so refuse and make the operator
#    fence the old primary first.
if timeout 5 docker compose "${COMPOSE_FILES[@]}" exec -T "$PG_SERVICE" \
      pg_isready -h "$SENTINEL_PRIMARY_HOST" -p "${SENTINEL_PRIMARY_PORT:-5432}" >/dev/null 2>&1; then
  red "REFUSING TO PROMOTE: the primary at ${SENTINEL_PRIMARY_HOST} is still accepting connections."
  red ""
  red "Promoting now would give you TWO primaries taking divergent writes — harder to"
  red "recover from than the outage you are responding to."
  red ""
  red "Fence the old primary first (stop its stack, or cut its network), confirm it is"
  red "down, then re-run this script:"
  red "    ssh ${SENTINEL_PRIMARY_HOST} 'cd /opt/sentinel-src/deploy/docker && docker compose -f compose.prod.yml -f compose.2vm-active.yml down'"
  exit 1
fi
grn "✓ primary at ${SENTINEL_PRIMARY_HOST} is unreachable — promotion is safe to consider"

# 3. Report how far behind we are, so the operator knows what they are about to lose.
LAG=$(docker compose "${COMPOSE_FILES[@]}" exec -T "$PG_SERVICE" \
        psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc \
        "SELECT COALESCE(EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp()))::int, -1);" 2>/dev/null | tr -d '[:space:]')
if [[ "$LAG" == "-1" || -z "$LAG" ]]; then
  ylw "! replication lag unknown (no replayed transaction yet)"
else
  ylw "! last replayed transaction was ${LAG}s ago — writes newer than that are LOST on promotion"
fi

echo
ylw "This promotes ${HOSTNAME} to PRIMARY. Asynchronous replication means recent"
ylw "committed writes may not have arrived. Type PROMOTE to continue."
read -r -p "> " CONFIRM
[[ "$CONFIRM" == "PROMOTE" ]] || { echo "aborted."; exit 1; }

echo
echo "── Promoting ─────────────────────────────────────────────────────────────"
docker compose "${COMPOSE_FILES[@]}" exec -T "$PG_SERVICE" \
  psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT pg_promote(wait => true, wait_seconds => 60);"

if docker compose "${COMPOSE_FILES[@]}" exec -T "$PG_SERVICE" \
     psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "SELECT pg_is_in_recovery();" | grep -q '^f$'; then
  grn "✓ promoted — this node is now a read-write primary"
else
  red "promotion did not complete; inspect: docker compose ${COMPOSE_FILES[*]} logs $PG_SERVICE"
  exit 1
fi

cat <<NEXT

── Finish the cutover ────────────────────────────────────────────────────────

1. Point this VM's control plane at the LOCAL database. In .env set:
       SENTINEL_DB_URL_PRIMARY=<the DSN for THIS host>
   The certificate's SAN must cover the hostname you use, or sslmode=verify-full
   will reject it. Then:
       docker compose ${COMPOSE_FILES[*]} up -d controlplane

   The control plane needs no promotion of its own: leadership is a Postgres
   advisory lock, so whichever node reaches the new primary simply takes it.

2. Move traffic. Fail the VIP over to this VM (keepalived does this automatically if
   configured), or update DNS.

3. ClickHouse / Threat Search is NOT here — event history lived on the old active VM.
   Restore the latest ClickHouse backup onto this VM if you need history; protection
   and the dashboard work without it.

4. Rebuild the old VM as the new standby once it is repaired. Its data directory has
   diverged, so it MUST be re-cloned:
       docker compose -f compose.prod.yml -f compose.2vm-active.yml down
       docker volume rm sentinel_pgdata          # destroys the diverged copy
       # then bring it up with the PASSIVE overlay, pointing at this VM
NEXT
