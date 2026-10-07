#!/usr/bin/env bash
# =============================================================================
# Swaraj Kavach — backup/restore DRILL.
#
# Proves backup.sh + restore.sh actually work, end to end, against throwaway
# postgres + clickhouse containers (same image versions as compose.prod.yml):
#   1. start ephemeral pg + ch          4. destroy the data (truncate / drop)
#   2. seed known rows                  5. restore.sh --force
#   3. backup.sh                        6. assert restored rows == seeded rows
#
# It reuses the REAL backup.sh/restore.sh code paths (via PG_CONTAINER/
# CH_CONTAINER overrides), so a green drill means the real scripts work.
#
# Usage:  ./drill.sh      (needs docker; pulls postgres:16-alpine, clickhouse-server:26.3.35.3-alpine)
# =============================================================================
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PGC=sentinel-drill-pg
CHC=sentinel-drill-ch
export POSTGRES_USER=drilluser POSTGRES_PASSWORD=drillpass POSTGRES_DB=drilldb
export CLICKHOUSE_USER=drilluser CLICKHOUSE_PASSWORD=drillpass CLICKHOUSE_DB=drilldb
DRILL_BACKUP_ROOT="$(mktemp -d)"

cleanup(){ docker rm -f "$PGC" "$CHC" >/dev/null 2>&1 || true; rm -rf "$DRILL_BACKUP_ROOT"; }
trap cleanup EXIT INT TERM

say(){ printf '\n\033[1m== %s\033[0m\n' "$*"; }

say "1. start ephemeral postgres + clickhouse"
docker rm -f "$PGC" "$CHC" >/dev/null 2>&1 || true
docker run -d --name "$PGC" -e POSTGRES_USER -e POSTGRES_PASSWORD -e POSTGRES_DB postgres:16-alpine >/dev/null
docker run -d --name "$CHC" -e CLICKHOUSE_USER -e CLICKHOUSE_PASSWORD -e CLICKHOUSE_DB \
  -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 clickhouse/clickhouse-server:26.3.35.3-alpine >/dev/null

printf 'waiting for postgres'
for i in $(seq 1 40); do docker exec "$PGC" pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB" >/dev/null 2>&1 && break; printf .; sleep 0.5; done; echo
printf 'waiting for clickhouse'
for i in $(seq 1 60); do docker exec "$CHC" clickhouse-client -u "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" -q "SELECT 1" >/dev/null 2>&1 && break; printf .; sleep 0.5; done; echo

say "2. seed known data"
docker exec -i "$PGC" psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 <<'SQL'
CREATE TABLE drill_t (id int PRIMARY KEY, v text);
INSERT INTO drill_t VALUES (1,'alpha'),(2,'bravo'),(3,'charlie');
SQL
docker exec "$CHC" clickhouse-client -u "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" -d "$CLICKHOUSE_DB" -q \
  "CREATE TABLE ev (ts DateTime, msg String) ENGINE=MergeTree ORDER BY ts"
docker exec "$CHC" clickhouse-client -u "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" -d "$CLICKHOUSE_DB" -q \
  "INSERT INTO ev VALUES (now(),'e1'),(now(),'e2'),(now(),'e3'),(now(),'e4')"
# A SECOND table: with one, the drill could not see that restore.sh restored
# only the first table of the list (docker exec -i swallowed the rest of it).
docker exec "$CHC" clickhouse-client -u "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" -d "$CLICKHOUSE_DB" -q \
  "CREATE TABLE ev2 (ts DateTime, msg String) ENGINE=MergeTree ORDER BY ts"
docker exec "$CHC" clickhouse-client -u "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" -d "$CLICKHOUSE_DB" -q \
  "INSERT INTO ev2 VALUES (now(),'f1'),(now(),'f2')"
PG_SEED=$(docker exec "$PGC" psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "SELECT count(*) FROM drill_t")
CH_SEED=$(docker exec "$CHC" clickhouse-client -u "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" -d "$CLICKHOUSE_DB" -q "SELECT count(*) FROM ev")
CH2_SEED=$(docker exec "$CHC" clickhouse-client -u "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" -d "$CLICKHOUSE_DB" -q "SELECT count(*) FROM ev2")
echo "seeded: postgres=$PG_SEED rows, clickhouse=$CH_SEED + $CH2_SEED rows"

say "3. backup.sh (via PG_CONTAINER/CH_CONTAINER overrides)"
PG_CONTAINER="$PGC" CH_CONTAINER="$CHC" BACKUP_ROOT="$DRILL_BACKUP_ROOT" RETENTION_DAYS=999 "$HERE/backup.sh"

say "4. destroy the data"
docker exec "$PGC" psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "DROP TABLE drill_t"
docker exec "$CHC" clickhouse-client -u "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" -d "$CLICKHOUSE_DB" -q "DROP TABLE ev"
docker exec "$CHC" clickhouse-client -u "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" -d "$CLICKHOUSE_DB" -q "DROP TABLE ev2"
echo "dropped all three tables"

say "5. restore.sh --force"
PG_CONTAINER="$PGC" CH_CONTAINER="$CHC" BACKUP_ROOT="$DRILL_BACKUP_ROOT" "$HERE/restore.sh" latest --force

say "6. verify"
PG_NOW=$(docker exec "$PGC" psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "SELECT count(*) FROM drill_t")
CH_NOW=$(docker exec "$CHC" clickhouse-client -u "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" -d "$CLICKHOUSE_DB" -q "SELECT count(*) FROM ev")
CH2_NOW=$(docker exec "$CHC" clickhouse-client -u "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" -d "$CLICKHOUSE_DB" -q "SELECT count(*) FROM ev2" 2>/dev/null || echo missing)
echo "restored: postgres=$PG_NOW rows (seed $PG_SEED), clickhouse=$CH_NOW + $CH2_NOW rows (seed $CH_SEED + $CH2_SEED)"
PG_SUM=$(docker exec "$PGC" psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "SELECT string_agg(v,',' ORDER BY id) FROM drill_t")

if [ "$PG_NOW" = "$PG_SEED" ] && [ "$CH_NOW" = "$CH_SEED" ] && [ "$CH2_NOW" = "$CH2_SEED" ] && [ "$PG_SUM" = "alpha,bravo,charlie" ]; then
  printf '\n\033[32m✔ DRILL PASSED — backup + restore round-trips both databases correctly.\033[0m\n'
  exit 0
else
  printf '\n\033[31mx DRILL FAILED — restored counts/data do not match seed.\033[0m\n'
  exit 1
fi
