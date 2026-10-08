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
# and that the backup is what it claims to be: encrypted when gpg is present,
# root-only on disk, refused under the wrong key before anything is touched,
# and carrying the .env / PKI / certificates extract-secrets.sh gives back.
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
DRILL_DIR="$(mktemp -d)"
DRILL_BACKUP_ROOT="$DRILL_DIR/backups"
# Stand-ins for the host's secrets, so the drill never reads the real ones.
export BACKUP_KEY_FILE="$DRILL_DIR/backup.key"
export ENV_FILE="$DRILL_DIR/host/env/.env" PKI_DIR="$DRILL_DIR/host/pki" CERTS_DIR="$DRILL_DIR/host/certs"
mkdir -p "$(dirname "$ENV_FILE")" "$PKI_DIR" "$CERTS_DIR/default"
echo "SENTINEL_JWT_SECRET=drill-$RANDOM" > "$ENV_FILE"
echo "drill root key $RANDOM" > "$PKI_DIR/root.key"
echo "drill site cert $RANDOM" > "$CERTS_DIR/default/cert.pem"

cleanup(){ docker rm -f "$PGC" "$CHC" >/dev/null 2>&1 || true; rm -rf "$DRILL_DIR"; }
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

say "3b. the backup on disk"
BK="$(find "$DRILL_BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d | sort | tail -1)"
FAILS=0
check(){ if eval "$2"; then echo "  ok   $1"; else echo "  FAIL $1"; FAILS=$((FAILS+1)); fi; }
check "backup root is owner-only"  '[ "$(stat -c %a "$DRILL_BACKUP_ROOT")" = 700 ]'
check "no file is readable by others" '[ -z "$(find "$BK" -type f -perm /077)" ]'
check "the secrets are in it"       '[ -s "$BK/secrets.tar" ]'
if command -v gpg >/dev/null; then
  check "manifest says encrypted"    'grep -qx "encryption=gpg-symmetric" "$BK/MANIFEST.txt"'
  check "postgres.dump is not a readable dump" '[ "$(head -c5 "$BK/postgres.dump")" != PGDMP ]'
  check "the .env is not readable in it" '! grep -aq SENTINEL_JWT_SECRET "$BK/secrets.tar"'
  say "3c. the wrong key is refused before anything is touched"
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$DRILL_DIR/wrong.key"
  if BACKUP_KEY_FILE="$DRILL_DIR/wrong.key" PG_CONTAINER="$PGC" CH_CONTAINER="$CHC" \
       "$HERE/restore.sh" "$BK" --force > "$DRILL_DIR/wrong.log" 2>&1; then
    check "a restore under the wrong key fails" false
  else
    check "a restore under the wrong key fails" 'grep -q "does not decrypt" "$DRILL_DIR/wrong.log"'
  fi
  check "…and changed nothing" '[ "$(docker exec "$PGC" psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "SELECT count(*) FROM drill_t")" = "$PG_SEED" ]'
else
  echo "  (gpg not installed here: the encryption checks are skipped)"
fi

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

say "7. extract-secrets.sh"
BACKUP_ROOT="$DRILL_BACKUP_ROOT" "$HERE/extract-secrets.sh" latest "$DRILL_DIR/out"
for f in "$ENV_FILE" "$PKI_DIR/root.key" "$CERTS_DIR/default/cert.pem"; do
  check "${f#"$DRILL_DIR"/} comes back identical" 'cmp -s "$f" "$DRILL_DIR/out$f"'
done

if [ "$FAILS" -eq 0 ] && [ "$PG_NOW" = "$PG_SEED" ] && [ "$CH_NOW" = "$CH_SEED" ] && [ "$CH2_NOW" = "$CH2_SEED" ] && [ "$PG_SUM" = "alpha,bravo,charlie" ]; then
  printf '\n\033[32m✔ DRILL PASSED — backup + restore round-trips both databases correctly.\033[0m\n'
  exit 0
else
  printf '\n\033[31mx DRILL FAILED — restored counts/data do not match seed.\033[0m\n'
  exit 1
fi
