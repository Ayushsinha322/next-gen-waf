#!/usr/bin/env bash
# =============================================================================
#  Reclaim the disk ClickHouse spent logging about itself.
#
#  WHY A SEPARATE STEP IS NEEDED
#
#  clickhouse-logging.xml puts a TTL on ClickHouse's self-log tables, but a TTL
#  only governs a table from the moment it exists. When ClickHouse starts and
#  finds an existing table whose definition no longer matches its config — which
#  is exactly what adding a TTL does — it does NOT alter it. It RENAMES the old
#  table out of the way and creates a fresh one:
#
#      system.text_log      →  new, with the TTL
#      system.text_log_0    →  every existing row, and still no TTL, for ever
#
#  Verified against clickhouse-server:24-alpine rather than assumed: a table
#  seeded without the drop-in came back as text_log_0 holding all its rows while
#  the new text_log started empty with TTL 7 days.
#
#  So deploying the drop-in alone stops the growth and reclaims nothing. On the
#  deploy VM that would leave 15.26 GiB parked in a renamed table permanently.
#  This script is what turns it back into free disk.
#
#  USAGE
#
#      ./clickhouse-reclaim-logs.sh            # report only, changes nothing
#      ./clickhouse-reclaim-logs.sh --apply    # drop the renamed leftovers
#
#      CH_CONTAINER=sentinel-clickhouse-1 ./clickhouse-reclaim-logs.sh --apply
#
#  SAFETY
#
#  It only ever touches tables in the `system` database whose name is one of
#  ClickHouse's own log tables, optionally followed by a rename suffix. The
#  product's own data lives in `sentinel_logs` and is never named, never
#  matched, and never dropped. There is no wildcard anywhere in this script.
# =============================================================================
set -uo pipefail

RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; DIM=$'\e[2m'; B=$'\e[1m'; R=$'\e[0m'

CH_CONTAINER="${CH_CONTAINER:-sentinel-clickhouse-1}"
APPLY=0
[[ "${1:-}" == "--apply" ]] && APPLY=1
[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && { sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0; }

# ClickHouse's own log tables. Named explicitly: a pattern like `%_log` would
# also match a user table that happens to end in _log, and this script drops
# things.
#
# The list is DERIVED from clickhouse-logging.xml rather than restated here.
# Keeping two lists in step by hand does not work — the first version of this
# script was written from memory, missed query_metric_log and s3queue_log, and
# silently left their renamed leftovers on disk while reporting "none". A
# config entry with no matching entry here is exactly the kind of quiet gap
# that makes a cleanup tool worse than useless.
CONFIG_XML="$(dirname "${BASH_SOURCE[0]}")/clickhouse-logging.xml"

# Logs that may exist on disk from an older config even though nothing sets a
# TTL for them now. Union, not replacement, so past leftovers are still cleaned.
SELF_LOGS=( session_log opentelemetry_span_log crash_log )

if [[ -r "$CONFIG_XML" ]]; then
  while read -r t; do
    [[ -n "$t" ]] && SELF_LOGS+=("$t")
  done < <(grep -oE '^[[:space:]]*<[a-z0-9_]+_log>' "$CONFIG_XML" | tr -d ' <>')
else
  printf '  %s!%s %s not readable — falling back to a built-in list\n' \
    "$YEL" "$R" "$CONFIG_XML"
  SELF_LOGS+=(
    text_log query_log query_thread_log query_views_log part_log
    metric_log asynchronous_metric_log trace_log processors_profile_log
    backup_log blob_storage_log asynchronous_insert_log error_log
    query_metric_log s3queue_log
  )
fi

# crash_log is in the list ON PURPOSE even though it is deliberately unbounded:
# a RENAMED crash_log_0 is a dead copy from an old config and should go, while
# the live crash_log is never matched because the pattern requires the suffix.

ch() { docker exec "$CH_CONTAINER" clickhouse-client -q "$1" 2>/dev/null; }

if ! docker inspect "$CH_CONTAINER" >/dev/null 2>&1; then
  printf '\n  %s✗%s no container named %s\n' "$RED" "$R" "$CH_CONTAINER"
  printf '      %sset CH_CONTAINER to the right name%s\n\n' "$DIM" "$R"
  exit 1
fi
if ! ch "select 1" >/dev/null; then
  printf '\n  %s✗%s %s is not answering queries\n\n' "$RED" "$R" "$CH_CONTAINER"
  exit 1
fi

# Build the SQL IN-list once, for both the report and the drop.
in_list=$(printf "'%s'," "${SELF_LOGS[@]}"); in_list="${in_list%,}"

# A renamed leftover is a self-log name plus an underscore and digits. `extract`
# strips that suffix so the base name can be matched against the list above,
# which keeps the match exact rather than a prefix test — `text_log_0` counts,
# a hypothetical `text_log_archive` does not.
# The character class allows DIGITS. `[a-z_]+` looks right and silently skips
# s3queue_log_0, because the name carries a 3 — the same one-character gap that
# made the hand-written list wrong.
LEFTOVER_PRED="database = 'system'
   AND match(name, '^[a-z0-9_]+_[0-9]+$')
   AND extract(name, '^([a-z0-9_]+)_[0-9]+$') IN ($in_list)"

printf '\n%s%s==> what ClickHouse is holding for its own logs%s\n\n' "$B" "$YEL" "$R"

ch "SELECT
      t.name,
      formatReadableSize(sum(p.bytes_on_disk)) AS size,
      sum(p.rows) AS rows,
      if(t.engine_full LIKE '%TTL%', 'bounded', 'NO TTL') AS retention
    FROM system.tables t
    LEFT JOIN system.parts p
      ON p.database = t.database AND p.table = t.name AND p.active
    WHERE t.database = 'system' AND (t.name IN ($in_list) OR ($LEFTOVER_PRED))
    GROUP BY t.name, t.engine_full
    HAVING sum(p.bytes_on_disk) > 0
    ORDER BY sum(p.bytes_on_disk) DESC
    FORMAT PrettyCompactMonoBlock" || true

# For contrast: the data the product actually exists to keep.
printf '\n  %sfor comparison, the events this WAF stores:%s\n' "$DIM" "$R"
ch "SELECT table, formatReadableSize(sum(bytes_on_disk)) AS size, sum(rows) AS rows
    FROM system.parts WHERE database = 'sentinel_logs' AND active
    GROUP BY table ORDER BY sum(bytes_on_disk) DESC FORMAT PrettyCompactMonoBlock" || true

# ── the leftovers ───────────────────────────────────────────────────────────
mapfile -t LEFTOVERS < <(ch "SELECT name FROM system.tables WHERE $LEFTOVER_PRED ORDER BY name FORMAT TSV")

printf '\n%s%s==> renamed leftovers with no retention%s\n\n' "$B" "$YEL" "$R"

if (( ${#LEFTOVERS[@]} == 0 )); then
  printf '  %s✓%s none — nothing has been renamed out of the way here\n' "$GRN" "$R"
  printf '      %s(expected on a node that was installed with the drop-in already in place)%s\n\n' "$DIM" "$R"
  exit 0
fi

RECLAIM=$(ch "SELECT formatReadableSize(sum(bytes_on_disk)) FROM system.parts
              WHERE database = 'system' AND active AND table IN (
                SELECT name FROM system.tables WHERE $LEFTOVER_PRED)")

for t in "${LEFTOVERS[@]}"; do
  sz=$(ch "SELECT formatReadableSize(sum(bytes_on_disk)) FROM system.parts
           WHERE database='system' AND active AND table='$t'")
  printf '  %-32s %s\n' "$t" "${sz:-0.00 B}"
done
printf '\n  %stotal reclaimable: %s%s\n' "$B" "${RECLAIM:-unknown}" "$R"

if (( APPLY == 0 )); then
  printf '\n  %sreport only — nothing was changed.%s\n' "$DIM" "$R"
  printf '  %sre-run with --apply to drop these tables.%s\n\n' "$DIM" "$R"
  exit 0
fi

printf '\n%s%s==> dropping%s\n\n' "$B" "$YEL" "$R"
failed=0
for t in "${LEFTOVERS[@]}"; do
  # Name each table explicitly. Never a pattern, never a loop over a wildcard.
  if ch "DROP TABLE IF EXISTS system.\`$t\` SYNC" >/dev/null; then
    printf '  %s✓%s dropped system.%s\n' "$GRN" "$R" "$t"
  else
    printf '  %s✗%s could not drop system.%s\n' "$RED" "$R" "$t"
    failed=$((failed + 1))
  fi
done

printf '\n'
if (( failed == 0 )); then
  printf '  %s✓%s reclaimed %s\n' "$GRN" "$R" "${RECLAIM:-space}"
  printf '      %sgrowth from here is bounded by clickhouse-logging.xml%s\n\n' "$DIM" "$R"
  exit 0
fi
printf '  %s✗%s %d table(s) could not be dropped\n\n' "$RED" "$R" "$failed"
exit 1
