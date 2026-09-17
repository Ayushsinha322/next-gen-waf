#!/usr/bin/env bash
# =============================================================================
#  Installer sizing + validator check  —  runs in CI, needs no Docker and no VM
#
#      ./deploy/ci/check-installer-sizing.sh [path/to/install.sh]
#
#  install.sh sizes the deployment to the host it lands on (ClickHouse memory,
#  the per-request log ceiling, the event spool) and refuses unsafe console binds
#  and malformed shared-egress lists. Those decisions are pure functions kept
#  between marker comments precisely so they can be lifted out and exercised
#  here for the three host shapes the product is actually installed on — a
#  16 GB evaluation VM, the 32 GB / 16 vCPU / 200 GB production node, and a
#  64 GB host that must hit the cap — without provisioning anything.
#
#  It also closes the silently-inert gap for the keys the sizing writes: a .env
#  key that compose.prod.yml never interpolates is stored, printed in the report
#  and changes nothing. Every sized key must appear in the generated-.env heredoc
#  AND be read by compose.
#
#  Each assertion has been confirmed to fail when its guard is removed — cap
#  16→20, floor deleted, the public-address branch made permissive, a key
#  dropped from the heredoc, a step renumbered, the old brand restored, the
#  trailing-comma guard deleted. (Deleting only the explicit 0.0.0.0 line does
#  NOT fail it: 0.0.0.0 is also caught by the private-range branch, which is
#  the guard that matters. The explicit line is there to be read, not relied on.)
#  A check that cannot fail is worse than no check.
# =============================================================================
set -uo pipefail

INSTALLER="${1:-deploy/package/customer/install.sh}"
COMPOSE="${COMPOSE_FILE:-deploy/docker/compose.prod.yml}"
[[ -f "$INSTALLER" ]] || { echo "no installer at $INSTALLER" >&2; exit 2; }
[[ -f "$COMPOSE"   ]] || { echo "no compose file at $COMPOSE" >&2; exit 2; }

if [[ -t 1 ]]; then R=$'\e[0m'; RED=$'\e[91m'; GRN=$'\e[92m'; B=$'\e[1m'
else R=''; RED=''; GRN=''; B=''; fi
FAIL=0
pass() { printf '  %s✓%s %s\n' "$GRN" "$R" "$*"; }
fail() { printf '  %s✗%s %s\n' "$RED" "$R" "$*"; FAIL=1; }
sect() { printf '\n%s== %s%s\n' "$B" "$*" "$R"; }

# Lift a marked block out of the installer. The markers are part of the
# installer's contract with this check; moving them is a deliberate act.
extract() { # extract BEGIN-REGEX END-REGEX
  awk -v b="$1" -v e="$2" '$0 ~ b {on=1; next} $0 ~ e {on=0} on' "$INSTALLER"
}

sect "sizing function is present and loads"
SIZING_SRC="$(extract '^# --- sizing-begin' '^# --- sizing-end')"
if [[ -z "$SIZING_SRC" ]]; then fail "no '# --- sizing-begin' … '# --- sizing-end' block in $INSTALLER"; exit 1; fi
# shellcheck disable=SC1090
eval "$SIZING_SRC" || { fail "sizing block does not evaluate"; exit 1; }
declare -F size_for_host >/dev/null && pass "size_for_host() defined" || { fail "size_for_host() missing"; exit 1; }

# get KEY <<< "$(size_for_host …)"
val() { sed -n "s/^$1=//p" <<<"$2"; }
expect() { # expect LABEL ACTUAL WANT
  if [[ "$2" == "$3" ]]; then pass "$1 = $2"; else fail "$1 = '$2', expected '$3'"; fi
}

sect "16 GB evaluation VM (reports 15 GB, 4 vCPU, 98 GB free)"
S="$(size_for_host 15 4 98)"
expect "tier"            "$(val TIER "$S")"                     minimum
expect "clickhouse mem"  "$(val CLICKHOUSE_MEM_LIMIT "$S")"     6g       # floor: 15*30% = 4 → 6
expect "log max mb"      "$(val SENTINEL_LOG_MAX_MB "$S")"      100
expect "log keep"        "$(val SENTINEL_LOG_KEEP "$S")"        5
expect "spool bytes"     "$(val SENTINEL_SPOOL_MAX_BYTES "$S")" 268435456

sect "16 GB / 8 vCPU / 200 GB (recommended tier, disk-scaled logs)"
S="$(size_for_host 15 8 196)"
expect "tier"            "$(val TIER "$S")"                     recommended
expect "clickhouse mem"  "$(val CLICKHOUSE_MEM_LIMIT "$S")"     6g
expect "log max mb"      "$(val SENTINEL_LOG_MAX_MB "$S")"      250
expect "log keep"        "$(val SENTINEL_LOG_KEEP "$S")"        7
expect "spool bytes"     "$(val SENTINEL_SPOOL_MAX_BYTES "$S")" 1073741824

sect "32 GB / 16 vCPU / 200 GB SSD — the production node (reports 31 GB, 196 GB free)"
S="$(size_for_host 31 16 196)"
expect "tier"            "$(val TIER "$S")"                     production
expect "clickhouse mem"  "$(val CLICKHOUSE_MEM_LIMIT "$S")"     9g       # 31*30% = 9
expect "log max mb"      "$(val SENTINEL_LOG_MAX_MB "$S")"      250
expect "log keep"        "$(val SENTINEL_LOG_KEEP "$S")"        7
expect "spool bytes"     "$(val SENTINEL_SPOOL_MAX_BYTES "$S")" 1073741824

sect "64 GB and 128 GB hosts hit the ClickHouse cap"
expect "64 GB clickhouse mem"  "$(val CLICKHOUSE_MEM_LIMIT "$(size_for_host 62 32 500)")"  16g   # 62*30% = 18 → 16
expect "128 GB clickhouse mem" "$(val CLICKHOUSE_MEM_LIMIT "$(size_for_host 125 64 900)")" 16g
expect "64 GB tier"            "$(val TIER "$(size_for_host 62 32 500)")"                  production

sect "sizing is monotonic and never below the floor"
prev=0; mono=yes
for ram in 15 20 24 31 40 48 62 90; do
  ch="$(val CLICKHOUSE_MEM_LIMIT "$(size_for_host "$ram" 8 200)")"; ch="${ch%g}"
  (( ch >= 6 && ch <= 16 )) || { fail "ram=$ram gives ${ch}g outside 6g–16g"; mono=no; }
  (( ch >= prev )) || { fail "ram=$ram gives ${ch}g < previous ${prev}g"; mono=no; }
  prev=$ch
done
[[ "$mono" == "yes" ]] && pass "6g ≤ clickhouse mem ≤ 16g and non-decreasing across 15–90 GB"

sect "120 GB disk gets the middle log tier"
S="$(size_for_host 31 16 150)"
expect "log max mb (150 GB free)" "$(val SENTINEL_LOG_MAX_MB "$S")" 150
expect "spool (150 GB free)"      "$(val SENTINEL_SPOOL_MAX_BYTES "$S")" 536870912

sect "validators are present and load"
VAL_SRC="$(extract '^# --- validators-begin' '^# --- validators-end')"
if [[ -z "$VAL_SRC" ]]; then fail "no validators block in $INSTALLER"; exit 1; fi
# shellcheck disable=SC1090
eval "$VAL_SRC" || { fail "validators block does not evaluate"; exit 1; }
declare -F console_bind_ok >/dev/null && pass "console_bind_ok() defined" || fail "console_bind_ok() missing"
declare -F cidr_list_ok   >/dev/null && pass "cidr_list_ok() defined"   || fail "cidr_list_ok() missing"

sect "console bind: private + local is accepted, everything else refused"
LOCAL="172.16.21.150 10.0.0.8 192.168.1.20 203.0.113.5 127.0.0.1"
accepts() { console_bind_ok "$1" "$LOCAL" && pass "accepts $1 ($2)" || fail "REFUSED $1 ($2)"; }
refuses() { console_bind_ok "$1" "$LOCAL" && fail "ACCEPTED $1 ($2)" || pass "refuses $1 ($2)"; }
accepts 172.16.21.150 "RFC1918 172.16/12, configured on host"
accepts 10.0.0.8      "RFC1918 10/8, configured on host"
accepts 192.168.1.20  "RFC1918 192.168/16, configured on host"
accepts 127.0.0.1     "loopback"
refuses 0.0.0.0       "wildcard — would publish the console on every interface"
refuses 203.0.113.5   "PUBLIC address, even though it is configured on the host"
refuses 172.16.21.151 "private but NOT configured on this host"
refuses 172.32.0.1    "outside 172.16/12"
refuses 172.16.21     "not an IPv4 address"
refuses 10.0.0.256    "octet out of range"
refuses ""            "empty"

sect "shared egress list"
cidr_list_ok "203.0.113.7,198.51.100.0/24"   && pass "accepts ip,cidr"            || fail "refused a valid ip,cidr list"
cidr_list_ok "10.0.0.0/8, 172.16.0.0/12"     && pass "accepts a spaced list"      || fail "refused a spaced list"
cidr_list_ok "203.0.113.7/33"                && fail "accepted /33"               || pass "refuses /33"
cidr_list_ok ""                              && fail "accepted an empty list"     || pass "refuses empty"
cidr_list_ok "office-nat"                    && fail "accepted a hostname"        || pass "refuses a hostname (data plane would drop it silently)"
cidr_list_ok "203.0.113.7,"                  && fail "accepted a trailing comma"  || pass "refuses a trailing comma"

sect "every sized key reaches .env AND is read by compose (not silently inert)"
HEREDOC="$(awk '/cat > "\$ENV_FILE" <<ENVEOF/{inside=1; next} inside && /^ENVEOF$/{inside=0} inside' "$INSTALLER")"
[[ -n "$HEREDOC" ]] || fail "could not find the generated-.env heredoc (marker moved?)"
for key in CLICKHOUSE_MEM_LIMIT SENTINEL_LOG_MAX_MB SENTINEL_LOG_KEEP SENTINEL_SPOOL_MAX_BYTES SENTINEL_MGMT_BIND; do
  grep -qE "^${key}=\\\$" <<<"$HEREDOC" && pass "$key written to .env from a variable" \
    || fail "$key is not written to .env from a variable — the sizing/flag does not reach the deployment"
  grep -qF "\${${key}" "$COMPOSE" && pass "$key is interpolated by compose.prod.yml" \
    || fail "$key is not read by compose.prod.yml — a .env key nothing consumes"
done
grep -qF '$SHARED_EGRESS_LINE' <<<"$HEREDOC" && pass "shared-egress line reaches .env" \
  || fail "SHARED_EGRESS_LINE is not in the heredoc"
grep -qF '${SENTINEL_SHARED_EGRESS_CIDRS' "$COMPOSE" && pass "SENTINEL_SHARED_EGRESS_CIDRS is read by compose.prod.yml" \
  || fail "SENTINEL_SHARED_EGRESS_CIDRS is not read by compose.prod.yml"

sect "step numbering is consistent (renumbering leaves no 'Step 9 of 10')"
mapfile -t STEPS < <(grep -oE 'step "Step [0-9]+ of [0-9]+ ' "$INSTALLER" | grep -oE '[0-9]+ of [0-9]+')
TOTALS="$(printf '%s\n' "${STEPS[@]}" | awk '{print $3}' | sort -u | tr '\n' ' ')"
if [[ "$(wc -w <<<"$TOTALS")" -eq 1 ]]; then pass "one total everywhere: ${TOTALS}steps"; else fail "mixed step totals: $TOTALS"; fi
want=1; seq_ok=yes
for s in "${STEPS[@]}"; do
  n="${s%% *}"
  [[ "$n" -eq "$want" ]] || { fail "step $n follows step $((want - 1)) — expected $want"; seq_ok=no; }
  want=$((n + 1))
done
[[ "$seq_ok" == "yes" && "$((want - 1))" -eq "${TOTALS% }" ]] && pass "steps run 1..${TOTALS% } with no gap" \
  || { [[ "$seq_ok" == "yes" ]] && fail "last step is $((want - 1)) but the total says ${TOTALS% }"; }

sect "operator-facing text carries the product name"
if grep -q 'Next-Gen ESDSWAF' "$INSTALLER"; then fail "installer still says 'Next-Gen ESDSWAF' (product is Swaraj Kavach; archive names may keep ESDSWAF)"
else pass "no 'Next-Gen ESDSWAF' in the installer"; fi
grep -q 'Swaraj Kavach  —  Installer' "$INSTALLER" && pass "banner names Swaraj Kavach" || fail "banner does not name Swaraj Kavach"
if grep -q 'cannot be changed later' "$INSTALLER"; then
  fail "installer still claims the password cannot be changed — /api/v1/auth/password/change exists"
else pass "password guidance does not claim it is unchangeable"; fi

echo
if [[ $FAIL -ne 0 ]]; then printf '  %s✗ installer sizing/validator check FAILED%s\n\n' "$RED" "$R"; exit 1; fi
printf '  %s✓ installer sizing, validators, .env passthrough and step numbering all hold%s\n\n' "$GRN" "$R"
