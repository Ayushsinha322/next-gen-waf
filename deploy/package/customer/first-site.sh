#!/usr/bin/env bash
# =============================================================================
#  Swaraj Kavach — guided first site
#
#      sudo ./first-site.sh
#
#  Run this straight after install.sh. It takes an operator who has never seen
#  this product from "the installer said it worked" to a real website protected
#  by the WAF, with the protection PROVEN rather than assumed — then stops and
#  says what to do next.
#
#  It asks three questions (the hostname visitors use, and the origin's address
#  and port), and nothing else. Everything else is read from the installation.
#
#  WHY THIS EXISTS
#
#  install.sh ends with a healthy stack and no protected site, which means the
#  WAF answers 502 to everything — correct, and alarming if you do not know it.
#  The next step was a wizard in a browser reached over an SSH tunnel, described
#  across two documents. This is the same journey in one command, and it fails
#  loudly at each point instead of leaving a site that looks configured.
#
#  WHAT IT WILL NOT DO
#
#  It never creates a site in blocking mode. A new site's false-positive rate
#  against YOUR traffic is unknown until it has seen some, and blocking first
#  assumes the answer. It finishes in learning mode and tells you how to measure
#  before you switch.
#
#      --dry-run    ask the questions, show the payload, create nothing
#      --yes        do not pause for confirmation (for a scripted rebuild)
# =============================================================================
set -uo pipefail

INSTALL_DIR=/opt/sentinel/current
ENV_FILE="$INSTALL_DIR/.env"
# The console listens where the installer bound it (SENTINEL_MGMT_BIND in .env:
# "127.0.0.1:" by default, "<private-ip>:" with --console-bind). Read it rather
# than assume loopback, or this script cannot reach a console that is perfectly
# healthy on the management address.
MGMT_HOST="$(sed -n 's/^SENTINEL_MGMT_BIND=//p' "$ENV_FILE" 2>/dev/null | head -1 | tr -d ':[:space:]')"
[[ -n "$MGMT_HOST" && "$MGMT_HOST" != "0.0.0.0" ]] || MGMT_HOST=127.0.0.1
API="${SENTINEL_API:-https://${MGMT_HOST}:9443}"
EMAIL="${SENTINEL_ADMIN_EMAIL:-admin@sentinel.local}"

DRY_RUN=no
ASSUME_YES=no
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=yes ;;
    --yes|-y)  ASSUME_YES=yes ;;
    -h|--help) sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

if [[ -t 1 ]]; then
  B=$'\e[1m'; R=$'\e[0m'; DIM=$'\e[2m'
  RED=$'\e[91m'; GRN=$'\e[92m'; YEL=$'\e[93m'; CYN=$'\e[96m'
else B=''; R=''; DIM=''; RED=''; GRN=''; YEL=''; CYN=''; fi

step() { printf '\n%s%s==> %s%s\n' "$B" "$CYN" "$*" "$R"; }
ok()   { printf '  %s✓%s %s\n' "$GRN" "$R" "$*"; }
warn() { printf '  %s!%s %s\n' "$YEL" "$R" "$*"; }
die()  { printf '\n  %s✗ %s%s\n\n' "$RED" "$*" "$R" >&2; exit 1; }
ask()  { # ask VAR PROMPT [DEFAULT]
  local __v="$1" __p="$2" __d="${3:-}" __a=""
  if [[ -n "$__d" ]]; then read -r -p "  $__p [$__d]: " __a || true; __a="${__a:-$__d}"
  else while [[ -z "$__a" ]]; do read -r -p "  $__p: " __a || true; done; fi
  printf -v "$__v" '%s' "$__a"
}

printf '\n  %s%s================================================%s\n' "$B" "$CYN" "$R"
printf '  %s%s   Swaraj Kavach — your first protected site%s\n' "$B" "$CYN" "$R"
printf '  %s%s================================================%s\n' "$B" "$CYN" "$R"

# ── 0. Prerequisites ────────────────────────────────────────────────────────
step "Checking the installation"
[[ $EUID -eq 0 ]] || die "run this with sudo — the secrets file is mode 0600 and root-owned."
[[ -f "$ENV_FILE" ]] || die "no installation found at $ENV_FILE. Run ./install.sh first."
command -v curl >/dev/null || die "curl is required."
command -v jq   >/dev/null || die "jq is required.  apt-get install -y jq"

# The one credential that exists. install.sh generates it into the .env because
# there is no password-change or password-reset endpoint in this build, so a
# password recoverable only from a container log would be lost on any recreate.
PW=$(sed -n 's/^SENTINEL_BOOTSTRAP_ADMIN_PASSWORD=//p' "$ENV_FILE" | head -1)
[[ -n "$PW" ]] || die "SENTINEL_BOOTSTRAP_ADMIN_PASSWORD is not in $ENV_FILE.
    This installation predates that change. Recover the password from the
    control plane's log instead:
      docker logs sentinel-controlplane-1 2>&1 | grep -A1 'GENERATED password'"

# Ask the control plane whether it has a DATABASE, not whether its container is
# up. Without one it serves forever in degraded mode and every login returns 503
# — a state indistinguishable from healthy if you only look at `docker ps`.
RDY=$(docker exec sentinel-clickhouse-1 wget -qO- --timeout=5 http://controlplane:9501/readyz 2>/dev/null)
printf '%s' "$RDY" | grep -q '"db"[[:space:]]*:[[:space:]]*"ok"' \
  || die "the control plane is running WITHOUT a database — every login will fail.
    $RDY
    Restart it once Postgres is healthy:  docker restart sentinel-controlplane-1"
ok "control plane is up and connected to its database"

TOK=$(curl -sk --max-time 10 -X POST "$API/api/v1/auth/login" \
        -H 'Content-Type: application/json' \
        -d "$(jq -nc --arg e "$EMAIL" --arg p "$PW" '{email:$e,password:$p}')" \
        2>/dev/null | jq -r '.access_token // empty')
[[ -n "$TOK" ]] || die "could not log in as $EMAIL with the password from $ENV_FILE."
ok "authenticated as $EMAIL"

# ── 1. Questions ────────────────────────────────────────────────────────────
step "Your website"
cat <<INTRO
  ${DIM}Two addresses are involved and confusing them is the usual first mistake:${R}

    ${B}the hostname visitors type${R}   e.g. portal.example.com
                                 what the WAF matches on. Site matching is by
                                 Host header ALONE, so this must be exact.

    ${B}the origin server${R}           e.g. 10.20.30.40 port 8080
                                 where your application actually runs today,
                                 reachable from THIS host.
INTRO
echo
ask DOMAIN   "Hostname visitors will use"
ask UP_HOST  "Origin server address (IP or hostname, no port)"
ask UP_PORT  "Origin server port" "8080"

case "$DOMAIN" in
  http*|*/*) die "hostname only — no http://, no trailing path. e.g. portal.example.com" ;;
esac
case "$UP_HOST" in
  *:*) die "the port goes in the next answer, not here. Enter just '${UP_HOST%%:*}'." ;;
esac
[[ "$UP_PORT" =~ ^[0-9]+$ ]] || die "the port must be a number."

# ── 2. Is the origin actually reachable? ────────────────────────────────────
# Checked BEFORE the site is created. A site whose upstream is down returns 502,
# and a 502 on a brand-new site reads as "the WAF is broken" rather than "the
# application is not running" — which is where the time goes.
step "Reaching the origin from this host"
if docker exec sentinel-clickhouse-1 sh -c "nc -z -w4 '$UP_HOST' '$UP_PORT'" >/dev/null 2>&1; then
  ok "$UP_HOST:$UP_PORT is accepting connections"
else
  warn "$UP_HOST:$UP_PORT did NOT accept a connection from inside the WAF's network"
  printf '      %sIf it is only reachable from the host, or behind a firewall, the site%s\n' "$DIM" "$R"
  printf '      %swill return 502 for every request. Fix that before going live.%s\n' "$DIM" "$R"
  if [[ "$ASSUME_YES" != "yes" ]]; then
    read -r -p "  Continue anyway? [y/N]: " a || true
    [[ "${a,,}" == "y" ]] || die "stopped. Nothing was created."
  fi
fi

# ── 3. Build the configuration ──────────────────────────────────────────────
# waf_policy is an ALLOWLIST on the control-plane side: a key it does not name is
# stored, echoed back to the dashboard, and never reaches the data plane. Only
# allowlisted keys are sent here, and they are printed so the record is honest.
#
# anomaly_threshold 10, not 5 — the benchmarked configuration. At 5 a single weak
# +5 heuristic blocks on its own, which is where most benign false positives came
# from.
UPSTREAM_JSON=$(jq -nc --arg h "$UP_HOST" --argjson p "$UP_PORT" '{
  load_balancer: "round_robin",
  servers: [ { host: $h, port: $p, weight: 1, tls: false } ],
  health_check: { path: "/", interval: "10s", timeout: "3s" },
  timeout_secs: 30,
  connect_timeout_secs: 5,
  proxy: { websocket: false, keepalive: true }
}')
WAF_JSON=$(jq -nc '{
  mode: "learning",
  paranoia_level: 2,
  anomaly_threshold: 10,
  max_body_size: 20971520,
  max_uri_length: 8192,
  max_header_count: 100,
  allowed_methods: ["GET","HEAD","POST","PUT","PATCH","DELETE","OPTIONS"]
}')
SITE_NAME=$(printf '%s' "$DOMAIN" | tr '.' '-')
BODY=$(jq -nc --arg n "$SITE_NAME" --arg d "$DOMAIN" \
             --argjson u "$UPSTREAM_JSON" --argjson w "$WAF_JSON" \
             '{name:$n, domains:[$d], upstream:$u, waf_policy:$w}')

step "The site that will be created"
printf '  name       %s\n' "$SITE_NAME"
printf '  domain     %s\n' "$DOMAIN"
printf '  origin     %s:%s  (plain HTTP)\n' "$UP_HOST" "$UP_PORT"
printf '  mode       %sLEARNING%s — detects and records, blocks nothing\n' "$B" "$R"
printf '  threshold  10 (paranoia 2) — the benchmarked configuration\n'
cat <<'LIMITS'

  Request limits applied — these reject in EVERY mode including learning:

    max body size     20 MB     over this -> 413
    max URI length    8192      over this -> 414   (SAML logins can exceed it)
    max header count  100       over this -> 431   (corporate SSO can exceed it)
    allowed methods   GET HEAD POST PUT PATCH DELETE OPTIONS  -> others 405

  If your application needs more than any of these, stop now, raise them in the
  dashboard after creation, and re-test. Learning mode will NOT protect you from
  them.
LIMITS

if [[ "$DRY_RUN" == "yes" ]]; then
  printf '\n  %s--dry-run: nothing was created.%s\n\n' "$YEL" "$R"
  printf '  %spayload:%s %s\n\n' "$DIM" "$R" "$(jq -c . <<<"$BODY")"
  exit 0
fi
if [[ "$ASSUME_YES" != "yes" ]]; then
  echo
  read -r -p "  Create it? [Y/n]: " a || true
  [[ -z "$a" || "${a,,}" == "y" ]] || die "stopped. Nothing was created."
fi

# ── 4. Validate, then create ────────────────────────────────────────────────
# Dry-run against the data plane's own parser first. Storage is not enforcement:
# the control plane will happily store a configuration the data plane rejects,
# and the symptom appears later as a site that exists and does not work.
# Recorded BEFORE creation so the wait below can prove THIS site arrived, rather
# than observing that some site exists. See the note at that step.
dp_site_count() {
  curl -fsS --max-time 5 http://127.0.0.1/healthz 2>/dev/null \
    | sed -n 's/.*"sites"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -1
}
SITES_BEFORE=$(dp_site_count); SITES_BEFORE=${SITES_BEFORE:-0}

step "Validating against the data plane"
VALID=$(curl -sk --max-time 15 -X POST "$API/api/v1/sites/validate" \
          -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
          -d "$BODY" 2>/dev/null)
if [[ "$(jq -r '.valid // false' <<<"$VALID")" != "true" ]]; then
  die "the data plane cannot use this configuration:
    $(jq -rc '.errors // .' <<<"$VALID")"
fi
ok "configuration accepted"

step "Creating the site"
CREATED=$(curl -sk --max-time 20 -X POST "$API/api/v1/sites" \
            -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
            -d "$BODY" 2>/dev/null)
SITE_ID=$(jq -r '.site.id // .id // empty' <<<"$CREATED")
[[ -n "$SITE_ID" ]] || die "the site was not created:
    $(head -c 400 <<<"$CREATED")"
ok "created — id $SITE_ID"

# ── 5. Did it actually reach the data plane? ────────────────────────────────
# The whole point. A site can be stored, echoed back by the API, listed in the
# dashboard, and never loaded by the process that inspects traffic.
step "Confirming the data plane loaded it"
# Wait for the COUNT TO RISE above what it was before this run, not for it to be
# non-zero. Configuration reaches the data plane asynchronously, so on a host
# that already protects a site the non-zero test is satisfied instantly by the
# OTHER site — the wait returns immediately, the traffic probe below runs before
# the new site exists, and the operator is told their origin is unreachable when
# in fact nothing had loaded yet. This script reported exactly that on its first
# real run, which is the same "checked something adjacent to the thing you cared
# about" mistake it exists to protect the operator from.
LOADED=no
for _ in $(seq 1 20); do
  n=$(dp_site_count); n=${n:-0}
  if [[ "$n" -gt "$SITES_BEFORE" ]]; then
    LOADED=yes; ok "data plane loaded it — now serving $n site(s), was $SITES_BEFORE"; break
  fi
  sleep 3
done
[[ "$LOADED" == "yes" ]] || die "the site was stored but the data plane never loaded it
    after 60s (it still reports $SITES_BEFORE site(s)). The control plane accepted
    a configuration the data plane never applied:
      docker logs sentinel-dataplane-1 --tail 50
      docker logs sentinel-controlplane-1 --tail 50"

# ── 6. Prove it inspects traffic ────────────────────────────────────────────
step "Proving the WAF inspects traffic for this site"
BENIGN=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H "Host: $DOMAIN" "http://127.0.0.1/" 2>/dev/null)
ATTACK=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H "Host: $DOMAIN" "http://127.0.0.1/?id=1%27+OR+1%3D1--" 2>/dev/null)

case "$BENIGN" in
  502) die "a normal request returned 502 — the WAF matched the site but could not
    reach $UP_HOST:$UP_PORT. The site exists; the origin is the problem." ;;
  2??|3??) ok "normal request -> $BENIGN (the origin answered; a redirect counts)" ;;
  *)   warn "normal request -> $BENIGN — unexpected, check the origin" ;;
esac

# In learning mode the attack is EXPECTED to pass. What proves the WAF saw it is
# the recorded VERDICT, not the status code — so read that back rather than infer
# anything from a 200.
#
# AND RETRY, because a brand-new site is matchable before it is inspected. The
# data plane matches sites from the config it has just been handed, but the rule
# engines are rebuilt by a separate task that polls every 5 seconds and then
# compiles the ruleset (334 rules for a default site). Until that lands, the site
# proxies traffic with an empty engine and every request records
# rule_matches=0 / decision=Allow. Measured on a fresh install:
#
#   11:17:15.173  REQUEST  score=0 matches=0 Allow  /
#   11:17:15.206  REQUEST  score=0 matches=0 Allow  /?id=1' OR 1=1--
#   11:17:16.678  rule engine loaded  rules=334
#
# A single early probe therefore reports "detection could not be confirmed" on a
# perfectly healthy site. Retrying until the engine is live is the difference
# between a proof and a coin toss.
step "Confirming the rule engine inspected it"
EV=""
for _ in $(seq 1 12); do
  EV=$(curl -sk --max-time 10 -H "Authorization: Bearer $TOK" \
         "$API/api/v1/events/search?limit=20" 2>/dev/null \
       | jq -c --arg s "$SITE_NAME" '[.events[]? | select(.site==$s)] | first // empty')
  [[ -n "$EV" ]] && break
  sleep 5
  # Re-send it: the earlier attempt may have arrived before the engine existed,
  # and that request is gone. Only a request made AFTER the engine loaded proves
  # anything.
  ATTACK=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
             -H "Host: $DOMAIN" "http://127.0.0.1/?id=1%27+OR+1%3D1--" 2>/dev/null)
done

if [[ -n "$EV" ]]; then
  ok "attack request -> $ATTACK, and the WAF recorded it:"
  printf '      rule %s  score %s/%s  %s\n' \
    "$(jq -r '.rule' <<<"$EV")" "$(jq -r '.score' <<<"$EV")" \
    "$(jq -r '.threshold' <<<"$EV")" "$(jq -r '.attack' <<<"$EV")"
  printf '      %s%s%s\n' "$DIM" "$(jq -r '.explanation' <<<"$EV" | cut -c1-170)" "$R"
else
  warn "attack request -> $ATTACK, but after 60s no detection was recorded for '$SITE_NAME'."
  printf '      %sThe site is serving traffic. Detection is NOT confirmed — do not%s\n' "$DIM" "$R"
  printf '      %sswitch this site to blocking until it is. Check:%s\n' "$DIM" "$R"
  printf '      %s  docker logs sentinel-dataplane-1 --tail 40 | grep %s%s\n' "$DIM" "$SITE_NAME" "$R"
fi

# ── 7. What now ─────────────────────────────────────────────────────────────
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
cat <<FINAL

  ${GRN}${B}$DOMAIN is protected and in learning mode.${R}

  ${B}Nothing is being blocked yet, on purpose.${R}
  Every detection figure this product publishes comes from a synthetic corpus.
  Nobody has measured how often it would wrongly block ${B}your${R} users. Learning
  mode answers that with real numbers instead of a guess.

  ${B}Next${R}

    1. Point DNS for $DOMAIN at ${IP:-this host}, or ask the network team to
       forward ports 80 and 443 here. Until then, test with:
         curl -H 'Host: $DOMAIN' http://${IP:-127.0.0.1}/

    2. Let it run for a full business cycle — one to two weeks, including a
       month-end if that is when your traffic looks different.

    3. Measure what it WOULD have blocked:
         $INSTALL_DIR/scripts/fpr-report.sh 168

    4. Only when that report is clean, switch to blocking in the dashboard
       (Sites -> $SITE_NAME -> Security Mode), then re-run:
         SENTINEL_VERIFY_HOST=$DOMAIN $INSTALL_DIR/../../verify.sh
       and confirm it reports "blocking is ENFORCED".

  ${B}Console${R}   ${DIM}loopback-only by design${R}
    ssh -L 9443:127.0.0.1:9443 root@${IP:-<this-host>}    then https://127.0.0.1:9443
    user  $EMAIL
    pass  ${DIM}sudo grep SENTINEL_BOOTSTRAP_ADMIN_PASSWORD $ENV_FILE${R}
          ${YEL}that password cannot be changed — back up $ENV_FILE${R}

FINAL
