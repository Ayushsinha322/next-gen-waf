#!/usr/bin/env bash
# =============================================================================
#  Swaraj Kavach — put a REAL application behind the WAF, in one command
#
#      sudo ./onboard-site.sh --domain app.example.com \
#           --origin 10.20.30.40:443 --origin-tls \
#           --cert /root/app.fullchain.pem --key /root/app.key.pem \
#           [--health /healthz] [--websocket] [--body-limit 52428800]
#
#  Run on the WAF host. It:
#    1. installs your certificate so the WAF presents it for that hostname
#       (checked first: the key must match the certificate, the certificate must
#       name the domain — a wrong pair here is a handshake failure for every user);
#    2. creates the site in LEARNING mode — inspected and recorded, nothing blocked,
#       because the false-positive rate against YOUR traffic is not known yet;
#    3. waits for the rule engine, then proves the path end to end FROM THIS HOST:
#       the WAF answers for the hostname, presents YOUR certificate, reaches the
#       origin, and records a detection — all before DNS moves;
#    4. prints the pre-cutover test for your laptop, the NAT rule, the DNS step,
#       and the origin lock-down, in the order they must happen.
#
#  first-site.sh is the five-minute learning exercise with a plain-HTTP origin.
#  This is the one for an application someone depends on.
#
#      --domain <fqdn>          hostname users type (site matching is by Host header, exact)
#      --origin <host:port>     where the application runs; repeat for several (load-balanced)
#      --origin-tls             the origin speaks HTTPS (the WAF verifies its certificate)
#      --sni <name>             hostname sent in TLS SNI to the origin (default: --domain)
#      --host-header <name>     Host header the origin expects (default: the client's, unchanged)
#      --cert <pem> --key <pem> your certificate (full chain) and UNENCRYPTED private key
#      --health <path>          health-check path, must answer without a login (default /)
#      --websocket              the application uses WebSockets (VM consoles, live updates)
#      --body-limit <bytes>     largest upload/request body (default 20971520 = 20 MiB)
#      --threshold <n>          anomaly threshold (default 10, the benchmarked value)
#      --mode learning|blocking default learning. Blocking before a learning window is
#                               a decision, not a default — it is accepted, and warned about.
#      --name <name>            site name in the console (default: the domain, dots as dashes)
#      --yes                    no confirmation pauses (scripted use)
#      --dry-run                show exactly what would be sent, change nothing
#
#  Authentication: reads the bootstrap admin password from /opt/sentinel/current/.env.
#  If the admin password has been changed (it should have been), it asks for it.
#  If the admin account has MFA on, use an API key instead:
#      export SENTINEL_API_KEY=...      (console → Settings → API keys, role editor or above)
#  Requires: curl, jq (apt-get install -y jq). openssl adds the certificate checks.
# =============================================================================
set -uo pipefail

INSTALL_DIR=/opt/sentinel/current
ENV_FILE="$INSTALL_DIR/.env"

if [[ -t 1 ]]; then B=$'\e[1m'; R=$'\e[0m'; DIM=$'\e[2m'; RED=$'\e[91m'; GRN=$'\e[92m'; YEL=$'\e[93m'; CYN=$'\e[96m'
else B=''; R=''; DIM=''; RED=''; GRN=''; YEL=''; CYN=''; fi
step() { printf '\n%s%s==> %s%s\n' "$B" "$CYN" "$*" "$R"; }
ok()   { printf '  %s✓%s %s\n' "$GRN" "$R" "$*"; }
warn() { printf '  %s!%s %s\n' "$YEL" "$R" "$*"; }
die()  { printf '\n  %s✗ %s%s\n\n' "$RED" "$*" "$R" >&2; exit 1; }
need_arg() { [[ -n "${2:-}" && "${2:0:2}" != "--" ]] || die "$1 needs a value"; }

DOMAIN=""; ORIGINS=(); ORIGIN_TLS=no; SNI=""; HOST_HEADER=""; CERT=""; KEY=""
HEALTH="/"; WEBSOCKET=no; BODY_LIMIT=20971520; THRESHOLD=10; MODE=learning; NAME=""
ASSUME_YES=no; DRY_RUN=no
while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain)      need_arg "$1" "${2:-}"; DOMAIN="$2"; shift ;;
    --origin)      need_arg "$1" "${2:-}"; ORIGINS+=("$2"); shift ;;
    --origin-tls)  ORIGIN_TLS=yes ;;
    --sni)         need_arg "$1" "${2:-}"; SNI="$2"; shift ;;
    --host-header) need_arg "$1" "${2:-}"; HOST_HEADER="$2"; shift ;;
    --cert)        need_arg "$1" "${2:-}"; CERT="$2"; shift ;;
    --key)         need_arg "$1" "${2:-}"; KEY="$2"; shift ;;
    --health)      need_arg "$1" "${2:-}"; HEALTH="$2"; shift ;;
    --websocket)   WEBSOCKET=yes ;;
    --body-limit)  need_arg "$1" "${2:-}"; BODY_LIMIT="$2"; shift ;;
    --threshold)   need_arg "$1" "${2:-}"; THRESHOLD="$2"; shift ;;
    --mode)        need_arg "$1" "${2:-}"; MODE="$2"; shift ;;
    --name)        need_arg "$1" "${2:-}"; NAME="$2"; shift ;;
    --yes|-y)      ASSUME_YES=yes ;;
    --dry-run)     DRY_RUN=yes ;;
    -h|--help)     awk 'NR>2 && /^# =+$/{exit} NR>2' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
  shift
done

# ── argument sanity, before touching anything ────────────────────────────────
[[ -n "$DOMAIN" ]] || die "--domain is required (the hostname users type, e.g. app.example.com)"
[[ "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$ ]] \
  || die "--domain '$DOMAIN' is not a hostname. No scheme, no path, no port, no wildcard here."
(( ${#ORIGINS[@]} > 0 )) || die "at least one --origin host:port is required"
for o in "${ORIGINS[@]}"; do
  [[ "$o" =~ ^[^:/[:space:]]+:[0-9]{1,5}$ ]] || die "--origin '$o' must be host:port (e.g. 10.20.30.40:443)"
done
case "$MODE" in learning|blocking) ;; *) die "--mode must be learning or blocking" ;; esac
[[ "$BODY_LIMIT" =~ ^[0-9]+$ && "$THRESHOLD" =~ ^[0-9]+$ ]] || die "--body-limit and --threshold take integers"
[[ "$HEALTH" == /* ]] || die "--health must start with / (got '$HEALTH')"
if [[ -n "$CERT" || -n "$KEY" ]]; then
  [[ -n "$CERT" && -n "$KEY" ]] || die "--cert and --key go together"
  [[ -r "$CERT" ]] || die "cannot read certificate file $CERT"
  [[ -r "$KEY"  ]] || die "cannot read key file $KEY"
  grep -q 'BEGIN CERTIFICATE' "$CERT" || die "$CERT does not contain a PEM certificate (BEGIN CERTIFICATE)"
  grep -q 'PRIVATE KEY' "$KEY"        || die "$KEY does not contain a PEM private key"
  grep -q 'ENCRYPTED' "$KEY" && die "$KEY is an ENCRYPTED private key — the WAF cannot prompt for a passphrase.
    Decrypt a copy:  openssl pkey -in $KEY -out $KEY.plain   (then chmod 600 it)"
fi
[[ "$ORIGIN_TLS" == "yes" && -z "$SNI" ]] && SNI="$DOMAIN"
[[ -n "$NAME" ]] || NAME="$(printf '%s' "$DOMAIN" | tr '.' '-')"

# ── who we talk to ───────────────────────────────────────────────────────────
command -v curl >/dev/null || die "curl is required"
command -v jq   >/dev/null || die "jq is required:  apt-get install -y jq"
HAVE_OPENSSL=no; command -v openssl >/dev/null && HAVE_OPENSSL=yes
[[ -r "$ENV_FILE" ]] || die "cannot read $ENV_FILE — run with sudo on the WAF host"
MGMT_HOST="$(sed -n 's/^SENTINEL_MGMT_BIND=//p' "$ENV_FILE" | head -1 | tr -d ':[:space:]')"
[[ -n "$MGMT_HOST" && "$MGMT_HOST" != "0.0.0.0" ]] || MGMT_HOST=127.0.0.1
API="${SENTINEL_API:-https://${MGMT_HOST}:9443}"
# The console login the installer created (SENTINEL_BOOTSTRAP_ADMIN_EMAIL, the
# "Administrator email" it asked for); installs older than that setting use
# the old fixed login.
BOOT_LOGIN="$(sed -n 's/^SENTINEL_BOOTSTRAP_ADMIN_EMAIL=//p' "$ENV_FILE" 2>/dev/null | head -1)"
EMAIL="${SENTINEL_ADMIN_EMAIL:-${BOOT_LOGIN:-admin@sentinel.local}}"
WAF_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')"
[[ -n "$WAF_IP" ]] || WAF_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"

printf '\n  %sSwaraj Kavach — application onboarding%s\n' "$B" "$R"

# ── certificate checks (local, before anything is sent) ──────────────────────
CERT_FP=""
if [[ -n "$CERT" ]]; then
  step "Certificate"
  if [[ "$HAVE_OPENSSL" == "yes" ]]; then
    # Key must belong to the certificate: a mismatch is a TLS handshake failure
    # for every single user the moment DNS moves. Compare the public keys.
    CPUB="$(openssl x509 -in "$CERT" -noout -pubkey 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | cut -c1-16)"
    KPUB="$(openssl pkey -in "$KEY" -pubout -outform DER 2>/dev/null | sha256sum | cut -c1-16)"
    [[ -n "$CPUB" && "$CPUB" == "$KPUB" ]] || die "the private key in $KEY does NOT match the certificate in $CERT.
    Every TLS handshake would fail. Find the key that was generated with this certificate's CSR."
    ok "private key matches the certificate"
    SUBJ="$(openssl x509 -in "$CERT" -noout -subject 2>/dev/null | sed 's/^subject=//')"
    SANS="$(openssl x509 -in "$CERT" -noout -ext subjectAltName 2>/dev/null | tr ',' '\n' | sed -n 's/.*DNS://p' | tr -d ' ' | tr '\n' ' ')"
    NOTAFTER="$(openssl x509 -in "$CERT" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')"
    covers=no
    for n in $SANS; do
      if [[ "$n" == "$DOMAIN" ]]; then covers=yes; fi
      if [[ "$n" == \*.* && "$DOMAIN" == *".${n#\*.}" && "${DOMAIN%%.*}" != "" && "${DOMAIN#*.}" == "${n#\*.}" ]]; then covers=yes; fi
    done
    if [[ "$covers" == "yes" ]]; then ok "certificate names $DOMAIN  ${DIM}(SANs: ${SANS:-none})${R}"
    else warn "certificate does NOT list $DOMAIN in its SANs (${SANS:-none}; subject: $SUBJ) — browsers will refuse it. Continuing because you may know better; check before cutover."; fi
    if openssl x509 -in "$CERT" -noout -checkend 604800 >/dev/null 2>&1; then ok "valid until $NOTAFTER"
    else warn "certificate expires within 7 days (or already has): $NOTAFTER"; fi
    CHAIN_N="$(grep -c 'BEGIN CERTIFICATE' "$CERT")"
    (( CHAIN_N >= 2 )) && ok "chain present ($CHAIN_N certificates in the file)" \
      || warn "only the leaf certificate is in $CERT — without the intermediate chain some clients will not trust it. Ask for the fullchain."
    CERT_FP="$(openssl x509 -in "$CERT" -noout -fingerprint -sha256 2>/dev/null | sed 's/^.*=//')"
  else
    warn "openssl not found — skipping key/certificate consistency checks"
  fi
fi

# ── control plane reachable and authenticated ────────────────────────────────
step "Control plane"
code="$(curl -sk --max-time 8 -o /dev/null -w '%{http_code}' "$API/api/v1/sites" 2>/dev/null)"
[[ "$code" =~ ^(401|403)$ ]] || die "the console API at $API did not answer as expected (HTTP ${code:-000}).
    Is the WAF running?  docker compose -p sentinel ps
    Console bound elsewhere? set SENTINEL_API=https://<console-ip>:9443"
ok "API answering at $API"

AUTH=()
if [[ -n "${SENTINEL_API_KEY:-}" ]]; then
  AUTH=(-H "X-API-Key: $SENTINEL_API_KEY")
  ok "using the API key from SENTINEL_API_KEY"
else
  PW="${SENTINEL_ADMIN_PASSWORD:-$(sed -n 's/^SENTINEL_BOOTSTRAP_ADMIN_PASSWORD=//p' "$ENV_FILE" | head -1)}"
  login() { curl -sk --max-time 10 -X POST "$API/api/v1/auth/login" -H 'Content-Type: application/json' \
              -d "$(jq -nc --arg e "$EMAIL" --arg p "$1" '{email:$e,password:$p}')" 2>/dev/null; }
  RESP="$(login "$PW")"
  if jq -e '.mfa_required == true' <<<"$RESP" >/dev/null 2>&1; then
    die "$EMAIL has MFA enabled, which this script cannot complete. Use an API key:
      console → Settings → API keys → create (role editor or above), then
      export SENTINEL_API_KEY=<key>   and re-run."
  fi
  TOK="$(jq -r '.access_token // empty' <<<"$RESP")"
  if [[ -z "$TOK" && -t 0 ]]; then
    warn "the bootstrap password in $ENV_FILE no longer works for $EMAIL (changed — good)"
    read -r -s -p "  Password for $EMAIL: " PW; echo
    RESP="$(login "$PW")"; TOK="$(jq -r '.access_token // empty' <<<"$RESP")"
  fi
  [[ -n "$TOK" ]] || die "could not log in as $EMAIL: $(jq -r '.error // "no token in response"' <<<"$RESP" 2>/dev/null)
    Set SENTINEL_ADMIN_EMAIL / SENTINEL_ADMIN_PASSWORD, or use SENTINEL_API_KEY."
  AUTH=(-H "Authorization: Bearer $TOK")
  ok "authenticated as $EMAIL"
fi
unset PW

# A site with these domains already? Refuse rather than create a duplicate that
# nobody can tell apart in the console.
EXISTING="$(curl -sk --max-time 15 "${AUTH[@]}" "$API/api/v1/sites" 2>/dev/null \
  | jq -r --arg d "$DOMAIN" '(.sites // .)[]? | select(.domains[]? == $d) | .name' 2>/dev/null | head -1)"
[[ -z "$EXISTING" ]] || die "a site named '$EXISTING' already serves $DOMAIN. Edit that one in the console, or delete it first."

# ── origin reachability from THIS host ───────────────────────────────────────
step "Origin"
unreach=0
for o in "${ORIGINS[@]}"; do
  h="${o%:*}"; p="${o##*:}"
  # A name that does not resolve on the HOST may still resolve inside Docker's
  # network (a service name such as `app:8080`), where the WAF actually runs.
  # Say that, instead of reporting a healthy origin as down.
  if [[ ! "$h" =~ ^[0-9.]+$ ]] && ! getent hosts "$h" >/dev/null 2>&1; then
    warn "$h does not resolve on this host — if it is a Docker service name the WAF may still reach it; cannot test from here"
    continue
  fi
  if [[ "$ORIGIN_TLS" == "yes" ]]; then
    c="$(curl -sk --max-time 8 -o /dev/null -w '%{http_code}' --resolve "${SNI}:${p}:${h}" "https://${SNI}:${p}${HEALTH}" 2>/dev/null)"
    label="https://$o (SNI $SNI)"
  else
    c="$(curl -s --max-time 8 -o /dev/null -w '%{http_code}' -H "Host: ${HOST_HEADER:-$DOMAIN}" "http://${h}:${p}${HEALTH}" 2>/dev/null)"
    label="http://$o"
  fi
  case "$c" in
    2??|3??|401|403) ok "$label$HEALTH → $c" ;;
    000) warn "$label$HEALTH → no answer (connection refused, timed out, or TLS failed)"; unreach=1 ;;
    *)   warn "$label$HEALTH → $c" ;;
  esac
done
if [[ $unreach -eq 1 && "$ASSUME_YES" != "yes" && "$DRY_RUN" != "yes" ]]; then
  printf '  %sAn origin did not answer from this host. The WAF will return 502 for it until it does%s\n' "$DIM" "$R"
  printf '  %s(firewall between the WAF and the application? wrong port? origin TLS without --origin-tls?).%s\n' "$DIM" "$R"
  read -r -p "  Continue anyway? [y/N]: " a || true
  [[ "$a" =~ ^[Yy]$ ]] || die "stopped — fix the origin path first"
fi

# ── the site ─────────────────────────────────────────────────────────────────
SERVERS="$(for o in "${ORIGINS[@]}"; do jq -nc --arg h "${o%:*}" --argjson p "${o##*:}" --argjson t "$([[ "$ORIGIN_TLS" == yes ]] && echo true || echo false)" '{host:$h, port:$p, weight:1, tls:$t}'; done | jq -sc '.')"
PROXY="$(jq -nc --argjson ws "$([[ "$WEBSOCKET" == yes ]] && echo true || echo false)" '{websocket:$ws, keepalive:true}')"
[[ "$ORIGIN_TLS" == "yes" ]] && PROXY="$(jq -c --arg s "$SNI" '. + {ssl_sni:true, ssl_sni_name:$s}' <<<"$PROXY")"
[[ -n "$HOST_HEADER" ]] && PROXY="$(jq -c --arg hh "$HOST_HEADER" '. + {host_header:$hh}' <<<"$PROXY")"
UPSTREAM="$(jq -nc --argjson s "$SERVERS" --arg hp "$HEALTH" --argjson px "$PROXY" \
  '{load_balancer:"round_robin", servers:$s, health_check:{path:$hp, interval:"10s", timeout:"3s"}, timeout_secs:30, connect_timeout_secs:5, proxy:$px}')"
WAF="$(jq -nc --arg m "$MODE" --argjson t "$THRESHOLD" --argjson bl "$BODY_LIMIT" \
  '{mode:$m, paranoia_level:2, anomaly_threshold:$t, max_body_size:$bl, max_uri_length:8192, max_header_count:100,
    allowed_methods:["GET","HEAD","POST","PUT","PATCH","DELETE","OPTIONS"],
    ml:{enable:true, models:[], sensitivity:0.9}}')"
BODY="$(jq -nc --arg n "$NAME" --arg d "$DOMAIN" --argjson u "$UPSTREAM" --argjson w "$WAF" '{name:$n, domains:[$d], upstream:$u, waf_policy:$w}')"

step "What will be created"
printf '  site        %s\n' "$NAME"
printf '  domain      %s   %s(exact Host-header match — nothing else answers to it)%s\n' "$DOMAIN" "$DIM" "$R"
for o in "${ORIGINS[@]}"; do printf '  origin      %s://%s%s\n' "$([[ "$ORIGIN_TLS" == yes ]] && echo https || echo http)" "$o" "$([[ "$ORIGIN_TLS" == yes ]] && printf '  SNI %s' "$SNI")"; done
[[ -n "$HOST_HEADER" ]] && printf '  host header %s (rewritten for the origin)\n' "$HOST_HEADER"
printf '  health      %s every 10s\n' "$HEALTH"
printf '  websockets  %s\n' "$WEBSOCKET"
printf '  body limit  %s bytes\n' "$BODY_LIMIT"
printf '  certificate %s\n' "${CERT:-none — the WAF presents its self-signed default until one is installed}"
if [[ "$MODE" == "learning" ]]; then
  printf '  mode        %sLEARNING%s — every request inspected and recorded, nothing blocked\n' "$B" "$R"
else
  printf '  mode        %sBLOCKING%s — attacks get 403 from the first request\n' "$RED" "$R"
  warn "blocking before a learning window means the false-positive rate for THIS application is unmeasured."
fi
printf '  threshold   %s (paranoia 2)\n' "$THRESHOLD"

if [[ "$DRY_RUN" == "yes" ]]; then
  printf '\n  %s--dry-run: the site payload that would be sent:%s\n' "$YEL" "$R"
  jq '.' <<<"$BODY" | sed 's/^/    /'
  [[ -n "$CERT" ]] && printf '  %s(plus POST /api/v1/certs/manual for %s — PEM contents not shown)%s\n' "$DIM" "$DOMAIN" "$R"
  printf '\n  %snothing was changed.%s\n\n' "$YEL" "$R"; exit 0
fi
if [[ "$ASSUME_YES" != "yes" ]]; then
  read -r -p "  Create it? [Y/n]: " a || true
  [[ -z "$a" || "$a" =~ ^[Yy]$ ]] || die "aborted — nothing was created"
fi

# ── install the certificate first, so the site never serves the default cert ──
if [[ -n "$CERT" ]]; then
  step "Installing the certificate"
  CRESP="$(curl -sk --max-time 30 -X POST "$API/api/v1/certs/manual" "${AUTH[@]}" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg d "$DOMAIN" --arg n "$NAME" --rawfile c "$CERT" --rawfile k "$KEY" '{domain:$d, name:$n, cert_pem:$c, key_pem:$k}')" \
    -w '\n%{http_code}' 2>/dev/null)"
  ccode="${CRESP##*$'\n'}"; cbody="${CRESP%$'\n'*}"
  [[ "$ccode" =~ ^2 ]] || die "certificate upload failed (HTTP $ccode): $(jq -r '.error // .' <<<"$cbody" 2>/dev/null | head -c 300)"
  ok "installed for $DOMAIN ($(jq -r '.installed // "ok"' <<<"$cbody" 2>/dev/null))"
fi

# ── create ───────────────────────────────────────────────────────────────────
step "Creating the site"
VRESP="$(curl -sk --max-time 20 -X POST "$API/api/v1/sites/validate" "${AUTH[@]}" -H 'Content-Type: application/json' -d "$BODY" -w '\n%{http_code}' 2>/dev/null)"
vcode="${VRESP##*$'\n'}"; vbody="${VRESP%$'\n'*}"
if [[ "$vcode" =~ ^2 ]]; then ok "configuration validated"
else warn "validate → HTTP $vcode: $(jq -r '.error // .errors // .' <<<"$vbody" 2>/dev/null | head -c 300) — trying to create anyway"; fi
CRESP="$(curl -sk --max-time 30 -X POST "$API/api/v1/sites" "${AUTH[@]}" -H 'Content-Type: application/json' -d "$BODY" -w '\n%{http_code}' 2>/dev/null)"
scode="${CRESP##*$'\n'}"; sbody="${CRESP%$'\n'*}"
[[ "$scode" =~ ^2 ]] || die "site creation failed (HTTP $scode): $(jq -r '.error // .' <<<"$sbody" 2>/dev/null | head -c 400)"
SITE_ID="$(jq -r '.site.id // .id // empty' <<<"$sbody")"
ok "site created${SITE_ID:+ (id $SITE_ID)}"

# ── prove it from this host, before DNS moves ────────────────────────────────
step "Proving the path from this host"
# The data plane matches the site at once but compiles its rule engine on a
# separate task. In learning mode the site is SERVED while that happens (a
# transient warm-up is not a broken ruleset), so an early probe is answered
# uninspected and proves nothing. Wait until /healthz no longer lists the site
# as without an engine, then probe.
engine=no; tries=0
INSP="$(curl -s --max-time 5 -H @- http://127.0.0.1/healthz 2>/dev/null <<<"x-sentinel-internal: $(sed -n 's/^SENTINEL_INTERNAL_SECRET=//p' "$ENV_FILE" 2>/dev/null | head -1)" | jq -c '.inspection.sites_without_engine' 2>/dev/null)"
if [[ -z "$INSP" || "$INSP" == "null" ]]; then
  warn "this data plane does not report per-site engine state at /healthz (older build) — waiting 20s instead"
  sleep 20; engine=unknown
else
  while (( tries < 18 )); do
    INSP="$(curl -s --max-time 5 -H @- http://127.0.0.1/healthz 2>/dev/null <<<"x-sentinel-internal: $(sed -n 's/^SENTINEL_INTERNAL_SECRET=//p' "$ENV_FILE" 2>/dev/null | head -1)" | jq -c '.inspection.sites_without_engine // []' 2>/dev/null)"
    if [[ -n "$INSP" ]] && ! grep -qF "$NAME" <<<"$INSP" && ! grep -qF "${SITE_ID:-__none__}" <<<"$INSP"; then engine=yes; break; fi
    sleep 5; tries=$((tries + 1))
  done
  [[ "$engine" == "yes" ]] && ok "rule engine compiled for the site ($((tries * 5))s)" \
    || warn "after 90s /healthz still lists the site without an engine — inspection is not running for it yet"
fi
# 503 = engine still warming; 502 right after creation can be the upstream health
# probe not having run yet (10s interval); the WAF's own 404 "No site is
# configured" means the new site has not reached this node yet. Keep asking for
# a while before calling any of them final.
served=""; tries=0
while (( tries < 12 )); do
  resp="$(curl -sk --max-time 8 -w '\n%{http_code}' --resolve "${DOMAIN}:443:127.0.0.1" "https://${DOMAIN}${HEALTH}" 2>/dev/null)"
  served="${resp##*$'\n'}"
  [[ "$served" == "404" && "$resp" == *"No site is configured for this hostname"* ]] && served="nosite"
  case "$served" in 503|502|000|nosite|"") sleep 5; tries=$((tries + 1)) ;; *) break ;; esac
done
case "$served" in
  2??|3??|401|403) ok "https://$DOMAIN$HEALTH via the WAF → $served (origin answered through the WAF)" ;;
  502) warn "https://$DOMAIN$HEALTH via the WAF → 502: the WAF is serving the site but cannot reach the origin — firewall, port, or --origin-tls" ;;
  503) warn "still 503 after 2 minutes — the rule engine has not come up for this site. Check: curl -s http://127.0.0.1/healthz | jq .inspection" ;;
  nosite) warn "after 2 minutes this node still has no site for $DOMAIN — the new site has not reached the data plane. Check the Cluster page for a node REJECTING config" ;;
  *)   warn "https://$DOMAIN$HEALTH via the WAF → ${served:-no answer}" ;;
esac
if [[ -n "$CERT_FP" && "$HAVE_OPENSSL" == "yes" ]]; then
  SERVED_FP="$(openssl s_client -connect 127.0.0.1:443 -servername "$DOMAIN" </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null | sed 's/^.*=//')"
  if [[ -n "$SERVED_FP" && "$SERVED_FP" == "$CERT_FP" ]]; then ok "the WAF presents YOUR certificate for $DOMAIN (fingerprint matches)"
  else warn "the WAF presented a different certificate for $DOMAIN (served ${SERVED_FP:-nothing}, uploaded $CERT_FP) — check the console → Certificates"; fi
fi
# Send the probe, look for its record; re-send on each poll in case the first
# one landed a moment before the engine did.
EV=""; ATTACK=""
for _ in $(seq 1 8); do
  ATTACK="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 --resolve "${DOMAIN}:443:127.0.0.1" "https://${DOMAIN}/?id=1%27+OR+1%3D1--" 2>/dev/null)"
  sleep 4
  EV="$(curl -sk --max-time 10 "${AUTH[@]}" "$API/api/v1/events/search?limit=50" 2>/dev/null \
        | jq -c --arg s "$NAME" --arg d "$DOMAIN" '[.events[]? | select(.site==$s or .site==$d or .host==$d)] | first // empty' 2>/dev/null)"
  [[ -n "$EV" ]] && break
done
if [[ -n "$EV" ]]; then
  ok "test attack → $ATTACK and recorded: rule $(jq -r '.rule' <<<"$EV") score $(jq -r '.score' <<<"$EV")/$(jq -r '.threshold' <<<"$EV") $(jq -r '.attack // ""' <<<"$EV")"
else
  warn "test attack → $ATTACK but no detection was recorded for '$NAME' within 30s — inspection is NOT confirmed; do not switch to blocking until it is"
fi

# ── what happens next, in order ──────────────────────────────────────────────
EGRESS_SET="$(sed -n 's/^SENTINEL_SHARED_EGRESS_CIDRS=//p' "$ENV_FILE" | head -1)"
cat <<NEXT

  ${GRN}${B}$DOMAIN is configured on this WAF in ${MODE^^} mode.${R}
  DNS still points at the old server — nobody is affected yet. Do these in order:

  ${B}1. Test from your laptop, without touching DNS${R}
     Add to your hosts file:     ${B}$WAF_IP  $DOMAIN${R}
       (Windows: C:\\Windows\\System32\\drivers\\etc\\hosts · Linux/Mac: /etc/hosts)
     then open https://$DOMAIN in the browser and go through the FULL login and
     the journeys that matter. Or from a terminal:
       curl -sI --resolve $DOMAIN:443:$WAF_IP https://$DOMAIN$HEALTH
     Remove the hosts entry afterwards.

  ${B}2. Lower the DNS TTL${R} for $DOMAIN to 60 s, at least 24 h before cutover.

  ${B}3. Public ingress${R} — network team forwards ONLY tcp/80 and tcp/443 (udp/443 optional)
     from the public address to ${B}$WAF_IP${R}. Never 9443, never 22, never 1:1.

  ${B}4. Cutover${R} — change the A record for $DOMAIN to the public address. Rollback is
     the same change in reverse (takes one TTL).

  ${B}5. Lock the origin${R} — the application's firewall accepts 80/443 only from $WAF_IP.
     Until then the WAF can be walked around by anyone who learns the origin address.

  ${B}6. Learning window${R} — one full business cycle. Read the learning report, add
     scoped exclusions for what the application legitimately does, then switch
     to blocking in the console. Guide: $INSTALL_DIR/docs/manual/SITE-ONBOARDING.md
NEXT
if [[ -z "$EGRESS_SET" ]]; then
  printf '\n  %s!%s SENTINEL_SHARED_EGRESS_CIDRS is not set in %s. If your users reach the WAF\n' "$YEL" "$R" "$ENV_FILE"
  printf '    through one office NAT/VPN address, set it (comma-separated) and run\n'
  printf '    docker compose -p sentinel -f %s/compose.prod.yml up -d dataplane — or one\n' "$INSTALL_DIR"
  printf '    person'"'"'s scan gets the whole office blocked.\n'
fi
printf '\n  Site id: %s   Undo: curl -sk -X DELETE %s/api/v1/sites/%s (with your token)\n\n' "${SITE_ID:-?}" "$API" "${SITE_ID:-<id>}"
