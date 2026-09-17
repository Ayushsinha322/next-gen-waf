#!/usr/bin/env bash
# =============================================================================
# Swaraj Kavach — PRE-EXPOSURE AUDIT
#
# Run this on the WAF host BEFORE a public address is forwarded to it, and read
# every line of the output. It answers one question:
#
#     "If this host becomes reachable from the internet, what becomes reachable
#      WITH it that nobody intended?"
#
# It exists because a WAF host does not become public by having a site added. It
# becomes public all at once, for everything already on it, the moment a firewall
# rule changes — and three properties of this product make that surprising:
#
#   1. SITE MATCHING IS BY HOST HEADER ALONE. site_matches() in
#      crates/sentinel-proxy/src/lib.rs:4787 compares the client's Host against
#      each site's domain list — exact, or a `*.` suffix. The client chooses the
#      Host. So every site on the node is reachable from any address that reaches
#      the node, by anyone who guesses a domain. A site whose domains include
#      `localhost`, `juice` or an internal IP is not "internal": it is one curl
#      -H away from the internet, and those three are guesses an attacker makes
#      in the first minute, not the hundredth.
#
#   2. A `default_site` ANSWERS FOR UNMATCHED HOSTS. With it set, a request whose
#      Host matches nothing is not refused — it is served by that site
#      (lib.rs:2673). Without it, an unmatched Host is a 502, which is the safe
#      behaviour and the one you want while a public address is new.
#
#   3. THE ADMIN CONSOLE MAY BE ON 0.0.0.0. compose.prod.yml publishes 9443 on
#      loopback by default and says why; SENTINEL_MGMT_BIND=0.0.0.0: overrides
#      that for lab boxes, and it is set on the ESDS dev host. Loopback-only was
#      the thing protecting it. A 1:1 NAT publishes the WAF's own admin UI and
#      API — whose management certificate is a self-signed rcgen cert with no IP
#      SAN, so a browser cannot even tell you that you reached the wrong one.
#
# None of this is a defect. All of it is invisible until someone enumerates it,
# and none of it announces itself in a dashboard that lists one site.
#
# Usage:
#   SENTINEL_ADMIN_PASSWORD=... ./pre-exposure-audit.sh [--expect-domain NAME]
#
#   --expect-domain NAME   the ONE hostname the public address is meant to serve.
#                          Every other reachable domain is then reported as an
#                          unintended exposure rather than merely listed.
#
# Env:
#   SENTINEL_API              default https://127.0.0.1:9443
#   SENTINEL_ADMIN_EMAIL      default admin@sentinel.local
#   SENTINEL_ADMIN_PASSWORD   required
#
# Exit 0 = nothing found that must be fixed first. Non-zero = do not open the
# firewall yet. Warnings do not fail the run; findings do.
# =============================================================================
set -uo pipefail

API="${SENTINEL_API:-https://127.0.0.1:9443}"
EMAIL="${SENTINEL_ADMIN_EMAIL:-admin@sentinel.local}"
EXPECT_DOMAIN=""

while [ $# -gt 0 ]; do
  case "$1" in
    --expect-domain) EXPECT_DOMAIN="${2:-}"; shift ;;
    -h|--help) sed -n '2,50p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
warn()  { printf '\033[33m%s\033[0m\n' "$*"; }
bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
die()   { red "FATAL: $*"; exit 2; }

FINDINGS=0
WARNINGS=0
finding() { red   "  ✗ FINDING: $*"; FINDINGS=$((FINDINGS+1)); }
caution() { warn  "  ! $*";          WARNINGS=$((WARNINGS+1)); }
ok()      { green "  ✓ $*"; }

[ -n "${SENTINEL_ADMIN_PASSWORD:-}" ] || die "SENTINEL_ADMIN_PASSWORD is not set"
command -v jq   >/dev/null || die "jq is required"
command -v curl >/dev/null || die "curl is required"

echo "=============================================================="
echo " PRE-EXPOSURE AUDIT — what a public address would reach"
echo " api=$API${EXPECT_DOMAIN:+  intended public domain=$EXPECT_DOMAIN}"
echo "=============================================================="
echo

LOGIN=$(curl -sk -X POST "$API/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg e "$EMAIL" --arg p "$SENTINEL_ADMIN_PASSWORD" '{email:$e,password:$p}')")
TOKEN=$(jq -r '.access_token // .token // empty' <<<"$LOGIN")
[ -n "$TOKEN" ] || die "login failed as $EMAIL — $(jq -rc '.' <<<"$LOGIN" | head -c 300)"

# ---------------------------------------------------------------------------
# 1. Every site, every domain. This is the exposure surface.
# ---------------------------------------------------------------------------
bold "1 · sites reachable by Host header"

# GET /sites returns a bare array; GET /sites/:id returns {"site":{...}}. Handle
# both shapes rather than assuming — assuming the list shape here is what made
# every site read as "not found" in fpr-report.sh (commit c61ea54).
SITES_JSON=$(curl -sk "$API/api/v1/sites" -H "Authorization: Bearer $TOKEN")
SITES=$(jq -c 'if type=="array" then . elif has("sites") then .sites else [.] end' <<<"$SITES_JSON" 2>/dev/null) \
  || die "could not parse GET /sites — $(head -c 200 <<<"$SITES_JSON")"
COUNT=$(jq 'length' <<<"$SITES")
echo "  $COUNT site(s) configured on this node"
echo

# Hosts nobody should be able to reach a real application through from outside.
# Not exhaustive by design — the point is to make the operator LOOK at the list.
RISKY_RE='^(localhost|127\.0\.0\.1|0\.0\.0\.0|.*\.local|.*\.internal|10\..*|172\.(1[6-9]|2[0-9]|3[01])\..*|192\.168\..*)$'

while IFS= read -r site; do
  [ -n "$site" ] || continue
  SID=$(jq -r '.id' <<<"$site")
  SNAME=$(jq -r '.name // "?"' <<<"$site")
  SMODE=$(jq -r '.waf_policy.mode // "?"' <<<"$site")
  printf '  %s  (%s)  mode=%s\n' "$SNAME" "$SID" "$SMODE"

  while IFS= read -r d; do
    [ -n "$d" ] || continue
    if [ -n "$EXPECT_DOMAIN" ] && [ "$d" = "$EXPECT_DOMAIN" ]; then
      ok "    $d — intended"
    elif [[ "$d" =~ $RISKY_RE ]]; then
      finding "    $d — a guessable/internal Host on a publicly reachable node." \
              "Anyone can send it: curl -H 'Host: $d' https://<public-ip>/"
    elif [ -n "$EXPECT_DOMAIN" ]; then
      caution "    $d — reachable from the public address but not the intended domain"
    else
      echo    "    $d"
    fi
  done < <(jq -r '.domains[]?' <<<"$site")

  # A deliberately vulnerable origin on a host about to face the internet is the
  # single worst finding this script can produce, so name it explicitly.
  UP=$(jq -r '.upstream.servers[]? | "\(.host):\(.port)"' <<<"$site" 2>/dev/null | tr '\n' ' ')
  case "$UP" in
    *juiceshop*|*juice-shop*)
      finding "    upstream $UP is OWASP Juice Shop — DELIBERATELY VULNERABLE." \
              "It must not be reachable from a public address. Delete the site, or" \
              "narrow its domains to a name that is not guessable and confirm the" \
              "firewall cannot reach it." ;;
    *) [ -n "$UP" ] && echo "    → upstream $UP" ;;
  esac
  echo
done < <(jq -c '.[]' <<<"$SITES")

# ---------------------------------------------------------------------------
# 2. Unmatched Host behaviour. 502 is correct and safe here.
# ---------------------------------------------------------------------------
bold "2 · unmatched Host"

# A host that matches nothing. If this returns anything other than 502/404, a
# default_site is answering for it and the node has no "not for you" response.
UNMATCHED=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 \
  -H 'Host: audit-unmatched-host.invalid' https://127.0.0.1/ 2>/dev/null)
case "$UNMATCHED" in
  502|404|000)
    ok "unmatched Host → $UNMATCHED (no default_site answering; this is what you want)" ;;
  *)
    finding "unmatched Host → $UNMATCHED, so some site answers for a Host it never" \
            "declared. That is a default_site (config/mod.rs:187). Unset it before" \
            "going public, or every scanner hitting the bare IP lands in a real app." ;;
esac
echo

# ---------------------------------------------------------------------------
# 3. What else is listening. Only 80 and 443 may be forwarded.
# ---------------------------------------------------------------------------
bold "3 · listeners on non-loopback addresses"

if command -v ss >/dev/null; then
  # Everything bound to something other than 127.0.0.1/::1 is reachable from any
  # network the host is on — which includes the internet under a 1:1 NAT.
  EXPOSED=$(ss -Hltnp 2>/dev/null | awk '{print $4}' \
            | grep -Ev '^(127\.0\.0\.1|\[::1\]):' | sed 's/.*://' | sort -un)
  for p in $EXPOSED; do
    case "$p" in
      80|443) ok "port $p — intended public entrypoint" ;;
      9443)   finding "port 9443 is on a non-loopback address — that is the ADMIN" \
                      "CONSOLE and API. Under a 1:1 NAT it is published to the" \
                      "internet with a self-signed cert. Forward ONLY 80 and 443," \
                      "and set SENTINEL_MGMT_BIND=127.0.0.1: in deploy/docker/.env" \
                      "unless a host firewall restricts it." ;;
      22)     caution "port 22 (SSH) is on a non-loopback address — must not be forwarded" ;;
      *)      caution "port $p is on a non-loopback address — confirm it is not forwarded" ;;
    esac
  done
else
  caution "ss(8) not available — enumerate listeners by hand before opening the firewall"
fi
echo

# ---------------------------------------------------------------------------
# 4. Who can log in. One shared account is not an audit trail.
# ---------------------------------------------------------------------------
bold "4 · console accounts"

USERS=$(curl -sk "$API/api/v1/users" -H "Authorization: Bearer $TOKEN" 2>/dev/null)
NUSERS=$(jq -r 'if type=="array" then length elif has("users") then (.users|length) else empty end' <<<"$USERS" 2>/dev/null)
if [ -n "${NUSERS:-}" ] && [ "$NUSERS" -ge 1 ]; then
  echo "  $NUSERS account(s)"
  if [ "$NUSERS" -eq 1 ]; then
    caution "a single shared account: the audit log cannot attribute a change to a person." \
            "Known open item — not a blocker for a practice site, but it is one for a customer."
  fi
else
  caution "could not enumerate /users — check by hand"
fi
echo

# ---------------------------------------------------------------------------
bold "verdict"
if [ "$FINDINGS" -gt 0 ]; then
  red "  $FINDINGS finding(s), $WARNINGS warning(s) — DO NOT open the firewall yet."
  exit 1
fi
green "  0 findings, $WARNINGS warning(s)."
echo "  Safe to forward ports 80 and 443 to this host. Nothing here checks the"
echo "  firewall itself — confirm with the network team that the rule is a port"
echo "  forward of 80/443 only, and not a 1:1 NAT of the whole address."
exit 0
