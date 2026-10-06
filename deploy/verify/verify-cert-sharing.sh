#!/usr/bin/env bash
# What certificate does the fleet serve, and what does it write to the shared
# cert volume?
#
# Run ON the WAF host. Creates a temporary site and DELETES it again.
#
# THE CONTRACT. The TLS resolver only looks certificates up; nothing a client
# sends makes it generate or write one. (It used to mint and persist a cert for
# every SNI name it had not seen, so a scanner cycling names grew the volume
# and two in-memory maps without bound, before any WAF check ran.)
#   1. A name no site is configured for gets the ONE shared default cert
#      ($V/default) from every node, and nothing is written for it.
#   2. No SNI (https://<ip>/) gets that same default cert.
#   3. A configured site with no cert of its own gets one self-signed cert,
#      minted in the background after the config sync, persisted on the shared
#      volume, and served identically by every node.
#   4. Recreating a node changes neither cert.
#
# Each check uses names with NOTHING on disk: wafdemo.esds.local carries a
# hand-placed cert, so testing with it would prove only that reading a file
# works.
set -uo pipefail
V=/var/lib/docker/volumes/sentinel_sentinel-certs/_data
STAMP=$(date +%s)
U="unconfigured-$STAMP.esds.local"   # never configured anywhere
S="certsite-$STAMP.esds.local"       # configured below, no cert of its own
NAME="probe-certsite-$STAMP"
PSQL="docker exec sentinel-postgres-1 psql -U sentinel -d sentinel -At -c"
compose() {
  ( cd /opt/sentinel-src/deploy/docker && docker compose -p sentinel \
      -f compose.prod.yml -f compose.cluster.yml -f compose.ha.yml "$@" )
}
pass=0; fail=0
ok()   { printf "  \033[32mPASS\033[0m  %s\n" "$1"; pass=$((pass+1)); }
bad()  { printf "  \033[31mFAIL\033[0m  %s\n" "$1"; fail=$((fail+1)); }

# Only restarts the control plane if this run actually CREATED the probe site.
CREATED=0
cleanup() {
  if [ "$CREATED" = "1" ]; then
    $PSQL "delete from sites where name='$NAME'" >/dev/null 2>&1
    compose up -d --no-deps --force-recreate controlplane >/dev/null 2>&1
  fi
  rm -rf "${V:?}/$S" "${V:?}/$U"
}
trap cleanup EXIT

# SHA-256 fingerprint of the cert served for SNI $1; "" sends no SNI at all.
served() {
  local sni=(-noservername)
  [ -n "$1" ] && sni=(-servername "$1")
  echo | timeout 8 openssl s_client -connect 127.0.0.1:443 "${sni[@]}" 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2
}
# The distinct fingerprints over $1 handshakes for SNI $2, one per line.
sample() { for _ in $(seq 1 "$1"); do served "$2"; done | sort -u | grep .; }
ondisk() { openssl x509 -noout -fingerprint -sha256 -in "$1" 2>/dev/null | cut -d= -f2; }
short() { printf '%s' "$1" | cut -c1-23; }

echo "=== 0. the shared default cert exists ==="
DEF=$(ondisk "$V/default/cert.pem")
if [ -z "$DEF" ]; then
  bad "no $V/default/cert.pem — the running image predates this change, or no SNI listener started"
  echo "=== RESULT: $pass passed, $fail failed ==="; exit 1
fi
ok "default cert on the volume: $(short "$DEF")"

echo
echo "=== 1. names no site is configured for: the default cert, nothing written ==="
ENTRIES_BEFORE=$(ls -A "$V" | wc -l)
FPS=$( { for i in $(seq 1 20); do served "scan-$i-$U"; done; sample 10 "$U"; } | sort -u | grep .)
ENTRIES_AFTER=$(ls -A "$V" | wc -l)
printf '%s\n' "$FPS" | cut -c1-23 | sed 's/^/    served: /'
[ "$FPS" = "$DEF" ] \
  && ok "30 handshakes over 21 unconfigured names all got the shared default cert" \
  || bad "unconfigured names were served something other than \$V/default ($(printf '%s\n' "$FPS" | grep -c .) distinct)"
[ ! -e "$V/$U" ] && ok "nothing written under \$V/$U" \
  || bad "$V/$U was created: the handshake still mints"
[ "$ENTRIES_BEFORE" = "$ENTRIES_AFTER" ] \
  && ok "cert volume unchanged ($ENTRIES_AFTER entries)" \
  || bad "cert volume grew $ENTRIES_BEFORE -> $ENTRIES_AFTER entries during the scan"

echo
echo "=== 2. no SNI (bare IP access) ==="
[ "$(sample 9 "")" = "$DEF" ] \
  && ok "every node served the default cert to a client sending no SNI" \
  || bad "no-SNI handshakes did not all get the default cert"

echo
echo "=== 3. a configured site with no cert converges on ONE persisted cert ==="
$PSQL "delete from sites where name='$NAME'" >/dev/null 2>&1
$PSQL "insert into sites (id, tenant_id, name, domains, upstream, waf_policy, status)
       select gen_random_uuid(), tenant_id, '$NAME', ARRAY['$S'], upstream, waf_policy, 'active'
       from sites where name='Juice Shop'" >/dev/null 2>&1
CREATED=1
if [ "$($PSQL "select count(*) from sites where name='$NAME'")" != "1" ]; then
  bad "could not create the probe site (is there a 'Juice Shop' site to clone?)"
  echo "=== RESULT: $pass passed, $fail failed ==="; exit 1
fi
# Restarting the control plane bumps its config version; the nodes then sync.
compose up -d --no-deps --force-recreate controlplane >/dev/null 2>&1
SITE=""
for _ in $(seq 1 60); do
  SITE=$(ondisk "$V/$S/cert.pem")
  [ -n "$SITE" ] && [ "$(sample 9 "$S")" = "$SITE" ] && break
  sleep 2
done
if [ -z "$SITE" ]; then
  bad "no cert under \$V/$S after 2 min: the site never synced, or the sync never minted"
else
  ok "cert persisted to the shared volume: $(short "$SITE")"
  [ "$(stat -c '%a' "$V/$S/key.pem")" = "600" ] \
    && ok "private key is 0600" || bad "private key is $(stat -c '%a' "$V/$S/key.pem"), want 600"
  grep -q '"source": *"self_signed"' "$V/$S/meta.json" 2>/dev/null \
    && ok "meta.json records source=self_signed (not passed off as manual/ACME)" \
    || bad "meta.json does not record source=self_signed"
  FPS=$(sample 15 "$S")
  [ "$FPS" = "$SITE" ] \
    && ok "15 handshakes: every node served the site's persisted cert" \
    || bad "$(printf '%s\n' "$FPS" | grep -c .) distinct certs for the site, or not the persisted one"
  [ "$SITE" != "$DEF" ] && ok "the site has its own cert, not the default" \
    || bad "the site's cert is the default cert"
fi

echo
echo "=== 4. recreating a node changes neither cert ==="
SITE_MD5=$(md5sum "$V/$S/cert.pem" 2>/dev/null | cut -d' ' -f1)
DEF_MD5=$(md5sum "$V/default/cert.pem" 2>/dev/null | cut -d' ' -f1)
compose up -d --no-deps --force-recreate waf2 >/dev/null 2>&1
for _ in $(seq 1 40); do [ "$(docker inspect -f '{{.State.Status}}' sentinel-waf2-1 2>/dev/null)" = running ] && break; sleep 2; done
sleep 8   # the node's first site sync, plus a margin
[ -n "$SITE_MD5" ] && [ "$SITE_MD5" = "$(md5sum "$V/$S/cert.pem" 2>/dev/null | cut -d' ' -f1)" ] \
  && ok "the site cert on disk was not rewritten" || bad "the site cert on disk changed after a recreate"
[ -n "$DEF_MD5" ] && [ "$DEF_MD5" = "$(md5sum "$V/default/cert.pem" 2>/dev/null | cut -d' ' -f1)" ] \
  && ok "the default cert on disk was not rewritten" || bad "the default cert on disk changed after a recreate"
[ -n "$SITE" ] && [ "$(sample 9 "$S")" = "$SITE" ] \
  && ok "still one cert for the site after the recreate" || bad "the site's served cert changed after a recreate"
[ "$(sample 9 "$U")" = "$DEF" ] \
  && ok "still the default cert for an unconfigured name" || bad "an unconfigured name's cert changed after a recreate"

echo
echo "=== cleanup: the probe site and its cert dir are removed on exit ==="
echo
echo "=== RESULT: $pass passed, $fail failed ==="
exit $(( fail > 0 ))
