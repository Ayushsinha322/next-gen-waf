#!/usr/bin/env bash
# Does the CODE fix converge the fleet on one self-signed cert?
#
# Must use an SNI name with NOTHING on disk. wafdemo.esds.local already has a
# hand-placed cert as an interim fix, so testing with it would prove only that
# reading a file works — masking whether the generate-and-persist path does.
set -uo pipefail
V=/var/lib/docker/volumes/sentinel_sentinel-certs/_data
D="certshare-$(date +%s).esds.local"
pass=0; fail=0
ok()  { printf "  \033[32mPASS\033[0m  %s\n" "$1"; pass=$((pass+1)); }
bad() { printf "  \033[31mFAIL\033[0m  %s\n" "$1"; fail=$((fail+1)); }

echo "  using a brand-new SNI name: $D"
echo "  on disk before: $(ls -d "$V/$D" 2>/dev/null || echo '<nothing>')"

echo
echo "=== 15 handshakes for a name no node has seen ==="
for _ in $(seq 1 15); do
  echo | timeout 8 openssl s_client -connect 127.0.0.1:443 -servername "$D" 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | cut -c1-23
done | sort | uniq -c | sed 's/^/    /'
N=$(for _ in $(seq 1 15); do
  echo | timeout 8 openssl s_client -connect 127.0.0.1:443 -servername "$D" 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2
done | sort -u | grep -c .)
[ "$N" = "1" ] \
  && ok "all nodes converged on ONE self-signed cert (was 3 before this fix)" \
  || bad "$N distinct certs — the fleet has NOT converged"

echo
echo "=== was it persisted to the shared volume? ==="
if [ -f "$V/$D/cert.pem" ] && [ -f "$V/$D/key.pem" ]; then
  ok "cert.pem + key.pem written to the shared store"
  echo "    perms: $(stat -c '%a %n' "$V/$D/cert.pem" "$V/$D/key.pem" | tr '\n' ' ')"
  [ "$(stat -c '%a' "$V/$D/key.pem")" = "600" ] \
    && ok "private key is 0600" || bad "private key is $(stat -c '%a' "$V/$D/key.pem"), want 600"
  grep -q '"source": *"self_signed"' "$V/$D/meta.json" 2>/dev/null \
    && ok "meta.json records source=self_signed (not passed off as manual/ACME)" \
    || echo "    meta.json source: $(python3 -c "import json;print(json.load(open('$V/$D/meta.json')).get('source'))" 2>/dev/null || echo '<unreadable>')"
else
  bad "nothing written to $V/$D — a new node would still invent its own"
fi

echo
echo "=== a restart must not change it ==="
BEFORE=$(md5sum "$V/$D/cert.pem" 2>/dev/null | cut -d' ' -f1)
( cd /opt/sentinel-src/deploy/docker && docker compose -p sentinel \
    -f compose.prod.yml -f compose.cluster.yml -f compose.ha.yml \
    up -d --no-deps --force-recreate waf2 >/dev/null 2>&1 )
for _ in $(seq 1 40); do [ "$(docker inspect -f '{{.State.Status}}' sentinel-waf2-1)" = running ] && break; sleep 2; done
sleep 5
AFTER=$(md5sum "$V/$D/cert.pem" 2>/dev/null | cut -d' ' -f1)
[ -n "$BEFORE" ] && [ "$BEFORE" = "$AFTER" ] \
  && ok "recreating a node did not rewrite the cert" \
  || bad "the on-disk cert changed after a restart ($BEFORE -> $AFTER)"
N2=$(for _ in $(seq 1 9); do
  echo | timeout 8 openssl s_client -connect 127.0.0.1:443 -servername "$D" 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2
done | sort -u | grep -c .)
[ "$N2" = "1" ] && ok "still one cert after the restart" || bad "$N2 certs after restart"

echo
echo "=== cleanup: remove the throwaway name ==="
rm -rf "$V/$D" && echo "    removed $V/$D"

echo
echo "=== RESULT: $pass passed, $fail failed ==="
exit $(( fail > 0 ))
