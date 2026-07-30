#!/usr/bin/env bash
# Sentinel WAF — ClickHouse TLS server certificate issuer.
#
# WHY: in the 2-VM active/passive topology ClickHouse runs on the ACTIVE node
# only (two nodes cannot form a Keeper quorum), so the PASSIVE node's data plane
# writes its event history — and its control plane reads it — across the peer
# link. That link was plaintext HTTP on :8123, which put the ClickHouse password
# and every stored event body (client IPs, request paths, attack payloads) on the
# wire in the clear.
#
# It was the one place left where this deployment protected a database by
# reachability (bind address + a DOCKER-USER /32 rule) rather than by crypto,
# which is the inverse of the posture Postgres has right beside it.
#
# Flipping the URL to https:// alone would BREAK the connection rather than
# secure it, because stock ClickHouse serves no TLS until told to. This script
# does the server side; the client side is
# crates/sentinel-storage/src/clickhouse.rs (Rust writer) and
# control-plane/internal/clickhouse/client.go (Go reader), both of which trust
# SENTINEL_CLICKHOUSE_CA_FILE.
#
# Reuses the internal Root CA created by issue-ip-cert.sh / issue-postgres-cert.sh
# so the deployment has ONE trust root, not three.
#
# Re-runnable: the Root CA is created once and reused; each run issues a fresh leaf.
set -euo pipefail

PKI_DIR="${PKI_DIR:-/opt/sentinel-pki}"
LEAF_DAYS="${LEAF_DAYS:-825}"
CA_DAYS="${CA_DAYS:-3650}"

# Every name/address a client dials must be in the SAN, because both clients
# verify the hostname — a cert that is merely signed by the right CA is still
# rejected if the SAN does not cover the address in SENTINEL_CLICKHOUSE_URL.
#
#   clickhouse                  — the compose service name (same-host containers)
#   localhost / 127.0.0.1       — the container healthcheck and local queries
#   CH_IPS                      — BOTH VMs plus the VIP. Both, deliberately: after
#                                 a role swap the other VM becomes the one serving
#                                 ClickHouse, and a cert naming only the original
#                                 master would then fail verification with no
#                                 obvious cause.
CH_HOSTS="${CH_HOSTS:-clickhouse,sentinel-clickhouse-1,localhost}"
CH_IPS="${CH_IPS:-127.0.0.1}"

# The ClickHouse alpine image runs its server as uid/gid 101. The key must be
# readable by that user or the server starts without TLS (or refuses to start),
# and a cert that is present but unreadable is the same class of bug as the
# absent-Postgres-cert that broke the first 2-VM install.
CH_UID="${CH_UID:-101}"
CH_GID="${CH_GID:-101}"

ORG="ESDS Software Solution Ltd"
OU="SIG-CyberSec"
COUNTRY="IN"

umask 077
mkdir -p "$PKI_DIR"
cd "$PKI_DIR"

# ---- 1. Root CA (shared; created once) ---------------------------------------
if [[ ! -f root.key || ! -f root.crt ]]; then
  echo "[*] Creating internal Root CA"
  openssl ecparam -name prime256v1 -genkey -noout -out root.key
  openssl req -x509 -new -nodes -key root.key -sha256 -days "$CA_DAYS" \
    -subj "/C=$COUNTRY/O=$ORG/OU=$OU/CN=Sentinel WAF Internal Root CA" \
    -out root.crt
else
  echo "[*] Reusing existing Root CA (root.crt present)"
fi

# ---- 2. ClickHouse server leaf ----------------------------------------------
echo "[*] Issuing ClickHouse server certificate"
openssl ecparam -name prime256v1 -genkey -noout -out ch-server.key

SAN=""
IFS=',' read -ra HOSTS <<< "$CH_HOSTS"
for h in "${HOSTS[@]}"; do
  h="$(echo "$h" | xargs)"
  [[ -n "$h" ]] && SAN+="DNS:$h,"
done
IFS=',' read -ra IPS <<< "$CH_IPS"
for ip in "${IPS[@]}"; do
  ip="$(echo "$ip" | xargs)"
  [[ -n "$ip" ]] && SAN+="IP:$ip,"
done
SAN="${SAN%,}"
[[ -n "$SAN" ]] || { echo "[!] empty SAN — set CH_HOSTS/CH_IPS"; exit 1; }
echo "[*] SAN: $SAN"

openssl req -new -key ch-server.key \
  -subj "/C=$COUNTRY/O=$ORG/OU=$OU/CN=clickhouse" \
  -out ch-server.csr

openssl x509 -req -in ch-server.csr -CA root.crt -CAkey root.key -CAcreateserial \
  -days "$LEAF_DAYS" -sha256 \
  -extfile <(printf 'subjectAltName=%s\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' "$SAN") \
  -out ch-server.crt

# ---- 3. Permissions the server will accept ----------------------------------
chmod 600 ch-server.key
chmod 644 ch-server.crt root.crt
if ! chown "$CH_UID:$CH_GID" ch-server.key ch-server.crt 2>/dev/null; then
  echo "[!] Could not chown to $CH_UID:$CH_GID (need root?)."
  echo "    ClickHouse runs as uid $CH_UID and cannot read a root-owned 0600 key,"
  echo "    so TLS would silently not come up."
  exit 1
fi

rm -f ch-server.csr

echo
echo "[✓] Wrote:"
echo "      $PKI_DIR/ch-server.crt   (server cert, mounted read-only into clickhouse)"
echo "      $PKI_DIR/ch-server.key   (server key, 0600 owned by $CH_UID:$CH_GID)"
echo "      $PKI_DIR/root.crt        (CA both clients verify against)"
echo
echo "    Verify SAN:  openssl x509 -in $PKI_DIR/ch-server.crt -noout -text | grep -A1 'Subject Alternative Name'"
echo "    Then:        docker compose -f compose.prod.yml -f compose.2vm-active.yml up -d clickhouse"
echo "    Confirm TLS: curl --cacert $PKI_DIR/root.crt https://<this-vm>:8443/ping   → Ok."
echo "    Confirm the OLD plaintext port is gone:  curl -m3 http://<this-vm>:8123/ping  → must fail"
