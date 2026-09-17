#!/usr/bin/env bash
# Swaraj Kavach — Postgres TLS server certificate issuer.
#
# WHY: the control plane connected to Postgres over PLAINTEXT. Every DSN shipped
# with sslmode=disable (deploy/docker/.env.example, compose.full.yml,
# k8s/11-secrets.example.yaml), and the compose Postgres was stock
# postgres:16-alpine with no certificate and no ssl=on — so it could not have
# accepted TLS even if a client asked. Everything the control plane reads and
# writes crossed the network in the clear: session tokens, API-key hashes, audit
# rows, tenant configuration, and the credentials in the connection handshake.
#
# Merely flipping sslmode in the DSN would have BROKEN every connection rather than
# securing it, because the server offers no TLS. This script fixes the server side
# first; the DSN change follows in compose/.env.
#
# Reuses the internal Root CA created by issue-ip-cert.sh so there is one trust
# root for the deployment, not two.
#
# Re-runnable: the Root CA is created once and reused; each run issues a fresh leaf.
set -euo pipefail

# Overridable so the cert flow can be exercised outside /opt (tests, CI).
PKI_DIR="${PKI_DIR:-/opt/sentinel-pki}"
LEAF_DAYS="${LEAF_DAYS:-825}"
CA_DAYS="${CA_DAYS:-3650}"

# Hostnames clients use to reach Postgres. sslmode=verify-full checks the hostname
# against these, so every name any client dials must appear here:
#   postgres                        — the compose service name
#   sentinel-postgres-rw            — the CloudNativePG primary Service
#   localhost / 127.0.0.1           — local psql and the integration tests
PG_HOSTS="${PG_HOSTS:-postgres,sentinel-postgres-rw,sentinel-postgres-rw.sentinel.svc.cluster.local,localhost}"
PG_IPS="${PG_IPS:-127.0.0.1}"

# postgres:16-alpine runs as uid/gid 70. Postgres REFUSES to start if its key is
# group/world readable, so the key must be 0600 and owned by that user.
PG_UID="${PG_UID:-70}"
PG_GID="${PG_GID:-70}"

ORG="ESDS Software Solution Ltd"
OU="SIG-CyberSec"
COUNTRY="IN"

umask 077
mkdir -p "$PKI_DIR"
cd "$PKI_DIR"

# ---- 1. Root CA (shared with issue-ip-cert.sh; created once) -----------------
if [[ ! -f root.key || ! -f root.crt ]]; then
  echo "[*] Creating internal Root CA"
  openssl ecparam -name prime256v1 -genkey -noout -out root.key
  openssl req -x509 -new -nodes -key root.key -sha256 -days "$CA_DAYS" \
    -subj "/C=$COUNTRY/O=$ORG/OU=$OU/CN=Swaraj Kavach Internal Root CA" \
    -out root.crt
else
  echo "[*] Reusing existing Root CA (root.crt present)"
fi

# ---- 2. Postgres server leaf -------------------------------------------------
echo "[*] Issuing Postgres server certificate"
openssl ecparam -name prime256v1 -genkey -noout -out pg-server.key

# Build the SAN list. The CN is legacy; verify-full matches on SAN, so the SAN is
# what actually has to be right.
SAN=""
IFS=',' read -ra HOSTS <<< "$PG_HOSTS"
for h in "${HOSTS[@]}"; do
  h="$(echo "$h" | xargs)"   # trim
  [[ -n "$h" ]] && SAN+="DNS:$h,"
done
IFS=',' read -ra IPS <<< "$PG_IPS"
for ip in "${IPS[@]}"; do
  ip="$(echo "$ip" | xargs)"
  [[ -n "$ip" ]] && SAN+="IP:$ip,"
done
SAN="${SAN%,}"
echo "[*] SAN: $SAN"

openssl req -new -key pg-server.key \
  -subj "/C=$COUNTRY/O=$ORG/OU=$OU/CN=postgres" \
  -out pg-server.csr

openssl x509 -req -in pg-server.csr -CA root.crt -CAkey root.key -CAcreateserial \
  -days "$LEAF_DAYS" -sha256 \
  -extfile <(printf 'subjectAltName=%s\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' "$SAN") \
  -out pg-server.crt

# ---- 3. Permissions Postgres will accept ------------------------------------
# Postgres exits at startup if the private key is readable beyond its owner.
chmod 600 pg-server.key
chmod 644 pg-server.crt root.crt
if ! chown "$PG_UID:$PG_GID" pg-server.key pg-server.crt 2>/dev/null; then
  echo "[!] Could not chown to $PG_UID:$PG_GID (need root?). Postgres will refuse"
  echo "    to start unless its key is owned by its own uid with mode 0600."
  exit 1
fi

rm -f pg-server.csr

echo
echo "[✓] Wrote:"
echo "      $PKI_DIR/pg-server.crt   (server cert, mounted read-only into postgres)"
echo "      $PKI_DIR/pg-server.key   (server key, 0600 owned by $PG_UID:$PG_GID)"
echo "      $PKI_DIR/root.crt        (CA clients verify against — sslrootcert)"
echo
echo "    Verify:  openssl x509 -in $PKI_DIR/pg-server.crt -noout -text | grep -A1 'Subject Alternative Name'"
echo "    Then:    docker compose -f compose.prod.yml up -d postgres"
echo "    Confirm: docker compose exec postgres psql -U \$POSTGRES_USER -d \$POSTGRES_DB \\"
echo "               -c \"SELECT ssl, version, cipher FROM pg_stat_ssl JOIN pg_stat_activity USING (pid) WHERE pid = pg_backend_pid();\""
