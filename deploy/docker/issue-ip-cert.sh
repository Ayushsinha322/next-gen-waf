#!/usr/bin/env bash
# Sentinel WAF — internal CA + bare-IP server cert issuer.
#
# Stands up a private Root CA (once) and issues a TLS server cert for the WAF's
# bare IP, then stages it into the data-plane cert repository under the "default"
# key. The SNI resolver serves the "default" cert to every client that sends no
# SNI — which is exactly what browsers do when you visit https://<ip>/. So this
# becomes the real, CA-signed cert presented for IP-over-VPN access. Clients that
# import root.crt get a green lock; others see the usual untrusted-issuer warning
# (acceptable per the internal demo decision) but the chain is real.
#
# Re-runnable: the Root CA is created once and reused; each run issues a fresh leaf.
set -euo pipefail

PKI_DIR=/opt/sentinel-pki
CERT_VOL_DATA=/var/lib/docker/volumes/sentinel_sentinel-certs/_data
WAF_IP="${WAF_IP:-172.16.21.71}"
LEAF_DAYS="${LEAF_DAYS:-825}"
CA_DAYS="${CA_DAYS:-3650}"

ORG="ESDS Software Solution Ltd"
OU="SIG-CyberSec"
COUNTRY="IN"

umask 077
mkdir -p "$PKI_DIR"
cd "$PKI_DIR"

# ---- 1. Root CA (create once; reused on re-run) ------------------------------
if [[ ! -f root.key || ! -f root.crt ]]; then
  echo "[*] Generating Sentinel Internal Root CA (ECDSA P-256, ${CA_DAYS}d)..."
  openssl ecparam -name prime256v1 -genkey -noout -out root.key
  openssl req -x509 -new -nodes -key root.key -sha256 -days "$CA_DAYS" \
    -subj "/C=${COUNTRY}/O=${ORG}/OU=${OU}/CN=Sentinel WAF Internal Root CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" \
    -out root.crt
else
  echo "[*] Reusing existing Root CA (root.crt present)"
fi

# ---- 2. Leaf cert for the bare IP --------------------------------------------
echo "[*] Issuing leaf cert for IP:${WAF_IP} (${LEAF_DAYS}d)..."
openssl ecparam -name prime256v1 -genkey -noout -out leaf.key
openssl req -new -key leaf.key \
  -subj "/C=${COUNTRY}/O=${ORG}/OU=${OU}/CN=${WAF_IP}" \
  -out leaf.csr

cat > leaf.ext <<EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:${WAF_IP}
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EXT

openssl x509 -req -in leaf.csr -CA root.crt -CAkey root.key -CAcreateserial \
  -days "$LEAF_DAYS" -sha256 -extfile leaf.ext -out leaf.crt

# PKCS8 private key (most portable for rustls' private_key parser)
openssl pkcs8 -topk8 -nocrypt -in leaf.key -out leaf.pkcs8.key

# ---- 3. Build CertMeta JSON (mirrors crate's cert_store::CertMeta) ------------
ISSUED=$(date -d "$(openssl x509 -startdate -noout -in leaf.crt | cut -d= -f2)" +%s)
EXPIRES=$(date -d "$(openssl x509 -enddate  -noout -in leaf.crt | cut -d= -f2)" +%s)
FP=$(openssl x509 -in leaf.crt -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f')

cat > meta.json <<JSON
{
  "domain": "default",
  "name": "Sentinel Internal CA - IP cert (${WAF_IP})",
  "san": ["${WAF_IP}"],
  "issued_at": ${ISSUED},
  "expires_at": ${EXPIRES},
  "fingerprint": "${FP}",
  "source": "manual"
}
JSON

# ---- 4. Stage into the data-plane cert repository under "default" -------------
DEST="${CERT_VOL_DATA}/default"
mkdir -p "$DEST"
cp leaf.crt       "$DEST/cert.pem"
cp leaf.pkcs8.key "$DEST/key.pem"
cp meta.json      "$DEST/meta.json"
chmod 644 "$DEST/cert.pem" "$DEST/meta.json"
chmod 600 "$DEST/key.pem"

echo
echo "[OK] Installed default IP cert into cert repository: $DEST"
echo "[i]  Root CA to distribute to clients:               $PKI_DIR/root.crt"
echo
echo "=== Leaf summary ==="
openssl x509 -in leaf.crt -noout -subject -issuer -dates -ext subjectAltName
echo
echo "=== Chain verify (leaf against our root) ==="
openssl verify -CAfile root.crt leaf.crt
