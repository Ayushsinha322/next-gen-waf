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
# WAF_IP is REQUIRED. It used to default to 172.16.21.71 — an ESDS development VM —
# so every customer install that did not set it (which was all of them: install.sh
# called this script with no environment at all) succeeded, exited 0, and staged a
# "default" certificate whose only SAN was a machine on someone else's network.
# The SNI resolver serves that cert to every client arriving without SNI, i.e. every
# browser visiting https://<the customer's address>/ — so HTTPS was broken on every
# host, in a way importing root.crt could not fix, while the installer reported
# success. Refusing to guess is the only safe default for a certificate subject.
WAF_IP="${WAF_IP:?WAF_IP must be set — refusing to issue a certificate for a guessed address}"
# Optional: when the operator has a hostname, add it as a DNS SAN so the same
# default cert is valid for both https://<ip>/ and https://<hostname>/.
WAF_HOSTNAME="${WAF_HOSTNAME:-}"
LEAF_DAYS="${LEAF_DAYS:-825}"
CA_DAYS="${CA_DAYS:-3650}"

# A hostname that is just the IP again adds nothing and would produce a bogus
# DNS: entry for a numeric name.
if [[ "$WAF_HOSTNAME" == "$WAF_IP" ]]; then WAF_HOSTNAME=""; fi
if [[ -n "$WAF_HOSTNAME" ]]; then
  SAN_LINE="subjectAltName=IP:${WAF_IP},DNS:${WAF_HOSTNAME}"
  SAN_JSON="\"${WAF_IP}\", \"${WAF_HOSTNAME}\""
  LEAF_CN="$WAF_HOSTNAME"
else
  SAN_LINE="subjectAltName=IP:${WAF_IP}"
  SAN_JSON="\"${WAF_IP}\""
  LEAF_CN="$WAF_IP"
fi

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
echo "[*] Issuing leaf cert for ${SAN_LINE#subjectAltName=} (${LEAF_DAYS}d)..."
openssl ecparam -name prime256v1 -genkey -noout -out leaf.key
openssl req -new -key leaf.key \
  -subj "/C=${COUNTRY}/O=${ORG}/OU=${OU}/CN=${LEAF_CN}" \
  -out leaf.csr

cat > leaf.ext <<EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
${SAN_LINE}
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
  "name": "Sentinel Internal CA - default cert (${LEAF_CN})",
  "san": [${SAN_JSON}],
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
