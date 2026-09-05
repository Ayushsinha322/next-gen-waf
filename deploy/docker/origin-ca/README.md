# Origin (upstream) CA bundle

Drop the PEM bundle of the CA that signed your **origin's** certificate here, and
point `SENTINEL_UPSTREAM_CA_FILE` at it:

```sh
cp corporate-root.pem deploy/docker/origin-ca/origin-ca.pem
echo 'SENTINEL_UPSTREAM_CA_FILE=/etc/sentinel/origin-ca/origin-ca.pem' >> deploy/docker/.env
docker compose up -d waf1 waf2 waf3
```

## Why you may need this

When a site's upstream has **"Upstream uses HTTPS"** enabled, the WAF verifies the
origin's certificate — it does not connect blindly. Until this file existed the
only trust anchors were the ~150 **public** roots, with no override, so an origin
whose certificate chains to an internal or corporate CA failed the handshake and
the site returned **502 forever**, with nothing in the UI explaining why.

Applies equally to a **self-signed** origin certificate: put that certificate
itself in the bundle.

## Semantics

Anchors here are **added to** the public roots, not substituted for them, so a
deployment can mix internal-CA and public-CA origins. If the file is missing or
unparseable the WAF logs an **ERROR** and keeps the public roots — trust is never
silently widened, and one bad path does not take every HTTPS origin on the node
down. Origins behind the missing CA keep failing, which is the symptom you are
already chasing, and the log now names the cause.

This differs from `SENTINEL_CLICKHOUSE_CA_FILE` and the SIEM `ca_file`, which each
talk to exactly ONE peer and therefore **replace** the public roots.

Leaving this directory empty is fine and is the default.
