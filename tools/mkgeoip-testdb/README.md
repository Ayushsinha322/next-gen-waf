# mkgeoip-testdb

Builds the synthetic `GeoLite2-Country-test.mmdb` fixture used by
`crates/sentinel-modules` to test country filtering.

```sh
cd tools/mkgeoip-testdb && go build -o mkgeoip-testdb .
./mkgeoip-testdb ../../crates/sentinel-modules/tests/fixtures/GeoLite2-Country-test.mmdb
```

## Why it exists

Country filtering had **no end-to-end test**, because a real MaxMind database
cannot be committed: MaxMind requires an account and its licence forbids
redistributing the data inside a third-party product. So "a configured country
block actually blocks" was an assumption for the entire life of the feature —
which is how the whole control came to be inert on every deployment without
anyone noticing.

This closes that gap without touching MaxMind's data. It uses MaxMind's
`mmdbwriter` library (Apache-2.0) to emit a file in the same format, populated
only with:

* RFC 5737 documentation ranges — `203.0.113.0/24` (CN), `198.51.100.0/24` (RU),
  `192.0.2.0/24` (US)
* RFC 1918 private space — `172.18.0.0/16` (CN, the compose bridge),
  `10.0.0.0/8` (GB)

The country codes are arbitrary. The file is **useless for real geolocation and
sufficient to prove the enforcement path**, which is exactly the trade wanted in
a fixture.

`IncludeReservedNetworks: true` is required, and its absence is why the first
attempt silently produced no file: mmdbwriter refuses reserved networks by
default, and every range here is deliberately reserved. Using real routable
ranges would be worse — the fixture would then assert something about addresses
that belong to somebody.

## This is NOT a substitute for a real database

Nothing here makes country filtering work in production. For that, supply a real
`GeoLite2-Country.mmdb` — see `deploy/docker/geoip/README.md`. Until you do, the
WAF reports the gap at `/healthz` → `geoip.inert` rather than pretending.
