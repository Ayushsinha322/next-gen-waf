# GeoIP database — supply your own

Country filtering needs a MaxMind **GeoLite2-Country.mmdb**. It is not shipped
with this product and cannot be: MaxMind requires an account, and its licence
does not permit redistributing the database inside a third-party bundle.

Drop the file here:

    deploy/docker/geoip/GeoLite2-Country.mmdb

Then restart the data plane. Nothing else to configure — every WAF node mounts
this directory read-only at `/var/lib/sentinel/geoip`, and that is where
`SENTINEL_GEOIP_DB` points by default.

Get it from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
(free account, then download the *Country* database in **MMDB** format — the CSV
form will not load).

## Until you do, country filtering is NOT enforced

This is the part that used to be silent. Without the database the WAF resolves
every address to `Unknown`, so a site configured to block `["CN","RU"]` passes
all traffic while the console still shows the policy. It now says so in three
places instead of none:

* an **ERROR** at startup naming the consequence,
* `/healthz` → `geoip.inert`, which lists every site whose country policy is
  configured and not applied (`/waf/status` relays it to the console),
* `geoip.configured` vs `geoip.active` — if those differ, something is claimed
  and not done.

Check it with:

    curl -sk https://127.0.0.1:9443/healthz | python3 -m json.tool | grep -A12 geoip
