# GeoIP database

Country filtering needs an MMDB country database in this directory. Since
2026-09-07 the control plane's **`geoip.refresh` job fetches one automatically**:
DB-IP's free *IP to Country Lite* database (licence CC BY 4.0), published monthly
at `https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.mmdb.gz`, written
here as `dbip-country-lite.mmdb`. Every data plane mounts this directory read-only
at `/var/lib/sentinel/geoip` and re-opens the file within a minute of it changing
(`/healthz -> geoip` shows `active`). The control plane mounts it read-write.

Attribution required by the licence and shown in the console: **IP Geolocation by
DB-IP** (https://db-ip.com).

Controls (Global Settings → GeoIP, or env): `geoip.auto_fetch` (default on),
`geoip.fetch_url`, `geoip.max_age_days` (default 7). System Jobs → `geoip.refresh`
→ *Run now* forces a download.

## Using MaxMind GeoLite2 instead

Turn `geoip.auto_fetch` off, download *GeoLite2-Country* in MMDB format with your
MaxMind account, copy it here, and set `SENTINEL_GEOIP_DB` to its path in
`deploy/docker/.env`. MaxMind's licence does not permit us to ship it.
