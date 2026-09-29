# Deployment topology
**Generated** by `deploy/gen-topology.py` from the merged compose configuration. Do not edit by hand.

The production deployment is **3 compose files, 1369 lines**, applied as an override chain:

1. `deploy/docker/compose.prod.yml`
2. `deploy/docker/compose.cluster.yml`
3. `deploy/docker/compose.ha.yml`

Later files override earlier ones. Every command against this deployment must pass all three `-f` flags in this order, plus `--profile demo` on a demo or pilot box — a profile gates what is **recreated** as well as what starts, so omitting it silently leaves those containers on their old image and configuration.

## Services (14)

Image tags read `:latest` here because `SENTINEL_VERSION` is not set when this page is generated; on a deployment the tag is that variable's value. **Health** is `compose` for a check declared in compose, `image` for one baked into the Dockerfile — the distroless images have no shell, so theirs is a static probe binary (`control-plane/cmd/healthprobe`) and compose cannot see it.

| Service | Image | Ports | Depends on | Health | Starts by default |
|---|---|---|---|---|---|
| `clickhouse` | `clickhouse/clickhouse-server:26.3.35.3-alpine` | — | — | compose | yes |
| `controlplane` | `sentinel/controlplane:latest` | — | clickhouse, migrate, postgres, redis | image | yes |
| `cp2` | `sentinel/controlplane:latest` | — | clickhouse, migrate, postgres, redis | image | yes |
| `cp3` | `sentinel/controlplane:latest` | — | clickhouse, migrate, postgres, redis | image | yes |
| `dashboard` | `sentinel/dashboard:latest` | 127.0.0.1:3000→3000 | controlplane | compose | yes |
| `juiceshop` | `bkimminich/juice-shop:v20.1.1@sha256:cd58d79c5cb4d82f22fbaf616f9ff43bbd04ba630cd6b448a9ed99cf652fcebf` | — | — | — | profile: demo |
| `lb` | `haproxy:2.9-alpine` | 80→80, 443→443, 127.0.0.1:8404→8404 | waf1, waf2, waf3 | — | yes |
| `migrate` | `sentinel/migrate:latest` | — | postgres | — | yes |
| `postgres` | `postgres:16-alpine` | — | — | compose | yes |
| `prometheus` | `prom/prometheus:v2.54.1` | — | controlplane | compose | yes |
| `redis` | `valkey/valkey:8-alpine` | — | — | compose | yes |
| `waf1` | `sentinel/dataplane:latest` | 127.0.0.1:9443→9443, 443→8443 | controlplane, redis | image | yes |
| `waf2` | `sentinel/dataplane:latest` | — | controlplane, redis | image | yes |
| `waf3` | `sentinel/dataplane:latest` | — | controlplane, redis | image | yes |

### Which file defines each service

| Service | Defined / overridden in |
|---|---|
| `clickhouse` | compose.prod.yml |
| `controlplane` | compose.prod.yml → compose.cluster.yml |
| `cp2` | compose.cluster.yml |
| `cp3` | compose.cluster.yml |
| `dashboard` | compose.prod.yml |
| `juiceshop` | compose.prod.yml |
| `lb` | compose.ha.yml |
| `migrate` | compose.prod.yml |
| `postgres` | compose.prod.yml |
| `prometheus` | compose.prod.yml |
| `redis` | compose.prod.yml |
| `waf1` | compose.ha.yml |
| `waf2` | compose.ha.yml |
| `waf3` | compose.ha.yml |

## Our own images (8)

Everything else is third-party and pulled at install time. See `THIRD-PARTY-NOTICES.md`.

- `controlplane` — `sentinel/controlplane:latest`
- `cp2` — `sentinel/controlplane:latest`
- `cp3` — `sentinel/controlplane:latest`
- `dashboard` — `sentinel/dashboard:latest`
- `migrate` — `sentinel/migrate:latest`
- `waf1` — `sentinel/dataplane:latest`
- `waf2` — `sentinel/dataplane:latest`
- `waf3` — `sentinel/dataplane:latest`

## Named volumes (8)

State that survives a container. Anything not listed here is lost on recreate.

- `chdata` — used by `clickhouse`
- `pgdata` — used by `postgres`
- `promdata` — used by `prometheus`
- `sentinel-certs` — used by `waf1`, `waf2`, `waf3`
- `sentinel-logs` — used by `controlplane`, `cp2`, `cp3`, `waf1`, `waf2`, `waf3`
- `waf1-state` — used by `waf1`
- `waf2-state` — used by `waf2`
- `waf3-state` — used by `waf3`

## Networks (1)

- `sentinel`

## Bind mounts from inside the source tree

These are the paths a `rsync --delete` of the repository can destroy on a host. `deploy/sync-to-host.sh --list-runtime-mounts <host>` classifies what is actually mounted on a running deployment; run that rather than trusting this list, which is only what the compose files declare.

- `deploy/docker/clickhouse-memory.xml` → `/etc/clickhouse-server/config.d/memory.xml`
- `deploy/docker/clickhouse-logging.xml` → `/etc/clickhouse-server/config.d/logging.xml`
- `deploy/docker/geoip` → `/var/lib/sentinel/geoip`
- `deploy/docker/haproxy.cfg` → `/usr/local/etc/haproxy/haproxy.cfg`
- `deploy/docker/pg_hba.conf` → `/etc/sentinel/pg/pg_hba.conf`
- `deploy/docker/prometheus.yml` → `/etc/prometheus/prometheus.yml`
- `deploy/docker/sentinel.proxy.yaml` → `/etc/sentinel/sentinel.yaml`
- `deploy/docker/origin-ca` → `/etc/sentinel/origin-ca`
