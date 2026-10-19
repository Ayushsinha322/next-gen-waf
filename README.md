# Swaraj Kavach

A web application firewall built by ESDS: a Rust data plane that inspects and
proxies traffic, a Go control plane that holds configuration and policy, and a
Next.js console.

`sentinel` is the source codename. It appears in paths, crate names, image names
and environment variables (`SENTINEL_*`); it is never shown to users. The product
name in the UI and in documents is **Swaraj Kavach**.

Current version: see [`VERSION`](VERSION).

## What it does

**Inspection (data plane, Rust)**
- Reverse proxy on Tokio, hyper and rustls: HTTP/1.1, HTTP/2 and HTTP/3 (QUIC)
  to clients, per-site certificates selected by SNI. The leg to the origin is
  HTTP/1.1 by design.
- Rule engine with its own compiler and VM. Runs the OWASP Core Rule Set 4.7.0
  (vendored in `rules/owasp-crs`) plus our own coverage rules for classes CRS
  barely covers (`rules/custom`), with paranoia levels and anomaly scoring.
- Machine learning, opt-in per site: an Isolation Forest anomaly model, a
  character n-gram payload classifier and a false-positive suppression model.
- Modules: rate limiting, bot detection with JA4 TLS fingerprints and
  forward-confirmed verification of good crawlers, IP reputation and
  threat-intelligence feeds, GeoIP country rules, request correlation, WebSocket
  inspection, JWT validation and outbound data-loss masking.
- Repeat offenders are auto-banned; the ban list is enforced in the kernel with
  XDP where the host allows it.
- WebAssembly plugins (wasmtime) from a bundled catalogue, enabled per site.
- Blocking, learning and off modes per site. A site whose rules fail to compile
  fails closed instead of serving uninspected.

**Management (control plane, Go)**
- REST API behind the data plane's management listener; the control plane
  itself has one internal HTTP listener.
- Users with five RBAC roles, local passwords, OIDC single sign-on, TOTP MFA and
  API keys. A hash-chained, verifiable audit log.
- Data planes pull configuration every 5 seconds; config generations are
  versioned and diffable. One leader at a time, elected with a PostgreSQL
  advisory lock.
- Alerts to webhook, Slack, syslog and CEF; scheduled HTML and CSV reports;
  system jobs such as the monthly GeoIP database download.

**Console (Next.js)**
- Overview, traffic, logs and threat search over the event store, sites and
  rules, certificates, blocked sources, threat intel, ML, cluster health, users
  and audit.

**Storage**
- PostgreSQL for configuration, ClickHouse for events and traffic, Valkey for
  shared rate-limit state when more than one data plane runs on a host.

## Architecture

```
  clients ──► XDP ban list (kernel, where the host allows it)
                │
                ▼
  ┌──────────────────────── DATA PLANE (Rust) ────────────────────────┐
  │ TLS / HTTP 1.1·2·3 ─► source checks ─► rule engine ─► ML ─► verdict │──► origin
  │   (block list, rate limit, bot + JA4, GeoIP, threat intel)        │   (HTTP/1.1)
  │   WASM plugins · correlation · DLP          management :9443 ─┐   │
  └──────────────────────────────┬────────────────────────────────┼───┘
            events + traffic     │                    /api/v1/*   │   config pull (5 s)
                                 ▼                                ▼
                            ClickHouse              CONTROL PLANE (Go) ──► PostgreSQL
                                                          ▲
                                         console (Next.js)┘
```

## Repository layout

| Path | What it is |
|---|---|
| `crates/sentinel-bin` | The data-plane binary |
| `crates/sentinel-proxy` | Listeners, TLS, HTTP/1.1, 2 and 3, the request pipeline |
| `crates/sentinel-core` | Configuration, shared types, per-request context |
| `crates/sentinel-rules` | Rule language, compiler and VM; CRS compatibility |
| `crates/sentinel-modules` | Rate limit, bot, GeoIP, IP reputation, DLP, JWT, … |
| `crates/sentinel-ml` | Feature extraction, models and their training data |
| `crates/sentinel-plugins` | WebAssembly plugin runtime |
| `crates/sentinel-ebpf` | The XDP ban-list program and its loader |
| `crates/sentinel-storage` | Valkey and ClickHouse clients |
| `crates/sentinel-telemetry` | Logging and metrics |
| `crates/sentinel-cli` | `sentinel`, the node-local admin CLI |
| `crates/sentinel-srl-validate` | Validates and dry-runs a rule with the real engine |
| `control-plane/` | Go control plane (`cmd/controllerd`), `sentinelctl`, Kubernetes operator |
| `dashboard/` | The console |
| `rules/` | OWASP CRS (`owasp-crs`), our coverage rules (`custom`), a test rule set (`sentinel`) |
| `plugins/` | Plugin catalogue and SDKs |
| `deploy/` | Compose files, installer bundle, 2-VM HA, Kubernetes, backup, CI checks |
| `benchmarks/`, `tests/`, `tools/` | Load harness, fuzz targets, test tooling |
| `engineering-notes/` | Internal engineering notes kept for history; not product documentation |

## Building

Toolchain versions match CI; use the same ones locally.

```sh
# Data plane — Rust 1.85.0
cargo build --workspace --release

# Control plane — Go 1.26.9
cd control-plane && go build ./...

# Console — Node 22
cd dashboard && npm ci && npm run dev        # http://localhost:2222
```

The console's dev server proxies `/api/v1/*` to `CONTROL_PLANE_URL`.

## Testing

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
(cd control-plane && go vet ./... && go test ./...)
(cd dashboard && npm run typecheck && npm run test && npm run build)
```

`deploy/ci/` holds the deployment checks: compose files parse, one version
number everywhere, upgrade and rollback, installer sizing, and the bundle
contract (every path a shipped script references exists).

## Deploying

- Single host: [`deploy/STANDALONE.md`](deploy/STANDALONE.md)
- Two VMs, active/passive with a virtual IP: [`deploy/ACTIVE-PASSIVE.md`](deploy/ACTIVE-PASSIVE.md)
- Customer bundle and installer: `deploy/package/`; checklist in
  [`deploy/DEPLOYMENT-CHECKLIST.md`](deploy/DEPLOYMENT-CHECKLIST.md)
- Putting a site behind the WAF: [`deploy/SITE-ONBOARDING-CHECKLIST.md`](deploy/SITE-ONBOARDING-CHECKLIST.md)
- Running it day to day: [`OPERATIONS.md`](OPERATIONS.md)

## CI

GitLab ([`.gitlab-ci.yml`](.gitlab-ci.yml)) is the pipeline releases are cut
from. [`.github/workflows/ci.yml`](.github/workflows/ci.yml) mirrors it check for
check with the same tool versions, so both forges give the same verdict.

## Security

Report vulnerabilities as described in [`SECURITY.md`](SECURITY.md), not in a
public issue.

## Licence

The licence for this code has not been published yet; it is pending legal
review. Third-party components and their licences are listed in
[`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md) and `licenses/`.
