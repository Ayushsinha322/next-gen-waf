# Sentinel WAF — Database & Multi-Tenancy Architecture

## Stack

| Purpose | Engine | Notes |
|---|---|---|
| **Primary OLTP** | PostgreSQL 16 | tenants, users, RBAC, sites, rules, plugins, audit |
| **Cache / Sessions / Counters** | Redis 7 | hot config, rate-limit, distributed locks, pub/sub |
| **Logs & Analytics** | ClickHouse 24+ | access logs, security events, traffic metrics |
| **Embedded fallback** | SQLite (via sqlx) | single-node / on-prem / dev mode |
| **Object storage** | S3-compatible (MinIO/AWS S3) | ML model blobs, plugin WASM, scanner reports |

## Why Postgres (not MongoDB like eNlight, not MySQL)

- **Row-Level Security (RLS)** — the killer feature for multi-tenancy. Tenant isolation enforced by the database itself.
- **JSONB** — flexible rule/config storage with indexable queries.
- **CTE, window functions, partial indexes** — needed for audit & reporting queries.
- **Logical replication** — easy HA, read replicas, geo-failover.
- **pgvector** — built-in vector search if we need embedding-based threat similarity.

## Multi-Tenancy Model

### Tier 1: Shared schema + RLS (default for SaaS)

Every tenant-scoped table has `tenant_id UUID NOT NULL`. RLS policies force every query to filter by the current `app.current_tenant` session variable.

```sql
CREATE TABLE sites (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    domains     TEXT[] NOT NULL,
    config      JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

ALTER TABLE sites ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON sites
    USING  (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

CREATE INDEX sites_tenant_id_idx ON sites(tenant_id);
```

Application opens a connection, sets `SET LOCAL app.current_tenant = '<uuid>'`, then runs queries normally. Even if app code forgets a `WHERE tenant_id = ?`, RLS blocks cross-tenant reads/writes.

### Tier 2: Schema-per-tenant (enterprise / compliance)

For tenants demanding hard isolation (HIPAA, banking):
- Each tenant gets their own Postgres schema: `tenant_<short_id>`
- Same DDL applied via migration runner
- App sets `search_path = tenant_acme, public` instead of RLS
- Backup/restore per-tenant becomes trivial

### Tier 3: Dedicated cluster (on-prem)

- Single tenant per Postgres instance
- RLS disabled, no `tenant_id` column needed (simpler ops)
- Same schema, controlled by `deployment_mode = "single_tenant"` in config

All three tiers use the **same Go data-access code**, controlled by a `TenantStrategy` interface.

## Core Schema (high level)

```
tenants            -- top-level tenant org
├── users         -- members of a tenant (with role)
├── api_keys      -- machine credentials
├── audit_logs    -- append-only, signed, RLS-protected
├── sites         -- websites/applications protected
│   ├── upstreams
│   ├── tls_certs
│   └── waf_policies
├── rules         -- WAF rules (custom + imported CRS refs)
├── rule_sets     -- bundles of rules attached to sites
├── plugins       -- installed WASM plugins per tenant
├── ml_profiles   -- per-site ML baselines
├── ip_lists      -- allow/deny lists
├── alerts        -- triggered alerts (ack/resolve workflow)
└── reports       -- scheduled report definitions
```

ClickHouse mirrors a subset for analytics:

```
access_logs        -- every request (sampled at high traffic)
security_events    -- every block/challenge/anomaly
traffic_metrics    -- 1s / 1m / 1h pre-aggregated rollups
```

## Connection Lifecycle (Go control plane)

```go
// every HTTP/gRPC request:
//   1. authenticate -> resolve user -> resolve tenant_id
//   2. acquire DB conn from pool
//   3. SET LOCAL app.current_tenant = $tenantID
//   4. SET LOCAL app.current_user   = $userID  (used by audit triggers)
//   5. run business query (RLS auto-filters)
//   6. on commit, audit triggers write to audit_logs
```

## Migrations

- Tool: **goose** or **golang-migrate** (Go-native, embeds .sql files)
- Location: `control-plane/internal/db/migrations/`
- Forward-only in prod, reversible in dev.

## High Availability

- **Postgres:** primary + 2 sync replicas via streaming replication; automatic failover via Patroni or cloud-managed (RDS, Cloud SQL).
- **Redis:** Redis Sentinel or Cluster mode (3 masters + 3 replicas).
- **ClickHouse:** ReplicatedMergeTree across 3 nodes with ZooKeeper/Keeper.

## Backup Strategy

| Data | Tool | Frequency | Retention |
|---|---|---|---|
| Postgres | pgBackRest / WAL-G to S3 | continuous WAL, daily full | 30 days |
| ClickHouse | clickhouse-backup to S3 | hourly | 90 days |
| Redis | RDB + AOF to S3 | hourly RDB | 7 days |
| Plugins/Models | S3 versioning | on write | indefinite |

## Compliance Hooks

- All audit_logs are append-only (RLS forbids UPDATE/DELETE).
- Every audit row HMAC-signed with a rotating key for tamper-evidence.
- Personal data tables tagged with `pii=true` in column comments → exported via `sentinelctl gdpr export <tenant>`.
- Right-to-erasure handled via tenant-scoped `DELETE FROM tenants` cascading.
