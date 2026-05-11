-- =====================================================================
-- Sentinel WAF — Initial schema
-- Multi-tenant via Row-Level Security (RLS).
-- Apply with: goose up
-- =====================================================================

-- +goose Up
-- +goose StatementBegin

CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "pg_trgm";    -- fuzzy text search

-- ---------------------------------------------------------------------
-- Tenants (top-level isolation boundary)
-- ---------------------------------------------------------------------
CREATE TABLE tenants (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug          TEXT UNIQUE NOT NULL,
    name          TEXT NOT NULL,
    plan          TEXT NOT NULL DEFAULT 'free'
                  CHECK (plan IN ('free','pro','enterprise')),
    isolation     TEXT NOT NULL DEFAULT 'shared'
                  CHECK (isolation IN ('shared','schema','dedicated')),
    status        TEXT NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active','suspended','deleted')),
    settings      JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
-- Users (members of a tenant)
-- ---------------------------------------------------------------------
CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email         TEXT NOT NULL,
    name          TEXT,
    password_hash TEXT,                      -- argon2id; NULL for SSO-only
    role          TEXT NOT NULL DEFAULT 'viewer'
                  CHECK (role IN ('owner','admin','editor','viewer','auditor')),
    mfa_secret    TEXT,
    sso_provider  TEXT,                       -- oidc, saml, ldap
    sso_subject   TEXT,
    last_login_at TIMESTAMPTZ,
    status        TEXT NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active','disabled','invited')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, email)
);
CREATE INDEX users_tenant_idx ON users(tenant_id);

-- ---------------------------------------------------------------------
-- API keys (machine identity)
-- ---------------------------------------------------------------------
CREATE TABLE api_keys (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    name          TEXT NOT NULL,
    key_hash      TEXT NOT NULL UNIQUE,       -- sha256 of key
    scopes        TEXT[] NOT NULL DEFAULT '{}',
    expires_at    TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ,
    last_used_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX api_keys_tenant_idx ON api_keys(tenant_id);

-- ---------------------------------------------------------------------
-- Sites (protected web applications)
-- ---------------------------------------------------------------------
CREATE TABLE sites (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    domains       TEXT[] NOT NULL,
    upstream      JSONB NOT NULL,             -- {servers, lb, healthcheck}
    waf_policy    JSONB NOT NULL,             -- {mode, paranoia, ml, dlp,...}
    tls           JSONB,                       -- {cert_id, min_version, pq}
    status        TEXT NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active','paused','draft')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);
CREATE INDEX sites_tenant_idx ON sites(tenant_id);

-- ---------------------------------------------------------------------
-- Rules (WAF rules)
-- ---------------------------------------------------------------------
CREATE TABLE rules (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    source        TEXT NOT NULL DEFAULT 'custom'
                  CHECK (source IN ('custom','crs','community','virtual_patch','ai_generated')),
    phase         INT NOT NULL CHECK (phase BETWEEN 0 AND 6),
    severity      TEXT NOT NULL DEFAULT 'medium'
                  CHECK (severity IN ('info','low','medium','high','critical')),
    dsl           TEXT NOT NULL,               -- source DSL
    bytecode      BYTEA,                       -- compiled bytecode
    enabled       BOOLEAN NOT NULL DEFAULT true,
    tags          TEXT[] NOT NULL DEFAULT '{}',
    created_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);
CREATE INDEX rules_tenant_idx ON rules(tenant_id);

-- ---------------------------------------------------------------------
-- Plugins (installed WASM modules per tenant)
-- ---------------------------------------------------------------------
CREATE TABLE plugins (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    version       TEXT NOT NULL,
    wasm_blob_uri TEXT NOT NULL,               -- s3://...
    config        JSONB NOT NULL DEFAULT '{}'::jsonb,
    capabilities  TEXT[] NOT NULL DEFAULT '{}',
    enabled       BOOLEAN NOT NULL DEFAULT true,
    sha256        TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name, version)
);
CREATE INDEX plugins_tenant_idx ON plugins(tenant_id);

-- ---------------------------------------------------------------------
-- ML profiles (per-site baselines)
-- ---------------------------------------------------------------------
CREATE TABLE ml_profiles (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    site_id       UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    model_kind    TEXT NOT NULL,               -- anomaly, payload, bot
    model_uri     TEXT NOT NULL,               -- s3://...
    version       TEXT NOT NULL,
    metrics       JSONB NOT NULL DEFAULT '{}'::jsonb,
    deployed_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ml_profiles_tenant_idx ON ml_profiles(tenant_id);

-- ---------------------------------------------------------------------
-- IP lists (allow / deny / watch)
-- ---------------------------------------------------------------------
CREATE TABLE ip_lists (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL CHECK (kind IN ('allow','deny','watch')),
    cidr          INET NOT NULL,
    note          TEXT,
    expires_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ip_lists_tenant_idx ON ip_lists(tenant_id);
CREATE INDEX ip_lists_cidr_idx   ON ip_lists USING gist (cidr inet_ops);

-- ---------------------------------------------------------------------
-- Alerts (triggered events requiring attention)
-- ---------------------------------------------------------------------
CREATE TABLE alerts (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    site_id       UUID REFERENCES sites(id) ON DELETE CASCADE,
    severity      TEXT NOT NULL,
    kind          TEXT NOT NULL,               -- anomaly, ddos, scan, exfil...
    summary       TEXT NOT NULL,
    details       JSONB NOT NULL DEFAULT '{}'::jsonb,
    state         TEXT NOT NULL DEFAULT 'open'
                  CHECK (state IN ('open','acked','resolved','closed')),
    assigned_to   UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at   TIMESTAMPTZ
);
CREATE INDEX alerts_tenant_idx ON alerts(tenant_id, created_at DESC);

-- ---------------------------------------------------------------------
-- Audit log (append-only, signed)
-- ---------------------------------------------------------------------
CREATE TABLE audit_logs (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_api_key UUID REFERENCES api_keys(id) ON DELETE SET NULL,
    action        TEXT NOT NULL,               -- e.g. site.create, rule.update
    target_kind   TEXT NOT NULL,
    target_id     UUID,
    diff          JSONB,
    ip            INET,
    user_agent    TEXT,
    hmac          BYTEA NOT NULL,              -- tamper-evident chain hash
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX audit_tenant_time_idx ON audit_logs(tenant_id, created_at DESC);

-- audit_logs is append-only: revoke UPDATE/DELETE to all roles by convention
-- enforced by application + RLS policies below.

-- =====================================================================
-- ENABLE Row-Level Security on every tenant-scoped table
-- =====================================================================
ALTER TABLE users        ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys     ENABLE ROW LEVEL SECURITY;
ALTER TABLE sites        ENABLE ROW LEVEL SECURITY;
ALTER TABLE rules        ENABLE ROW LEVEL SECURITY;
ALTER TABLE plugins      ENABLE ROW LEVEL SECURITY;
ALTER TABLE ml_profiles  ENABLE ROW LEVEL SECURITY;
ALTER TABLE ip_lists     ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts       ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs   ENABLE ROW LEVEL SECURITY;

-- Helper macro: every policy uses the same shape.
-- current_setting('app.current_tenant', true) returns NULL if unset (safe).

CREATE POLICY tenant_isolation ON users
    USING  (tenant_id::text = current_setting('app.current_tenant', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant', true));

CREATE POLICY tenant_isolation ON api_keys
    USING  (tenant_id::text = current_setting('app.current_tenant', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant', true));

CREATE POLICY tenant_isolation ON sites
    USING  (tenant_id::text = current_setting('app.current_tenant', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant', true));

CREATE POLICY tenant_isolation ON rules
    USING  (tenant_id::text = current_setting('app.current_tenant', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant', true));

CREATE POLICY tenant_isolation ON plugins
    USING  (tenant_id::text = current_setting('app.current_tenant', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant', true));

CREATE POLICY tenant_isolation ON ml_profiles
    USING  (tenant_id::text = current_setting('app.current_tenant', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant', true));

CREATE POLICY tenant_isolation ON ip_lists
    USING  (tenant_id::text = current_setting('app.current_tenant', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant', true));

CREATE POLICY tenant_isolation ON alerts
    USING  (tenant_id::text = current_setting('app.current_tenant', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant', true));

-- audit_logs: read-only via tenant; inserts unconstrained for triggers.
CREATE POLICY tenant_read ON audit_logs
    FOR SELECT
    USING (tenant_id::text = current_setting('app.current_tenant', true));
CREATE POLICY tenant_insert ON audit_logs
    FOR INSERT
    WITH CHECK (true);
-- UPDATE / DELETE: no policy => denied by default once RLS enabled.

-- ---------------------------------------------------------------------
-- updated_at trigger
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_tenants_updated  BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_sites_updated    BEFORE UPDATE ON sites
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_rules_updated    BEFORE UPDATE ON rules
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS audit_logs, alerts, ip_lists, ml_profiles,
                     plugins, rules, sites, api_keys, users, tenants CASCADE;
DROP FUNCTION IF EXISTS set_updated_at;
-- +goose StatementEnd
