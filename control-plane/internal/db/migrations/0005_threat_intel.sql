-- =====================================================================
-- Sentinel WAF — Threat Intelligence (CTI) IOC store
--
-- Global, node-wide table of Indicators of Compromise (IOCs) aggregated from
-- open threat feeds (Tor exit nodes, abuse.ch Feodo/URLhaus, STIX/TAXII).
-- IOCs are NOT tenant-scoped: they describe globally-malicious sources and are
-- enforced by the shared data plane for every tenant. Hence no tenant_id and no
-- RLS policy (unlike notification_channels / sites). Reads/writes go through the
-- raw pool (see ListActiveIOCs / UpsertIOCs), mirroring ListAllActiveSites.
--
-- Apply with: goose up  (also created idempotently at startup by
-- EnsureThreatIntelSchema so the feature works without a manual migration).
-- =====================================================================

-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS threat_intel_iocs (
    id          BIGSERIAL PRIMARY KEY,
    -- ioc_type drives how the data plane enforces the value:
    --   ip            single IPv4/IPv6 address
    --   cidr          IPv4/IPv6 network in CIDR form (radix-tree match)
    --   user_agent    exact bad User-Agent string
    --   domain        malicious hostname (Host header / SNI match)
    --   url_substring case-insensitive substring of the request URI
    ioc_type    TEXT NOT NULL
                CHECK (ioc_type IN ('ip','cidr','user_agent','domain','url_substring')),
    value       TEXT NOT NULL,
    source      TEXT NOT NULL,                       -- 'tor','feodo','urlhaus','stix','manual'
    category    TEXT NOT NULL DEFAULT 'malicious',   -- 'tor_exit','malware_c2','botnet','scanner',...
    confidence  INTEGER NOT NULL DEFAULT 75 CHECK (confidence BETWEEN 0 AND 100),
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ,                         -- NULL = never expires (e.g. manual entries)
    metadata    JSONB NOT NULL DEFAULT '{}'::jsonb,  -- free-form (malware family, feed notes)
    UNIQUE (ioc_type, value)
);

-- Lookup by type (data-plane read groups by type) and cheap expiry sweeps.
CREATE INDEX IF NOT EXISTS threat_intel_iocs_type_idx    ON threat_intel_iocs (ioc_type);
CREATE INDEX IF NOT EXISTS threat_intel_iocs_expires_idx ON threat_intel_iocs (expires_at);

-- Grant to the non-superuser runtime role when it exists (created by 0004).
-- Guarded so the migration also succeeds on a fresh DB where 0004 has not yet
-- created the role. (0004's ALTER DEFAULT PRIVILEGES also covers new tables, but
-- we grant explicitly for clarity and to be order-independent.)
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON threat_intel_iocs TO sentinel_app;
        GRANT USAGE, SELECT ON SEQUENCE threat_intel_iocs_id_seq TO sentinel_app;
    END IF;
END $$;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS threat_intel_iocs CASCADE;
-- +goose StatementEnd
