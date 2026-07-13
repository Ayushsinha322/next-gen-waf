-- =====================================================================
-- Sentinel WAF — Node health registry
--
-- Global, node-wide registry of WAF nodes (data-plane + control-plane) that
-- report their health via heartbeat. Nodes describe the cluster itself and are
-- NOT tenant-scoped: hence no tenant_id and no RLS policy (like
-- threat_intel_iocs, unlike notification_channels / sites). Reads/writes go
-- through the raw pool (see ListNodes / UpsertNode), mirroring ListActiveIOCs.
--
-- Apply with: goose up  (also created idempotently at startup by
-- EnsureNodesSchema so the feature works without a manual migration).
-- =====================================================================

-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS nodes (
    id         TEXT PRIMARY KEY,
    hostname   TEXT NOT NULL DEFAULT '',
    role       TEXT NOT NULL DEFAULT 'data-plane',
    version    TEXT NOT NULL DEFAULT '',
    status     TEXT NOT NULL DEFAULT 'healthy',
    last_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata   JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- Staleness sweeps and health reads order by recency.
CREATE INDEX IF NOT EXISTS nodes_last_seen_idx ON nodes (last_seen);

-- Grant to the non-superuser runtime role when it exists (created by 0004).
-- Guarded so the migration also succeeds on a fresh DB where 0004 has not yet
-- created the role. (0004's ALTER DEFAULT PRIVILEGES also covers new tables, but
-- we grant explicitly for clarity and to be order-independent.)
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON nodes TO sentinel_app;
    END IF;
END $$;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS nodes CASCADE;
-- +goose StatementEnd
