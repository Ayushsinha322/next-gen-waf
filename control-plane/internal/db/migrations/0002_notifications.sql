-- =====================================================================
-- Sentinel WAF — Notification channels
-- SOC integration: deliver alerts to webhook / Slack / syslog / CEF sinks.
-- Apply with: goose up  (also created idempotently at startup by
-- EnsureNotificationSchema so the feature works without a manual migration).
-- =====================================================================

-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS notification_channels (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    type          TEXT NOT NULL
                  CHECK (type IN ('webhook','slack','syslog','cef')),
    config        JSONB NOT NULL DEFAULT '{}'::jsonb,   -- url/headers or syslog host/port/proto
    min_severity  TEXT NOT NULL DEFAULT 'low'
                  CHECK (min_severity IN ('info','low','medium','high','critical')),
    enabled       BOOLEAN NOT NULL DEFAULT true,
    last_status   TEXT,                                  -- "ok" or last error
    last_sent_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);
CREATE INDEX IF NOT EXISTS notification_channels_tenant_idx
    ON notification_channels(tenant_id);

ALTER TABLE notification_channels ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'notification_channels' AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON notification_channels
            USING  (tenant_id::text = current_setting('app.current_tenant', true))
            WITH CHECK (tenant_id::text = current_setting('app.current_tenant', true));
    END IF;
END $$;

CREATE TRIGGER trg_notification_channels_updated BEFORE UPDATE ON notification_channels
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS notification_channels CASCADE;
-- +goose StatementEnd
