-- Scheduled security reports: a per-site (or all-sites) summary of the last
-- period — events by decision, top rules, top sources, top countries and the
-- learning-mode false-positive candidates — rendered as CSV or HTML and sent to
-- a notification channel or a mailbox on a daily/weekly schedule. The data was
-- always in ClickHouse; nothing produced a report from it, although the
-- customer deck claimed one (disproved 2026-08-13).
--
-- Mirrored by db.EnsureReportsSchema for deployments that never ran goose.

-- +goose Up
CREATE TABLE IF NOT EXISTS report_schedules (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    site          TEXT NOT NULL DEFAULT '',          -- site name; '' = every site
    cadence       TEXT NOT NULL DEFAULT 'weekly',    -- daily | weekly
    day_of_week   SMALLINT NOT NULL DEFAULT 1,       -- 0=Sunday … 6=Saturday (weekly)
    hour_utc      SMALLINT NOT NULL DEFAULT 6,
    format        TEXT NOT NULL DEFAULT 'html',      -- html | csv
    channel_id    UUID REFERENCES notification_channels(id) ON DELETE SET NULL,
    recipients    TEXT[] NOT NULL DEFAULT '{}',      -- e-mail addresses (needs SMTP)
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    last_run_at   TIMESTAMPTZ,
    last_status   TEXT,
    created_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE report_schedules ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON report_schedules
    USING  (tenant_id::text = current_setting('app.current_tenant', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant', true));

-- +goose Down
DROP TABLE IF EXISTS report_schedules;
