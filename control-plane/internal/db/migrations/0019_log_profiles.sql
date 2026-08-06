-- Log profiles: named, saved log views scoped to one web application.
--
-- The operator workflow this exists for: a customer calls and says "send me the
-- WAF logs for my app for 3 August". Without this, the operator rebuilds the
-- same filter set by hand every time, from memory, under time pressure — and
-- two operators handing over the same customer produce different result sets.
-- A profile makes that view a named, reviewable artifact.
--
-- Why the profile stores filters but NOT a time range as absolute timestamps:
-- the range is per-request, because it is the one thing that differs on every
-- call ("3 August" this time, "last week" the next). default_range_secs is only
-- the window the UI pre-selects when the profile is opened; the export endpoint
-- always takes explicit from/to.
--
-- site is TEXT, not a FK to sites(id), on purpose. It matches the `site` column
-- written into ClickHouse waf_events, which is the site NAME as the data plane
-- saw it. A site row can be renamed or deleted while its events remain in
-- ClickHouse for the retention period; a FK would either block that delete or
-- cascade away a profile that still points at retrievable history. An empty
-- site means "all applications in this tenant".

-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS log_profiles (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name               TEXT NOT NULL,
    description        TEXT NOT NULL DEFAULT '',
    site               TEXT NOT NULL DEFAULT '',
    -- Saved filter set. Mirrors clickhouse.SearchFilter minus tenant/time.
    rule               TEXT NOT NULL DEFAULT '',
    action             TEXT NOT NULL DEFAULT '',
    ip                 TEXT NOT NULL DEFAULT '',
    country            TEXT NOT NULL DEFAULT '',
    protocol           TEXT NOT NULL DEFAULT '',
    severity           TEXT NOT NULL DEFAULT '',
    q                  TEXT NOT NULL DEFAULT '',
    -- Window the UI pre-selects when the profile is opened (seconds).
    default_range_secs INTEGER NOT NULL DEFAULT 86400
                       CHECK (default_range_secs > 0 AND default_range_secs <= 31536000),
    -- Format the operator usually hands this customer.
    default_format     TEXT NOT NULL DEFAULT 'csv'
                       CHECK (default_format IN ('csv','ndjson','json')),
    created_by         UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS log_profiles_tenant_idx ON log_profiles(tenant_id);

ALTER TABLE log_profiles ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'log_profiles' AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON log_profiles
            USING  (tenant_id::text = current_setting('app.current_tenant', true))
            WITH CHECK (tenant_id::text = current_setting('app.current_tenant', true));
    END IF;
END $$;

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'trg_log_profiles_updated'
          AND tgrelid = 'log_profiles'::regclass
    ) THEN
        CREATE TRIGGER trg_log_profiles_updated BEFORE UPDATE ON log_profiles
            FOR EACH ROW EXECUTE FUNCTION set_updated_at();
    END IF;
END $$;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS log_profiles;

-- +goose StatementEnd
