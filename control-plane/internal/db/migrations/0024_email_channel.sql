-- =====================================================================
-- Email as a notification channel type.
--
-- The four sinks (webhook, Slack, syslog, CEF) all need something the customer
-- runs; most installations had none wired up, so no alert ever reached a person
-- (2026-10-07 review #24). Email goes through the SMTP relay already configured
-- for password recovery.
-- =====================================================================

-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'notification_channels_type_check'
          AND pg_get_constraintdef(oid) LIKE '%email%'
    ) THEN
        ALTER TABLE notification_channels DROP CONSTRAINT IF EXISTS notification_channels_type_check;
        ALTER TABLE notification_channels ADD CONSTRAINT notification_channels_type_check
            CHECK (type IN ('webhook','slack','syslog','cef','email'));
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM notification_channels WHERE type = 'email';
ALTER TABLE notification_channels DROP CONSTRAINT IF EXISTS notification_channels_type_check;
ALTER TABLE notification_channels ADD CONSTRAINT notification_channels_type_check
    CHECK (type IN ('webhook','slack','syslog','cef'));
-- +goose StatementEnd
