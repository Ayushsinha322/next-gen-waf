-- =====================================================================
-- Sentinel WAF — TOTP replay protection
--
-- Track the last successfully consumed 30s TOTP step per user so a code that
-- was already accepted cannot be replayed within the ±1 skew window
-- (RFC 6238 §5.2). Login does an atomic compare-and-set against this column.
-- =====================================================================

-- +goose Up
-- +goose StatementBegin
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_last_step BIGINT NOT NULL DEFAULT 0;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE users DROP COLUMN IF EXISTS mfa_last_step;
-- +goose StatementEnd
