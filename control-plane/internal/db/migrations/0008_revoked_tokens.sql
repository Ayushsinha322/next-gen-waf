-- =====================================================================
-- Sentinel WAF — JWT revocation denylist (logout / forced sign-out)
--
-- Node-global (a jti is not tenant-scoped), so no RLS. Shared across the HA
-- control-plane cluster, so a logout on one node revokes the token everywhere.
-- Rows are pruned once past the token's own expiry.
-- =====================================================================

-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti        TEXT PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS revoked_tokens_expires_idx ON revoked_tokens (expires_at);
GRANT SELECT, INSERT, DELETE ON revoked_tokens TO sentinel_app;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS revoked_tokens;
-- +goose StatementEnd
