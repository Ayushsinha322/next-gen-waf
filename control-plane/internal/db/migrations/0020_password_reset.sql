-- Password reset + credential lifecycle.
--
-- Two things land here, and they are related: the product had NO way to change a
-- password (the seeder printed "log in and change it immediately" for a
-- capability that did not exist, and the login page linked "Forgot password?" at
-- "#"), and it had no way to invalidate the sessions such a change must kill.
--
-- password_reset_tokens stores ONLY sha256(raw token). The raw token exists in
-- exactly two places and never at rest: the response path that mails it, and the
-- link in the user's inbox. A database dump therefore cannot be replayed into an
-- account takeover, which is the whole point of hashing here — the same reason
-- api_keys stores key_hash rather than the key.
--
-- token_hash is the PRIMARY KEY rather than a surrogate id: lookup is always
-- "given this hash, find the row", it is uniformly distributed, and making it the
-- key makes a duplicate token a database error instead of an ambiguity.
--
-- used_at is a timestamp rather than a boolean so the audit trail keeps WHEN a
-- token was burned; single-use is enforced by a conditional UPDATE (see
-- ConsumeResetToken), not by a read-then-write, so two concurrent redemptions
-- cannot both succeed.
--
-- users.sessions_valid_from is the session cut-off. Access tokens are stateless
-- JWTs, so "log everyone out" cannot be done by deleting rows; instead every
-- token issued before this instant is treated as invalid. NULL means "never
-- reset", which is the common case and costs nothing to check.

-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    token_hash   bytea       PRIMARY KEY,
    tenant_id    uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id      uuid        NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
    expires_at   timestamptz NOT NULL,
    used_at      timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    requested_ip inet,
    -- "self" (forgot-password) or "admin" (operator-initiated). Recorded so the
    -- audit trail can distinguish a user recovering their own account from an
    -- administrator forcing a reset on someone else's.
    initiated_by text        NOT NULL DEFAULT 'self'
);

-- Reclaim expired/used tokens without scanning the table.
CREATE INDEX IF NOT EXISTS password_reset_tokens_expires_idx
    ON password_reset_tokens (expires_at);

-- "Invalidate every outstanding token for this user" runs on every successful
-- reset and every password change, so it must not scan.
CREATE INDEX IF NOT EXISTS password_reset_tokens_user_idx
    ON password_reset_tokens (user_id);

ALTER TABLE password_reset_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE password_reset_tokens FORCE ROW LEVEL SECURITY;

-- The forgot-password path is PRE-AUTH: there is no session, so there is no
-- app.current_tenant to match against. Redemption is therefore driven through
-- the SECURITY DEFINER functions below rather than by direct table access, and
-- this policy exists so that any *authenticated* path (admin-initiated reset,
-- cleanup) stays tenant-scoped like every other table.
DROP POLICY IF EXISTS tenant_isolation ON password_reset_tokens;
CREATE POLICY tenant_isolation ON password_reset_tokens
    USING      (tenant_id::text = current_setting('app.current_tenant', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant', true));

ALTER TABLE users ADD COLUMN IF NOT EXISTS sessions_valid_from timestamptz;
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at timestamptz;

-- +goose StatementEnd

-- Pre-auth carve-outs, mirroring sentinel_auth_lookup from migration 0004.
--
-- SECURITY DEFINER because both run before the caller has a tenant: a password
-- reset is requested by someone who cannot log in. Each is deliberately narrow —
-- one resolves an email to an account, the other burns a token hash — and
-- neither returns a password hash or accepts a tenant argument, so widening the
-- blast radius would take a schema change, not a clever call.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION sentinel_reset_lookup(p_email text)
RETURNS TABLE (id uuid, tenant_id uuid, email text, name text)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT u.id, u.tenant_id, u.email, u.name
      FROM users u
     WHERE lower(u.email) = lower(p_email)
       AND u.status = 'active';
$$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Atomically burn a reset token and return the account it belonged to.
--
-- The single-use guarantee lives in this UPDATE's WHERE clause: used_at IS NULL
-- AND expires_at > now(). Two simultaneous redemptions of the same link both
-- reach here, exactly one matches a row, and the loser gets zero rows — no
-- read-modify-write window, no application-level lock.
CREATE OR REPLACE FUNCTION sentinel_reset_consume(p_token_hash bytea)
RETURNS TABLE (user_id uuid, tenant_id uuid, initiated_by text)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
    UPDATE password_reset_tokens
       SET used_at = now()
     WHERE token_hash = p_token_hash
       AND used_at IS NULL
       AND expires_at > now()
    RETURNING password_reset_tokens.user_id,
              password_reset_tokens.tenant_id,
              password_reset_tokens.initiated_by;
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP FUNCTION IF EXISTS sentinel_reset_consume(bytea);
DROP FUNCTION IF EXISTS sentinel_reset_lookup(text);
DROP TABLE IF EXISTS password_reset_tokens;
ALTER TABLE users DROP COLUMN IF EXISTS sessions_valid_from;
ALTER TABLE users DROP COLUMN IF EXISTS password_changed_at;
-- +goose StatementEnd
