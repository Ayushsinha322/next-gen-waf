-- Tamper-EVIDENT audit log: hash chain + append-only enforcement at the DB.
--
-- audit_logs already carried a per-row HMAC over that row's own fields, which
-- detects MODIFICATION of a row. It cannot detect anything about the log as a
-- whole, because no row commits to any other row:
--
--   * DELETION is invisible. Remove the row recording "admin disabled the WAF on
--     site X" and every remaining HMAC still verifies perfectly.
--   * REORDERING is invisible. Nothing commits to an order.
--   * TRUNCATION is invisible. An empty audit log verifies as clean.
--
-- Deletion is precisely the operation an attacker who reached the database wants,
-- so per-row HMACs left the property that matters unprotected.
--
-- This adds a per-tenant hash chain: each row stores the previous row's HMAC, and
-- its own HMAC is computed over (seq, prev_hmac, ...fields). Removing or
-- reordering any row now breaks the successor's linkage, and seq exposes gaps.
--
-- prev_hmac semantics (see auditMAC / auditChainMAC in store.go):
--   NULL            -> row predates this migration; verified with the legacy
--                      unchained MAC and reported as unchained.
--   32 zero bytes   -> genesis row of a tenant's chain.
--   otherwise       -> the preceding row's hmac for that tenant.
--
-- Chains are per-tenant so that verification works under FORCE ROW LEVEL
-- SECURITY, where a tenant-scoped role cannot read other tenants' rows.

-- +goose Up
-- +goose StatementBegin
ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS seq       bigserial,
    ADD COLUMN IF NOT EXISTS prev_hmac bytea;
-- +goose StatementEnd

-- +goose StatementBegin
-- Ordering and gap detection per tenant chain. UNIQUE so seq cannot be
-- duplicated to disguise an insertion.
CREATE UNIQUE INDEX IF NOT EXISTS audit_tenant_seq_idx ON audit_logs(tenant_id, seq);
-- +goose StatementEnd

-- +goose StatementBegin
-- Append-only, enforced by the database rather than by convention.
--
-- The 0001 schema said audit_logs was append-only but only "by convention" —
-- nothing stopped the runtime role from issuing UPDATE or DELETE. The chain makes
-- tampering DETECTABLE; this makes the ordinary path outright IMPOSSIBLE for the
-- application role, so detection is a backstop rather than the only control.
REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM PUBLIC;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_app') THEN
        EXECUTE 'REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM sentinel_app';
        EXECUTE 'GRANT SELECT, INSERT ON audit_logs TO sentinel_app';
        -- The chain writer calls nextval() explicitly so it can include seq in
        -- the signed payload before the row exists.
        EXECUTE 'GRANT USAGE, SELECT ON SEQUENCE audit_logs_seq_seq TO sentinel_app';
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS audit_tenant_seq_idx;
ALTER TABLE audit_logs
    DROP COLUMN IF EXISTS prev_hmac,
    DROP COLUMN IF EXISTS seq;
-- +goose StatementEnd
