-- =====================================================================
-- Audit rows never change after they are written.
--
-- audit_logs.actor_user_id and actor_api_key referenced users / api_keys with
-- ON DELETE SET NULL. Every row is HMAC-chained over its fields, actor
-- included, so deleting a user rewrote that user's past rows: their HMACs no
-- longer recomputed and /audit/verify reported them as ALTERED — a tamper alarm
-- raised by an ordinary leaver removal. It also erased who had done those
-- actions, which is what an audit trail is for. Found 2026-10-19 by deleting a
-- test user on a fresh 1.1.20 stack: three of that user's rows flagged.
--
-- The actor columns stay as plain UUIDs. A deleted user's id now remains on
-- their rows, and the audit list names them from the email recorded in the
-- user.delete entry. (API keys are revoked, not deleted, so their constraint
-- never fired; it goes for the same reason.)
--
-- Rows already nulled by a deletion before this migration cannot be repaired:
-- the original actor id is gone. They keep failing verification, and only a
-- row whose actor_user_id is NULL on an action that had an actor can be one.
-- =====================================================================

-- +goose Up
ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS audit_logs_actor_user_id_fkey;
ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS audit_logs_actor_api_key_fkey;

-- +goose Down
-- Deliberately not restored. Re-adding ON DELETE SET NULL would re-arm the
-- defect, and a plain foreign key would fail on the ids of users deleted since.
SELECT 1;
