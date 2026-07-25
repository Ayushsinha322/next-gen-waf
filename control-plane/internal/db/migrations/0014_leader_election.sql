-- Leader identity, for a control plane whose leadership comes from a Postgres
-- session-scoped advisory lock instead of hand-rolled Raft.
--
-- Why the Raft implementation went away:
--
--   * Its state machine did nothing. The Apply hook was an explicit no-op log
--     line, because by apply time the leader had ALREADY written through to
--     Postgres and followers re-read from Postgres on demand. The replicated log
--     therefore carried no state anyone consumed — Postgres was, and remains, the
--     only source of truth.
--   * The log grew forever. There was no snapshotting or compaction anywhere in
--     the 975-line implementation, so a long-lived cluster accumulated entries
--     until the disk filled.
--   * It was only ever exercised single-process, yet it carried the full risk
--     surface of a consensus protocol: terms, elections, and an authenticated RPC
--     layer with its own shared secret.
--   * Its quorum gate was actively harmful. Losing 2 of 3 control-plane nodes
--     refused all writes even while Postgres — itself HA, with its own synchronous
--     quorum under CloudNativePG — was perfectly healthy and writable.
--
-- What replaces it: contenders race for one session-scoped advisory lock on the
-- Postgres primary. The winner is leader for as long as its connection lives; if
-- it dies or is partitioned, the server drops the lock with no lease to expire and
-- no clock to trust. Availability now depends on Postgres, which is the same thing
-- a write already depended on, rather than on a second independent quorum.
--
-- This table exists only so FOLLOWERS can learn where to forward writes. It is
-- advisory metadata, never the authority on who holds leadership — that is the
-- lock itself. A stale row cannot cause split-brain; at worst a follower forwards
-- to a node that will answer 503 and be retried.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS cluster_leader (
    -- Single-row table, same pattern as config_generation.
    id           boolean     PRIMARY KEY DEFAULT true CHECK (id),
    node_id      text        NOT NULL,
    -- Address peers should forward writes to (host:port of the REST API).
    advertise    text        NOT NULL,
    acquired_at  timestamptz NOT NULL DEFAULT now(),
    heartbeat_at timestamptz NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose StatementBegin
-- Control-plane membership, so the cluster view shows real topology.
--
-- EVERY node heartbeats its own row here, leader and follower alike. This is
-- strictly better observability than Raft provided: Raft tracked peer liveness
-- only leader->follower, so a follower could not see its peers at all and the
-- cluster page had to guess ("a leader exists, so assume the others are up").
-- Now any node can report accurate per-node liveness from shared state.
CREATE TABLE IF NOT EXISTS cluster_members (
    node_id    text        PRIMARY KEY,
    advertise  text        NOT NULL,
    is_leader  boolean     NOT NULL DEFAULT false,
    started_at timestamptz NOT NULL DEFAULT now(),
    last_seen  timestamptz NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose StatementBegin
-- Readable and writable by the runtime role: every node reads these to find the
-- leader and render topology, and writes its own heartbeat. Not tenant-scoped, so
-- deliberately outside RLS.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON cluster_leader TO sentinel_app';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON cluster_members TO sentinel_app';
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS cluster_members;
DROP TABLE IF EXISTS cluster_leader;
-- +goose StatementEnd
