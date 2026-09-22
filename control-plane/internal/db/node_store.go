package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Node is a single WAF node (data-plane or control-plane) that reports its
// health to the control plane via heartbeat. Like IOCs, nodes are node-global
// infrastructure (NOT tenant-scoped): they describe the cluster itself, so the
// table has no tenant_id and no RLS. Reads/writes go through the raw pool (see
// UpsertNode / ListNodes), mirroring the threat-intel IOC store.
type Node struct {
	ID       string          `json:"id"`
	Hostname string          `json:"hostname"`
	Role     string          `json:"role"`
	Version  string          `json:"version"`
	Status   string          `json:"status"`
	LastSeen time.Time       `json:"last_seen"`
	Metadata json.RawMessage `json:"metadata,omitempty"`
}

// EnsureNodesSchema idempotently creates the nodes table so node-health tracking
// works even when goose migrations have not been run manually. Uses the raw pool
// (bypasses RLS) — the table has no RLS (it is node-global).
func EnsureNodesSchema(ctx context.Context, pool Pool) error {
	pg, ok := pool.(*pgxPool)
	if !ok {
		return fmt.Errorf("nodes schema: pool is not a *pgxPool")
	}
	const ddl = `
CREATE TABLE IF NOT EXISTS nodes (
    id         TEXT PRIMARY KEY,
    hostname   TEXT NOT NULL DEFAULT '',
    role       TEXT NOT NULL DEFAULT 'data-plane',
    version    TEXT NOT NULL DEFAULT '',
    status     TEXT NOT NULL DEFAULT 'healthy',
    last_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata   JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS nodes_last_seen_idx ON nodes (last_seen);`
	if _, err := pg.pool.Exec(ctx, ddl); err != nil {
		return fmt.Errorf("nodes schema: %w", err)
	}
	return nil
}

// UpsertNode inserts or refreshes a node's heartbeat. On conflict (id) it bumps
// last_seen to now() and overwrites the reported fields. Node-global (no tenant
// context) — the raw pool is used directly, like UpsertIOCs.
func (s *Store) UpsertNode(ctx context.Context, n Node) error {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return fmt.Errorf("store: pool is not a *pgxPool")
	}
	_, err := pg.pool.Exec(ctx, `
INSERT INTO nodes (id, hostname, role, version, status, last_seen, metadata)
VALUES ($1, $2, $3, $4, $5, now(), COALESCE($6, '{}'::jsonb))
ON CONFLICT (id) DO UPDATE
   SET hostname  = EXCLUDED.hostname,
       role      = EXCLUDED.role,
       version   = EXCLUDED.version,
       status    = EXCLUDED.status,
       last_seen = now(),
       metadata  = EXCLUDED.metadata`,
		n.ID, n.Hostname, n.Role, n.Version, n.Status, nullableJSON(n.Metadata))
	if err != nil {
		return fmt.Errorf("store: upsert node: %w", err)
	}
	return nil
}

// ListNodes returns every known node, most-recently-seen first. Node-global
// (raw pool), like ListActiveIOCs.
func (s *Store) ListNodes(ctx context.Context) ([]Node, error) {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return nil, fmt.Errorf("store: pool is not a *pgxPool")
	}
	rows, err := pg.pool.Query(ctx,
		`SELECT id, hostname, role, version, status, last_seen, metadata
		   FROM nodes
		  ORDER BY last_seen DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: list nodes: %w", err)
	}
	defer rows.Close()

	var out []Node
	for rows.Next() {
		var n Node
		if err := rows.Scan(&n.ID, &n.Hostname, &n.Role, &n.Version,
			&n.Status, &n.LastSeen, &n.Metadata); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// UpdateNodeStatus flips a node's stored status (e.g. the health monitor marking
// a stale node "down"). Node-global (raw pool).
// PruneNodes deletes nodes not heard from for longer than olderThan and returns
// how many went. Node-global (raw pool), like ListNodes.
//
// A node identifies itself by hostname, and an unpinned container's hostname is
// its container id — so every recreate used to leave the previous identity
// behind as a permanent "down" row. compose.prod.yml now pins the hostname, and
// this is the cleanup for rows that predate that, and for any node genuinely
// decommissioned without a clean shutdown. Heartbeats are every 10 s; the caller
// passes a window measured in hours.
func (s *Store) PruneNodes(ctx context.Context, olderThan time.Duration) (int64, error) {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return 0, fmt.Errorf("store: pool is not a *pgxPool")
	}
	if olderThan <= 0 {
		return 0, fmt.Errorf("store: prune window must be positive, got %s", olderThan)
	}
	tag, err := pg.pool.Exec(ctx,
		`DELETE FROM nodes WHERE last_seen < now() - make_interval(secs => $1)`,
		olderThan.Seconds())
	if err != nil {
		return 0, fmt.Errorf("store: prune nodes: %w", err)
	}
	return tag.RowsAffected(), nil
}

func (s *Store) UpdateNodeStatus(ctx context.Context, id, status string) error {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return fmt.Errorf("store: pool is not a *pgxPool")
	}
	if _, err := pg.pool.Exec(ctx,
		`UPDATE nodes SET status = $2 WHERE id = $1`, id, status); err != nil {
		return fmt.Errorf("store: update node status: %w", err)
	}
	return nil
}
