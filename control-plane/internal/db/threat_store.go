package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// IOC is a single Indicator of Compromise aggregated from a threat feed. It is
// global (not tenant-scoped): the shared data plane enforces IOCs for every
// tenant. See migration 0005 for the type semantics.
type IOC struct {
	Type       string     `json:"type"`  // ip|cidr|user_agent|domain|url_substring
	Value      string     `json:"value"` // the indicator (address, CIDR, UA string, host, substring)
	Source     string     `json:"source"`
	Category   string     `json:"category"`
	Confidence int        `json:"confidence"`
	LastSeen   time.Time  `json:"last_seen"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

// ThreatIntelStats summarizes the active IOC set. Version is the epoch of the
// most recent last_seen and is used by the data-plane poller to skip rebuilds
// when nothing changed.
type ThreatIntelStats struct {
	Count   int   `json:"count"`
	Version int64 `json:"version"`
}

// EnsureThreatIntelSchema idempotently creates the threat_intel_iocs table so
// the CTI pipeline works even when goose migrations have not been run manually.
// Uses the raw pool (bypasses RLS) — the table has no RLS (it is node-global).
func EnsureThreatIntelSchema(ctx context.Context, pool Pool) error {
	pg, ok := pool.(*pgxPool)
	if !ok {
		return fmt.Errorf("threat-intel schema: pool is not a *pgxPool")
	}
	const ddl = `
CREATE TABLE IF NOT EXISTS threat_intel_iocs (
    id          BIGSERIAL PRIMARY KEY,
    ioc_type    TEXT NOT NULL
                CHECK (ioc_type IN ('ip','cidr','user_agent','domain','url_substring')),
    value       TEXT NOT NULL,
    source      TEXT NOT NULL,
    category    TEXT NOT NULL DEFAULT 'malicious',
    confidence  INTEGER NOT NULL DEFAULT 75 CHECK (confidence BETWEEN 0 AND 100),
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ,
    metadata    JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (ioc_type, value)
);
CREATE INDEX IF NOT EXISTS threat_intel_iocs_type_idx    ON threat_intel_iocs (ioc_type);
CREATE INDEX IF NOT EXISTS threat_intel_iocs_expires_idx ON threat_intel_iocs (expires_at);`
	if _, err := pg.pool.Exec(ctx, ddl); err != nil {
		return fmt.Errorf("threat-intel schema: %w", err)
	}
	return nil
}

// upsertIOCChunk is how many rows we queue per SendBatch round-trip. Feeds run
// into the hundreds of thousands of rows; chunking bounds the per-batch memory
// and lets each round-trip pipeline over the wire.
const upsertIOCChunk = 1000

// UpsertIOCs inserts/refreshes a batch of IOCs. On conflict (ioc_type, value) it
// bumps last_seen, refreshes expiry, and keeps the higher confidence. Returns
// the number of rows submitted. Node-global (no tenant context) — the raw pool
// is used directly, like ListAllActiveSites.
func (s *Store) UpsertIOCs(ctx context.Context, iocs []IOC) (int, error) {
	if len(iocs) == 0 {
		return 0, nil
	}
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return 0, fmt.Errorf("store: pool is not a *pgxPool")
	}
	const q = `
INSERT INTO threat_intel_iocs (ioc_type, value, source, category, confidence, last_seen, expires_at)
VALUES ($1, $2, $3, $4, $5, now(), $6)
ON CONFLICT (ioc_type, value) DO UPDATE
   SET source     = EXCLUDED.source,
       category   = EXCLUDED.category,
       confidence = GREATEST(threat_intel_iocs.confidence, EXCLUDED.confidence),
       last_seen  = now(),
       expires_at = EXCLUDED.expires_at`

	submitted := 0
	for start := 0; start < len(iocs); start += upsertIOCChunk {
		end := start + upsertIOCChunk
		if end > len(iocs) {
			end = len(iocs)
		}
		batch := &pgx.Batch{}
		for _, ioc := range iocs[start:end] {
			conf := ioc.Confidence
			if conf <= 0 || conf > 100 {
				conf = 75
			}
			cat := ioc.Category
			if cat == "" {
				cat = "malicious"
			}
			batch.Queue(q, ioc.Type, ioc.Value, ioc.Source, cat, conf, ioc.ExpiresAt)
		}
		br := pg.pool.SendBatch(ctx, batch)
		var batchErr error
		for i := 0; i < end-start; i++ {
			if _, err := br.Exec(); err != nil && batchErr == nil {
				batchErr = err
			}
		}
		if cerr := br.Close(); cerr != nil && batchErr == nil {
			batchErr = cerr
		}
		if batchErr != nil {
			return submitted, fmt.Errorf("store: upsert IOCs: %w", batchErr)
		}
		submitted += end - start
	}
	return submitted, nil
}

// ListActiveIOCs returns every non-expired IOC, ordered for stable output.
func (s *Store) ListActiveIOCs(ctx context.Context) ([]IOC, error) {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return nil, fmt.Errorf("store: pool is not a *pgxPool")
	}
	rows, err := pg.pool.Query(ctx,
		`SELECT ioc_type, value, source, category, confidence, last_seen, expires_at
		   FROM threat_intel_iocs
		  WHERE expires_at IS NULL OR expires_at > now()
		  ORDER BY ioc_type, value`)
	if err != nil {
		return nil, fmt.Errorf("store: list active IOCs: %w", err)
	}
	defer rows.Close()

	var out []IOC
	for rows.Next() {
		var r IOC
		if err := rows.Scan(&r.Type, &r.Value, &r.Source, &r.Category,
			&r.Confidence, &r.LastSeen, &r.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// PurgeExpiredIOCs deletes IOCs whose TTL has elapsed. Returns rows removed.
func (s *Store) PurgeExpiredIOCs(ctx context.Context) (int64, error) {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return 0, fmt.Errorf("store: pool is not a *pgxPool")
	}
	ct, err := pg.pool.Exec(ctx,
		`DELETE FROM threat_intel_iocs
		  WHERE expires_at IS NOT NULL AND expires_at <= now()`)
	if err != nil {
		return 0, fmt.Errorf("store: purge expired IOCs: %w", err)
	}
	return ct.RowsAffected(), nil
}

// ThreatIntelStats returns the active IOC count and a version derived from the
// most recent last_seen (epoch seconds).
func (s *Store) ThreatIntelStats(ctx context.Context) (ThreatIntelStats, error) {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return ThreatIntelStats{}, fmt.Errorf("store: pool is not a *pgxPool")
	}
	var st ThreatIntelStats
	err := pg.pool.QueryRow(ctx,
		`SELECT count(*)::int,
		        COALESCE(EXTRACT(EPOCH FROM max(last_seen))::bigint, 0)
		   FROM threat_intel_iocs
		  WHERE expires_at IS NULL OR expires_at > now()`).
		Scan(&st.Count, &st.Version)
	if err != nil {
		return ThreatIntelStats{}, fmt.Errorf("store: threat-intel stats: %w", err)
	}
	return st, nil
}
