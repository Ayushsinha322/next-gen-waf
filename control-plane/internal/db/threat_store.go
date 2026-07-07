package db

import (
	"context"
	"fmt"
	"strings"
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

// ---------------------------------------------------------------------------
// Dashboard-facing reads/writes (JWT+RBAC surface; see threatintel_dashboard_handlers.go)
// ---------------------------------------------------------------------------

// DefaultBlockThreshold splits high-confidence "block" IOCs from lower-confidence
// "watch" IOCs, mirroring the data-plane tiering (ThreatFeed block/watch) and the
// SENTINEL_TI_BLOCK_CONFIDENCE default.
const DefaultBlockThreshold = 80

// ValidIOCType whitelists the ioc_type enum from migration 0005. Filters and
// mutations reject anything else before it reaches SQL (defense-in-depth on top
// of the table CHECK constraint).
func ValidIOCType(t string) bool {
	switch t {
	case "ip", "cidr", "user_agent", "domain", "url_substring":
		return true
	}
	return false
}

func normalizeThreshold(threshold int) int {
	if threshold <= 0 || threshold > 100 {
		return DefaultBlockThreshold
	}
	return threshold
}

// ThreatIntelSummary is the dashboard header: active total, tier split at a
// confidence threshold, per-type / per-source / per-category counts, and
// freshness bounds.
type ThreatIntelSummary struct {
	TotalActive int            `json:"total_active"`
	BlockTier   int            `json:"block_tier"` // confidence >= threshold
	WatchTier   int            `json:"watch_tier"` // confidence <  threshold
	Threshold   int            `json:"threshold"`
	ByType      map[string]int `json:"by_type"`
	BySource    map[string]int `json:"by_source"`
	ByCategory  map[string]int `json:"by_category"`
	NewestSeen  *time.Time     `json:"newest_seen,omitempty"` // nil when table empty
	OldestSeen  *time.Time     `json:"oldest_seen,omitempty"`
}

// ThreatIntelSummary returns aggregate stats over the ACTIVE IOC set. threshold
// is the block/watch cutoff (0 or out of range -> DefaultBlockThreshold).
// Node-global (raw pool), like ListActiveIOCs.
func (s *Store) ThreatIntelSummary(ctx context.Context, threshold int) (ThreatIntelSummary, error) {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return ThreatIntelSummary{}, fmt.Errorf("store: pool is not a *pgxPool")
	}
	threshold = normalizeThreshold(threshold)
	out := ThreatIntelSummary{
		Threshold:  threshold,
		ByType:     map[string]int{},
		BySource:   map[string]int{},
		ByCategory: map[string]int{},
	}

	err := pg.pool.QueryRow(ctx, `
SELECT count(*)::int                                  AS total,
       count(*) FILTER (WHERE confidence >= $1)::int  AS block_tier,
       count(*) FILTER (WHERE confidence <  $1)::int  AS watch_tier,
       max(last_seen)                                 AS newest,
       min(last_seen)                                 AS oldest
  FROM threat_intel_iocs
 WHERE expires_at IS NULL OR expires_at > now()`, threshold).
		Scan(&out.TotalActive, &out.BlockTier, &out.WatchTier, &out.NewestSeen, &out.OldestSeen)
	if err != nil {
		return ThreatIntelSummary{}, fmt.Errorf("store: TI summary scalars: %w", err)
	}

	groups := []struct {
		col string
		dst map[string]int
	}{
		{"ioc_type", out.ByType},
		{"source", out.BySource},
		{"category", out.ByCategory},
	}
	for _, g := range groups {
		// g.col is a fixed literal (never user input), so interpolation is safe.
		q := fmt.Sprintf(`SELECT %s, count(*)::int FROM threat_intel_iocs
 WHERE expires_at IS NULL OR expires_at > now() GROUP BY %s ORDER BY count(*) DESC`, g.col, g.col)
		if err := scanCounts(ctx, pg, q, g.dst); err != nil {
			return ThreatIntelSummary{}, fmt.Errorf("store: TI summary %s: %w", g.col, err)
		}
	}
	return out, nil
}

func scanCounts(ctx context.Context, pg *pgxPool, q string, dst map[string]int) error {
	rows, err := pg.pool.Query(ctx, q)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return err
		}
		dst[k] = n
	}
	return rows.Err()
}

// IOCListFilter is the (untrusted) query for the IOC browse table. Zero-value
// fields mean "no filter".
type IOCListFilter struct {
	Type      string // "" or one of the ioc_type enum (validated)
	Source    string // "" = any; exact match
	Tier      string // "" | "block" | "watch"
	Search    string // case-insensitive literal substring on value
	Threshold int    // block/watch cutoff (default 80)
	Limit     int    // default 50, capped 500
	Offset    int
}

// IOCListItem is one row of the browse table (includes the DB id for deletes and
// a derived tier label).
type IOCListItem struct {
	ID         int64      `json:"id"`
	Type       string     `json:"type"`
	Value      string     `json:"value"`
	Source     string     `json:"source"`
	Category   string     `json:"category"`
	Confidence int        `json:"confidence"`
	Tier       string     `json:"tier"` // derived: "block" | "watch"
	FirstSeen  time.Time  `json:"first_seen"`
	LastSeen   time.Time  `json:"last_seen"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

// IOCPage is a filtered, paginated slice plus the total match count.
type IOCPage struct {
	Items  []IOCListItem `json:"items"`
	Total  int           `json:"total"`
	Limit  int           `json:"limit"`
	Offset int           `json:"offset"`
}

// ListIOCs returns a filtered, paginated slice of active IOCs plus the total
// match count. All user values are bound as $N parameters; ioc_type and tier are
// whitelisted enums. Node-global (raw pool).
func (s *Store) ListIOCs(ctx context.Context, f IOCListFilter) (IOCPage, error) {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return IOCPage{}, fmt.Errorf("store: pool is not a *pgxPool")
	}
	threshold := normalizeThreshold(f.Threshold)
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	// Filters are bound as $1..$N in append order. The confidence threshold is
	// bound ONLY where it is referenced — in a tier filter's WHERE and in the
	// page query's tier-label CASE — never supplied unreferenced, since Postgres
	// rejects a bound-but-unused parameter (which would break unfiltered/type/
	// source/search-only lists whose count query omits the threshold).
	args := []any{}
	where := []string{"(expires_at IS NULL OR expires_at > now())"}

	if f.Type != "" {
		if !ValidIOCType(f.Type) {
			return IOCPage{}, fmt.Errorf("store: invalid ioc_type %q", f.Type)
		}
		args = append(args, f.Type)
		where = append(where, fmt.Sprintf("ioc_type = $%d", len(args)))
	}
	if f.Source != "" {
		args = append(args, f.Source)
		where = append(where, fmt.Sprintf("source = $%d", len(args)))
	}
	switch f.Tier {
	case "block":
		args = append(args, threshold)
		where = append(where, fmt.Sprintf("confidence >= $%d", len(args)))
	case "watch":
		args = append(args, threshold)
		where = append(where, fmt.Sprintf("confidence <  $%d", len(args)))
	case "":
		// no tier filter
	default:
		return IOCPage{}, fmt.Errorf("store: invalid tier %q", f.Tier)
	}
	if f.Search != "" {
		args = append(args, f.Search)
		// strpos on lowercased value = case-insensitive LITERAL substring: '%'/'_'
		// are not wildcards, and it is a bound param, so no LIKE-pattern or
		// injection surface.
		where = append(where, fmt.Sprintf("strpos(lower(value), lower($%d)) > 0", len(args)))
	}
	whereSQL := strings.Join(where, " AND ")

	var total int
	if err := pg.pool.QueryRow(ctx,
		`SELECT count(*)::int FROM threat_intel_iocs WHERE `+whereSQL, args...).
		Scan(&total); err != nil {
		return IOCPage{}, fmt.Errorf("store: count IOCs: %w", err)
	}

	// Page query appends threshold (for the tier label), limit, offset as the
	// final params. Copy args so the count query above stays unaffected.
	pageArgs := append(append([]any{}, args...), threshold, limit, offset)
	thIdx, limIdx, offIdx := len(args)+1, len(args)+2, len(args)+3
	q := fmt.Sprintf(`
SELECT id, ioc_type, value, source, category, confidence,
       CASE WHEN confidence >= $%d THEN 'block' ELSE 'watch' END AS tier,
       first_seen, last_seen, expires_at
  FROM threat_intel_iocs
 WHERE %s
 ORDER BY last_seen DESC, ioc_type, value
 LIMIT $%d OFFSET $%d`, thIdx, whereSQL, limIdx, offIdx)

	rows, err := pg.pool.Query(ctx, q, pageArgs...)
	if err != nil {
		return IOCPage{}, fmt.Errorf("store: list IOCs: %w", err)
	}
	defer rows.Close()

	page := IOCPage{Items: []IOCListItem{}, Total: total, Limit: limit, Offset: offset}
	for rows.Next() {
		var it IOCListItem
		if err := rows.Scan(&it.ID, &it.Type, &it.Value, &it.Source, &it.Category,
			&it.Confidence, &it.Tier, &it.FirstSeen, &it.LastSeen, &it.ExpiresAt); err != nil {
			return IOCPage{}, err
		}
		page.Items = append(page.Items, it)
	}
	return page, rows.Err()
}

// CreateIOC inserts/updates one operator-entered IOC and returns the stored row.
// For manual entries the supplied confidence is authoritative (overwrites, not
// GREATEST as the feed upsert does).
func (s *Store) CreateIOC(ctx context.Context, ioc IOC) (IOCListItem, error) {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return IOCListItem{}, fmt.Errorf("store: pool is not a *pgxPool")
	}
	if !ValidIOCType(ioc.Type) {
		return IOCListItem{}, fmt.Errorf("store: invalid ioc_type %q", ioc.Type)
	}
	ioc.Value = strings.TrimSpace(ioc.Value)
	if ioc.Value == "" {
		return IOCListItem{}, fmt.Errorf("store: IOC value required")
	}
	if ioc.Source == "" {
		ioc.Source = "manual"
	}
	if ioc.Category == "" {
		ioc.Category = "manual"
	}
	conf := ioc.Confidence
	if conf <= 0 || conf > 100 {
		conf = 75
	}
	threshold := DefaultBlockThreshold
	var out IOCListItem
	err := pg.pool.QueryRow(ctx, `
INSERT INTO threat_intel_iocs (ioc_type, value, source, category, confidence, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (ioc_type, value) DO UPDATE
   SET source     = EXCLUDED.source,
       category   = EXCLUDED.category,
       confidence = EXCLUDED.confidence,
       last_seen  = now(),
       expires_at = EXCLUDED.expires_at
RETURNING id, ioc_type, value, source, category, confidence,
          CASE WHEN confidence >= $7 THEN 'block' ELSE 'watch' END,
          first_seen, last_seen, expires_at`,
		ioc.Type, ioc.Value, ioc.Source, ioc.Category, conf, ioc.ExpiresAt, threshold).
		Scan(&out.ID, &out.Type, &out.Value, &out.Source, &out.Category, &out.Confidence,
			&out.Tier, &out.FirstSeen, &out.LastSeen, &out.ExpiresAt)
	if err != nil {
		return IOCListItem{}, fmt.Errorf("store: create IOC: %w", err)
	}
	return out, nil
}

// DeleteIOCByID removes one IOC by its primary key. Returns false when nothing
// matched (so the handler can answer 404).
func (s *Store) DeleteIOCByID(ctx context.Context, id int64) (bool, error) {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return false, fmt.Errorf("store: pool is not a *pgxPool")
	}
	ct, err := pg.pool.Exec(ctx, `DELETE FROM threat_intel_iocs WHERE id = $1`, id)
	if err != nil {
		return false, fmt.Errorf("store: delete IOC: %w", err)
	}
	return ct.RowsAffected() > 0, nil
}
