package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// LogProfileRow is a saved, named log view scoped to one web application.
// See migration 0019 for why `site` is a name rather than a FK.
type LogProfileRow struct {
	ID               string    `json:"id"`
	TenantID         string    `json:"tenant_id"`
	Name             string    `json:"name"`
	Description      string    `json:"description"`
	Site             string    `json:"site"`
	Rule             string    `json:"rule"`
	Action           string    `json:"action"`
	IP               string    `json:"ip"`
	Country          string    `json:"country"`
	Protocol         string    `json:"protocol"`
	Severity         string    `json:"severity"`
	Q                string    `json:"q"`
	DefaultRangeSecs int       `json:"default_range_secs"`
	DefaultFormat    string    `json:"default_format"`
	CreatedBy        *string   `json:"created_by,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// LogProfileRequest is the create/update payload. Every filter is a pointer on
// update so that "clear this filter" (empty string) is distinguishable from
// "leave it alone" (absent) — with plain strings, a PUT that omitted a field
// would silently widen the customer's saved view.
type LogProfileRequest struct {
	Name             string  `json:"name"`
	Description      *string `json:"description"`
	Site             *string `json:"site"`
	Rule             *string `json:"rule"`
	Action           *string `json:"action"`
	IP               *string `json:"ip"`
	Country          *string `json:"country"`
	Protocol         *string `json:"protocol"`
	Severity         *string `json:"severity"`
	Q                *string `json:"q"`
	DefaultRangeSecs *int    `json:"default_range_secs"`
	DefaultFormat    *string `json:"default_format"`
}

const logProfileCols = `id, tenant_id, name, description, site, rule, action, ip, country,
	 protocol, severity, q, default_range_secs, default_format, created_by, created_at, updated_at`

func scanLogProfile(sc interface{ Scan(...any) error }) (*LogProfileRow, error) {
	var r LogProfileRow
	err := sc.Scan(&r.ID, &r.TenantID, &r.Name, &r.Description, &r.Site, &r.Rule,
		&r.Action, &r.IP, &r.Country, &r.Protocol, &r.Severity, &r.Q,
		&r.DefaultRangeSecs, &r.DefaultFormat, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// EnsureLogProfileSchema idempotently creates the log_profiles table (+ RLS),
// mirroring EnsureNotificationSchema, so the feature works on a deployment
// where goose migrations were not run by hand. Bypasses RLS via the raw pool.
func EnsureLogProfileSchema(ctx context.Context, pool Pool) error {
	pg, ok := pool.(*pgxPool)
	if !ok {
		return fmt.Errorf("log profile schema: pool is not a *pgxPool")
	}
	const ddl = `
CREATE TABLE IF NOT EXISTS log_profiles (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name               TEXT NOT NULL,
    description        TEXT NOT NULL DEFAULT '',
    site               TEXT NOT NULL DEFAULT '',
    rule               TEXT NOT NULL DEFAULT '',
    action             TEXT NOT NULL DEFAULT '',
    ip                 TEXT NOT NULL DEFAULT '',
    country            TEXT NOT NULL DEFAULT '',
    protocol           TEXT NOT NULL DEFAULT '',
    severity           TEXT NOT NULL DEFAULT '',
    q                  TEXT NOT NULL DEFAULT '',
    default_range_secs INTEGER NOT NULL DEFAULT 86400
                       CHECK (default_range_secs > 0 AND default_range_secs <= 31536000),
    default_format     TEXT NOT NULL DEFAULT 'csv'
                       CHECK (default_format IN ('csv','ndjson','json')),
    created_by         UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);
CREATE INDEX IF NOT EXISTS log_profiles_tenant_idx ON log_profiles(tenant_id);
ALTER TABLE log_profiles ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'log_profiles' AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON log_profiles
            USING  (tenant_id::text = current_setting('app.current_tenant', true))
            WITH CHECK (tenant_id::text = current_setting('app.current_tenant', true));
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'trg_log_profiles_updated'
          AND tgrelid = 'log_profiles'::regclass
    ) THEN
        CREATE TRIGGER trg_log_profiles_updated BEFORE UPDATE ON log_profiles
            FOR EACH ROW EXECUTE FUNCTION set_updated_at();
    END IF;
END $$;`
	if _, err := pg.pool.Exec(ctx, ddl); err != nil {
		return fmt.Errorf("log profile schema: %w", err)
	}
	return nil
}

// ListLogProfiles returns the tenant's saved views, alphabetically — the
// operator is looking one up by customer name under time pressure, so name
// order beats recency here.
func (s *Store) ListLogProfiles(ctx context.Context, tenantID, userID string) ([]LogProfileRow, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	// Explicit tenant_id predicate alongside RLS (defense in depth): these rows
	// name customer applications, so a cross-tenant read is a disclosure even
	// before any log data is fetched.
	rows, err := tx.Query(ctx,
		`SELECT `+logProfileCols+` FROM log_profiles WHERE tenant_id = $1 ORDER BY name`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("store: list log profiles: %w", err)
	}
	defer rows.Close()

	var out []LogProfileRow
	for rows.Next() {
		r, err := scanLogProfile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}

func (s *Store) GetLogProfile(ctx context.Context, tenantID, userID, id string) (*LogProfileRow, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	r, err := scanLogProfile(tx.QueryRow(ctx,
		`SELECT `+logProfileCols+` FROM log_profiles WHERE id = $1 AND tenant_id = $2`,
		id, tenantID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Distinguished from a database failure so the handler can answer 404
			// rather than reporting a missing profile as an outage — or, worse,
			// reporting an outage as a missing profile.
			return nil, ErrLogProfileNotFound
		}
		return nil, fmt.Errorf("store: get log profile: %w", err)
	}
	return r, tx.Commit(ctx)
}

// ErrLogProfileNotFound is returned when no profile with that id exists in the
// caller's tenant.
var ErrLogProfileNotFound = errors.New("log profile not found")

func (s *Store) CreateLogProfile(ctx context.Context, tenantID, userID string, req LogProfileRequest) (*LogProfileRow, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	// created_by is the caller, not client input — it is the accountability
	// record for who defined this customer's view.
	var createdBy *string
	if userID != "" {
		createdBy = &userID
	}

	r, err := scanLogProfile(tx.QueryRow(ctx,
		`INSERT INTO log_profiles
		   (tenant_id, name, description, site, rule, action, ip, country, protocol,
		    severity, q, default_range_secs, default_format, created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		 RETURNING `+logProfileCols,
		tenantID, req.Name, str(req.Description), str(req.Site), str(req.Rule),
		str(req.Action), str(req.IP), str(req.Country), str(req.Protocol),
		str(req.Severity), str(req.Q), intOr(req.DefaultRangeSecs, 86400),
		strOr(req.DefaultFormat, "csv"), createdBy))
	if err != nil {
		return nil, fmt.Errorf("store: create log profile: %w", err)
	}
	return r, tx.Commit(ctx)
}

// UpdateLogProfile applies only the fields present in req. COALESCE against the
// pointer means an omitted field keeps its stored value while an explicit ""
// clears the filter.
func (s *Store) UpdateLogProfile(ctx context.Context, tenantID, userID, id string, req LogProfileRequest) (*LogProfileRow, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var name *string
	if req.Name != "" {
		name = &req.Name
	}

	r, err := scanLogProfile(tx.QueryRow(ctx,
		`UPDATE log_profiles SET
		    name               = COALESCE($3,  name),
		    description        = COALESCE($4,  description),
		    site               = COALESCE($5,  site),
		    rule               = COALESCE($6,  rule),
		    action             = COALESCE($7,  action),
		    ip                 = COALESCE($8,  ip),
		    country            = COALESCE($9,  country),
		    protocol           = COALESCE($10, protocol),
		    severity           = COALESCE($11, severity),
		    q                  = COALESCE($12, q),
		    default_range_secs = COALESCE($13, default_range_secs),
		    default_format     = COALESCE($14, default_format),
		    updated_at         = now()
		  WHERE id = $1 AND tenant_id = $2
		  RETURNING `+logProfileCols,
		id, tenantID, name, req.Description, req.Site, req.Rule, req.Action,
		req.IP, req.Country, req.Protocol, req.Severity, req.Q,
		req.DefaultRangeSecs, req.DefaultFormat))
	if err != nil {
		return nil, fmt.Errorf("store: update log profile: %w", err)
	}
	return r, tx.Commit(ctx)
}

func (s *Store) DeleteLogProfile(ctx context.Context, tenantID, userID, id string) error {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := tx.Exec(ctx,
		`DELETE FROM log_profiles WHERE id = $1 AND tenant_id = $2`, id, tenantID); err != nil {
		return fmt.Errorf("store: delete log profile: %w", err)
	}
	return tx.Commit(ctx)
}

// str dereferences an optional string to its value or "".
func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func strOr(p *string, def string) string {
	if p == nil || *p == "" {
		return def
	}
	return *p
}

func intOr(p *int, def int) int {
	if p == nil || *p <= 0 {
		return def
	}
	return *p
}
