package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// ChannelRow is a configured notification sink (webhook/slack/syslog/cef).
type ChannelRow struct {
	ID          string          `json:"id"`
	TenantID    string          `json:"tenant_id"`
	Name        string          `json:"name"`
	Type        string          `json:"type"`
	Config      json.RawMessage `json:"config"`
	MinSeverity string          `json:"min_severity"`
	Enabled     bool            `json:"enabled"`
	LastStatus  *string         `json:"last_status,omitempty"`
	LastSentAt  *time.Time      `json:"last_sent_at,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// CreateChannelRequest is the payload for creating a notification channel.
type CreateChannelRequest struct {
	Name        string          `json:"name"`
	Type        string          `json:"type"`
	Config      json.RawMessage `json:"config"`
	MinSeverity string          `json:"min_severity"`
	Enabled     *bool           `json:"enabled"`
}

// UpdateChannelRequest holds the mutable fields of a channel.
type UpdateChannelRequest struct {
	Name        *string         `json:"name"`
	Config      json.RawMessage `json:"config"`
	MinSeverity *string         `json:"min_severity"`
	Enabled     *bool           `json:"enabled"`
}

// CreateAlertRequest is the payload for raising an alert.
type CreateAlertRequest struct {
	SiteID   *string         `json:"site_id"`
	Severity string          `json:"severity"`
	Kind     string          `json:"kind"`
	Summary  string          `json:"summary"`
	Details  json.RawMessage `json:"details"`
}

// EnsureNotificationSchema idempotently creates the notification_channels table
// (+ RLS) so the alerting feature works even when goose migrations haven't been
// run manually. Bypasses RLS via the raw pool (same pattern as SeedDev).
func EnsureNotificationSchema(ctx context.Context, pool Pool) error {
	pg, ok := pool.(*pgxPool)
	if !ok {
		return fmt.Errorf("notify schema: pool is not a *pgxPool")
	}
	const ddl = `
CREATE TABLE IF NOT EXISTS notification_channels (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    type          TEXT NOT NULL CHECK (type IN ('webhook','slack','syslog','cef')),
    config        JSONB NOT NULL DEFAULT '{}'::jsonb,
    min_severity  TEXT NOT NULL DEFAULT 'low'
                  CHECK (min_severity IN ('info','low','medium','high','critical')),
    enabled       BOOLEAN NOT NULL DEFAULT true,
    last_status   TEXT,
    last_sent_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);
CREATE INDEX IF NOT EXISTS notification_channels_tenant_idx ON notification_channels(tenant_id);
ALTER TABLE notification_channels ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'notification_channels' AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON notification_channels
            USING  (tenant_id::text = current_setting('app.current_tenant', true))
            WITH CHECK (tenant_id::text = current_setting('app.current_tenant', true));
    END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'trg_notification_channels_updated'
          AND tgrelid = 'notification_channels'::regclass
    ) THEN
        CREATE TRIGGER trg_notification_channels_updated BEFORE UPDATE ON notification_channels
            FOR EACH ROW EXECUTE FUNCTION set_updated_at();
    END IF;
END $$;`
	if _, err := pg.pool.Exec(ctx, ddl); err != nil {
		return fmt.Errorf("notify schema: %w", err)
	}
	return nil
}

func (s *Store) ListChannels(ctx context.Context, tenantID, userID string) ([]ChannelRow, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	// Explicit tenant_id predicate (defense-in-depth): without it, alert fan-out
	// would depend solely on RLS and could dispatch one tenant's alert — and
	// leak other tenants' channel secrets (webhook URLs, Slack tokens) — to
	// every tenant's channels if RLS is ever inactive for the connecting role.
	rows, err := tx.Query(ctx,
		`SELECT id, tenant_id, name, type, config, min_severity, enabled,
		        last_status, last_sent_at, created_at, updated_at
		   FROM notification_channels WHERE tenant_id = $1 ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("store: list channels: %w", err)
	}
	defer rows.Close()

	var out []ChannelRow
	for rows.Next() {
		var r ChannelRow
		if err := rows.Scan(&r.ID, &r.TenantID, &r.Name, &r.Type, &r.Config,
			&r.MinSeverity, &r.Enabled, &r.LastStatus, &r.LastSentAt,
			&r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}

func (s *Store) GetChannel(ctx context.Context, tenantID, userID, id string) (*ChannelRow, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var r ChannelRow
	err = tx.QueryRow(ctx,
		`SELECT id, tenant_id, name, type, config, min_severity, enabled,
		        last_status, last_sent_at, created_at, updated_at
		   FROM notification_channels WHERE id = $1 AND tenant_id = $2`,
		id, tenantID,
	).Scan(&r.ID, &r.TenantID, &r.Name, &r.Type, &r.Config, &r.MinSeverity,
		&r.Enabled, &r.LastStatus, &r.LastSentAt, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("store: get channel: %w", err)
	}
	return &r, tx.Commit(ctx)
}

func (s *Store) CreateChannel(ctx context.Context, tenantID, userID string, req CreateChannelRequest) (*ChannelRow, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	sev := req.MinSeverity
	if sev == "" {
		sev = "low"
	}
	cfg := req.Config
	if len(cfg) == 0 {
		cfg = json.RawMessage(`{}`)
	}

	var r ChannelRow
	err = tx.QueryRow(ctx,
		`INSERT INTO notification_channels (tenant_id, name, type, config, min_severity, enabled)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, tenant_id, name, type, config, min_severity, enabled,
		           last_status, last_sent_at, created_at, updated_at`,
		tenantID, req.Name, req.Type, cfg, sev, enabled,
	).Scan(&r.ID, &r.TenantID, &r.Name, &r.Type, &r.Config, &r.MinSeverity,
		&r.Enabled, &r.LastStatus, &r.LastSentAt, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("store: create channel: %w", err)
	}
	return &r, tx.Commit(ctx)
}

func (s *Store) UpdateChannel(ctx context.Context, tenantID, userID, id string, req UpdateChannelRequest) (*ChannelRow, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var cfg any
	if len(req.Config) > 0 {
		cfg = req.Config
	}
	var r ChannelRow
	err = tx.QueryRow(ctx,
		`UPDATE notification_channels
		    SET name         = COALESCE($3, name),
		        config       = COALESCE($4, config),
		        min_severity = COALESCE($5, min_severity),
		        enabled      = COALESCE($6, enabled),
		        updated_at   = now()
		  WHERE id = $1 AND tenant_id = $2
		  RETURNING id, tenant_id, name, type, config, min_severity, enabled,
		            last_status, last_sent_at, created_at, updated_at`,
		id, tenantID, req.Name, cfg, req.MinSeverity, req.Enabled,
	).Scan(&r.ID, &r.TenantID, &r.Name, &r.Type, &r.Config, &r.MinSeverity,
		&r.Enabled, &r.LastStatus, &r.LastSentAt, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("store: update channel: %w", err)
	}
	return &r, tx.Commit(ctx)
}

func (s *Store) DeleteChannel(ctx context.Context, tenantID, userID, id string) error {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := tx.Exec(ctx,
		`DELETE FROM notification_channels WHERE id = $1 AND tenant_id = $2`,
		id, tenantID); err != nil {
		return fmt.Errorf("store: delete channel: %w", err)
	}
	return tx.Commit(ctx)
}

// RecordChannelDelivery stamps the outcome of the last delivery attempt.
func (s *Store) RecordChannelDelivery(ctx context.Context, tenantID, userID, id, status string) error {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := tx.Exec(ctx,
		`UPDATE notification_channels SET last_status = $3, last_sent_at = now()
		  WHERE id = $1 AND tenant_id = $2`,
		id, tenantID, status); err != nil {
		return fmt.Errorf("store: record delivery: %w", err)
	}
	return tx.Commit(ctx)
}

// CreateAlert inserts a new alert and returns the stored row.
func (s *Store) CreateAlert(ctx context.Context, tenantID, userID string, a CreateAlertRequest) (*AlertRow, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	details := a.Details
	if len(details) == 0 {
		details = json.RawMessage(`{}`)
	}
	var r AlertRow
	err = tx.QueryRow(ctx,
		`INSERT INTO alerts (tenant_id, site_id, severity, kind, summary, details, state)
		 VALUES ($1, $2, $3, $4, $5, $6, 'open')
		 RETURNING id, tenant_id, site_id, severity, kind, summary, details, state, created_at, resolved_at`,
		tenantID, a.SiteID, a.Severity, a.Kind, a.Summary, details,
	).Scan(&r.ID, &r.TenantID, &r.SiteID, &r.Severity, &r.Kind, &r.Summary,
		&r.Details, &r.State, &r.CreatedAt, &r.ResolvedAt)
	if err != nil {
		return nil, fmt.Errorf("store: create alert: %w", err)
	}
	return &r, tx.Commit(ctx)
}
