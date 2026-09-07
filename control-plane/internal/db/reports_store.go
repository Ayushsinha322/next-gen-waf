package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ReportScheduleRow is one scheduled security report.
type ReportScheduleRow struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"tenant_id"`
	Name       string     `json:"name"`
	Site       string     `json:"site"` // site name; "" = every site
	Cadence    string     `json:"cadence"`
	DayOfWeek  int        `json:"day_of_week"`
	HourUTC    int        `json:"hour_utc"`
	Format     string     `json:"format"`
	ChannelID  *string    `json:"channel_id"`
	Recipients []string   `json:"recipients"`
	Enabled    bool       `json:"enabled"`
	LastRunAt  *time.Time `json:"last_run_at"`
	LastStatus *string    `json:"last_status"`
	CreatedBy  *string    `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// ReportScheduleInput is the writable part of a schedule.
type ReportScheduleInput struct {
	Name       string
	Site       string
	Cadence    string
	DayOfWeek  int
	HourUTC    int
	Format     string
	ChannelID  *string
	Recipients []string
	Enabled    bool
}

var (
	ErrReportScheduleNotFound = errors.New("report schedule not found")
	ErrReportChannelNotFound  = errors.New("notification channel not found")
)

// EnsureReportsSchema mirrors migration 0022 for deployments that never ran goose.
func EnsureReportsSchema(ctx context.Context, pool Pool) error {
	pg, ok := pool.(*pgxPool)
	if !ok {
		return fmt.Errorf("reports schema: pool is not a *pgxPool")
	}
	const ddl = `
CREATE TABLE IF NOT EXISTS report_schedules (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    site          TEXT NOT NULL DEFAULT '',
    cadence       TEXT NOT NULL DEFAULT 'weekly',
    day_of_week   SMALLINT NOT NULL DEFAULT 1,
    hour_utc      SMALLINT NOT NULL DEFAULT 6,
    format        TEXT NOT NULL DEFAULT 'html',
    channel_id    UUID REFERENCES notification_channels(id) ON DELETE SET NULL,
    recipients    TEXT[] NOT NULL DEFAULT '{}',
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    last_run_at   TIMESTAMPTZ,
    last_status   TEXT,
    created_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE report_schedules ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'report_schedules' AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON report_schedules
            USING  (tenant_id::text = current_setting('app.current_tenant', true))
            WITH CHECK (tenant_id::text = current_setting('app.current_tenant', true));
    END IF;
END $$;`
	if _, err := pg.pool.Exec(ctx, ddl); err != nil {
		return fmt.Errorf("reports schema: %w", err)
	}
	return nil
}

const reportScheduleCols = `id, tenant_id, name, site, cadence, day_of_week, hour_utc, format, channel_id,
	recipients, enabled, last_run_at, last_status, created_by, created_at, updated_at`

func scanReportSchedule(row interface{ Scan(dest ...any) error }) (*ReportScheduleRow, error) {
	var r ReportScheduleRow
	if err := row.Scan(&r.ID, &r.TenantID, &r.Name, &r.Site, &r.Cadence, &r.DayOfWeek, &r.HourUTC, &r.Format,
		&r.ChannelID, &r.Recipients, &r.Enabled, &r.LastRunAt, &r.LastStatus, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return nil, err
	}
	if r.Recipients == nil {
		r.Recipients = []string{}
	}
	return &r, nil
}

func (s *Store) ListReportSchedules(ctx context.Context, tenantID, userID string) ([]ReportScheduleRow, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT `+reportScheduleCols+` FROM report_schedules WHERE tenant_id = $1 ORDER BY created_at`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("store: list report schedules: %w", err)
	}
	defer rows.Close()
	out := make([]ReportScheduleRow, 0, 8)
	for rows.Next() {
		r, err := scanReportSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	tx.Commit(ctx)
	return out, nil
}

func (s *Store) GetReportSchedule(ctx context.Context, tenantID, userID, id string) (*ReportScheduleRow, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	r, err := scanReportSchedule(tx.QueryRow(ctx, `SELECT `+reportScheduleCols+` FROM report_schedules WHERE tenant_id = $1 AND id = $2`, tenantID, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrReportScheduleNotFound
		}
		return nil, fmt.Errorf("store: get report schedule: %w", err)
	}
	tx.Commit(ctx)
	return r, nil
}

func (s *Store) CreateReportSchedule(ctx context.Context, tenantID, userID string, in ReportScheduleInput) (*ReportScheduleRow, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var by *string
	if userID != "" {
		by = &userID
	}
	r, err := scanReportSchedule(tx.QueryRow(ctx, `
INSERT INTO report_schedules (tenant_id, name, site, cadence, day_of_week, hour_utc, format, channel_id, recipients, enabled, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
RETURNING `+reportScheduleCols,
		tenantID, in.Name, in.Site, in.Cadence, in.DayOfWeek, in.HourUTC, in.Format, in.ChannelID, in.Recipients, in.Enabled, by))
	if err != nil {
		return nil, fmt.Errorf("store: create report schedule: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

func (s *Store) UpdateReportSchedule(ctx context.Context, tenantID, userID, id string, in ReportScheduleInput) (*ReportScheduleRow, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	r, err := scanReportSchedule(tx.QueryRow(ctx, `
UPDATE report_schedules SET name=$3, site=$4, cadence=$5, day_of_week=$6, hour_utc=$7, format=$8, channel_id=$9,
       recipients=$10, enabled=$11, updated_at=now()
 WHERE tenant_id = $1 AND id = $2
RETURNING `+reportScheduleCols,
		tenantID, id, in.Name, in.Site, in.Cadence, in.DayOfWeek, in.HourUTC, in.Format, in.ChannelID, in.Recipients, in.Enabled))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrReportScheduleNotFound
		}
		return nil, fmt.Errorf("store: update report schedule: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

func (s *Store) DeleteReportSchedule(ctx context.Context, tenantID, userID, id string) error {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := tx.Exec(ctx, `DELETE FROM report_schedules WHERE tenant_id = $1 AND id = $2`, tenantID, id); err != nil {
		return fmt.Errorf("store: delete report schedule: %w", err)
	}
	return tx.Commit(ctx)
}

// ListEnabledReportSchedulesGlobal returns every enabled schedule across
// tenants, for the dispatcher (a leader-only background job, no user context).
func (s *Store) ListEnabledReportSchedulesGlobal(ctx context.Context) ([]ReportScheduleRow, error) {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return nil, fmt.Errorf("store: pool is not a *pgxPool")
	}
	rows, err := pg.pool.Query(ctx, `SELECT `+reportScheduleCols+` FROM report_schedules WHERE enabled = true ORDER BY tenant_id, created_at`)
	if err != nil {
		return nil, fmt.Errorf("store: list enabled report schedules: %w", err)
	}
	defer rows.Close()
	out := make([]ReportScheduleRow, 0, 8)
	for rows.Next() {
		r, err := scanReportSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// MarkReportRun records the outcome of a delivery (called by the dispatcher).
func (s *Store) MarkReportRun(ctx context.Context, id string, at time.Time, status string) error {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return fmt.Errorf("store: pool is not a *pgxPool")
	}
	if len(status) > 500 {
		status = status[:500]
	}
	_, err := pg.pool.Exec(ctx, `UPDATE report_schedules SET last_run_at = $2, last_status = $3 WHERE id = $1`, id, at, status)
	return err
}

// GetChannelGlobal reads one channel without a user context, for the dispatcher.
func (s *Store) GetChannelGlobal(ctx context.Context, tenantID, id string) (*ChannelRow, error) {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return nil, fmt.Errorf("store: pool is not a *pgxPool")
	}
	var r ChannelRow
	err := pg.pool.QueryRow(ctx, `
SELECT id, tenant_id, name, type, config, min_severity, enabled, last_status, last_sent_at, created_at, updated_at
  FROM notification_channels WHERE tenant_id = $1 AND id = $2`, tenantID, id).
		Scan(&r.ID, &r.TenantID, &r.Name, &r.Type, &r.Config, &r.MinSeverity, &r.Enabled, &r.LastStatus, &r.LastSentAt, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrReportChannelNotFound
		}
		return nil, err
	}
	return &r, nil
}
