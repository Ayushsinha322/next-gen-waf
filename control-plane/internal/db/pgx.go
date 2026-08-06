package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// pgxPool wraps pgxpool.Pool and implements the Pool interface.
type pgxPool struct {
	pool *pgxpool.Pool
}

// pgxTenantTx wraps a pgx.Tx and implements TenantTx.
type pgxTenantTx struct {
	tx pgx.Tx
}

// Open dials Postgres using pgx/v5 and returns a Pool.
// The caller is responsible for calling Close() when done.
func Open(ctx context.Context, cfg Config) (Pool, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("db: empty connection URL")
	}

	pcfg, err := pgxpool.ParseConfig(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("db: parse config: %w", err)
	}

	if cfg.MaxConns > 0 {
		pcfg.MaxConns = cfg.MaxConns
	} else {
		pcfg.MaxConns = 25
	}
	if cfg.MinConns > 0 {
		pcfg.MinConns = cfg.MinConns
	} else {
		pcfg.MinConns = 2
	}

	pcfg.MaxConnLifetime = 30 * time.Minute
	pcfg.MaxConnIdleTime = 5 * time.Minute
	pcfg.HealthCheckPeriod = 30 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, pcfg)
	if err != nil {
		return nil, fmt.Errorf("db: connect pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: ping: %w", err)
	}

	return &pgxPool{pool: pool}, nil
}

// BeginTenant starts a transaction and sets the tenant/user session vars
// so that RLS policies automatically filter all rows to the given tenant.
func (p *pgxPool) BeginTenant(ctx context.Context, tenantID, userID string) (TenantTx, error) {
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.ReadCommitted,
		AccessMode: pgx.ReadWrite,
	})
	if err != nil {
		return nil, fmt.Errorf("db: begin tx: %w", err)
	}

	// RLS requires the tenant ID to be set as a session local variable.
	_, err = tx.Exec(ctx,
		`SELECT set_config('app.current_tenant', $1, true),
		        set_config('app.current_user_id', $2, true)`,
		tenantID, userID,
	)
	if err != nil {
		_ = tx.Rollback(ctx)
		return nil, fmt.Errorf("db: set tenant context: %w", err)
	}

	return &pgxTenantTx{tx: tx}, nil
}

func (p *pgxPool) Close() {
	p.pool.Close()
}

// Implement TenantTx.

func (t *pgxTenantTx) Exec(ctx context.Context, sql string, args ...any) error {
	_, err := t.tx.Exec(ctx, sql, args...)
	return err
}

func (t *pgxTenantTx) Query(ctx context.Context, sql string, args ...any) (Rows, error) {
	rows, err := t.tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return &pgxRows{rows: rows}, nil
}

func (t *pgxTenantTx) QueryRow(ctx context.Context, sql string, args ...any) Row {
	return t.tx.QueryRow(ctx, sql, args...)
}

func (t *pgxTenantTx) Commit(ctx context.Context) error {
	return t.tx.Commit(ctx)
}

func (t *pgxTenantTx) Rollback(ctx context.Context) error {
	return t.tx.Rollback(ctx)
}

// pgxRows wraps pgx.Rows to implement our Rows interface.
type pgxRows struct {
	rows pgx.Rows
}

func (r *pgxRows) Next() bool             { return r.rows.Next() }
func (r *pgxRows) Close()                 { r.rows.Close() }
func (r *pgxRows) Err() error             { return r.rows.Err() }
func (r *pgxRows) Scan(dest ...any) error { return r.rows.Scan(dest...) }
