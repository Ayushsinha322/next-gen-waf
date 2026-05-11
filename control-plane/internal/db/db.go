// Package db provides the PostgreSQL data-access layer for the Sentinel
// control plane, with built-in multi-tenant isolation via PostgreSQL
// Row-Level Security (RLS).
//
// Usage:
//
//	pool, _ := db.Open(ctx, cfg)
//	defer pool.Close()
//
//	// Every request:
//	tx, _ := pool.BeginTenant(ctx, tenantID, userID)
//	defer tx.Rollback(ctx)
//	// ... run queries; RLS auto-filters by tenant_id ...
//	tx.Commit(ctx)
package db

import (
	"context"
	"errors"
	"fmt"
)

// Config holds DB connection settings.
type Config struct {
	URL             string // postgres://user:pass@host:5432/sentinel?sslmode=verify-full
	MaxConns        int32
	MinConns        int32
	StatementCache  bool
	IsolationLevel  string // "shared" (RLS) | "schema" | "dedicated"
}

// Pool is the abstract connection pool interface so we can swap pgx for sqlite
// in single-node mode.
type Pool interface {
	BeginTenant(ctx context.Context, tenantID, userID string) (TenantTx, error)
	Close()
}

// TenantTx is a transaction with tenant context already set via
// `SET LOCAL app.current_tenant = ?`.  All queries through it are
// auto-filtered by RLS.
type TenantTx interface {
	Exec(ctx context.Context, sql string, args ...any) error
	Query(ctx context.Context, sql string, args ...any) (Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) Row
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

type Rows interface {
	Next() bool
	Scan(dest ...any) error
	Close()
	Err() error
}

type Row interface {
	Scan(dest ...any) error
}

// Open dials Postgres (or SQLite in dev mode) and returns a Pool.
// Implementation lives in pgx.go / sqlite.go.
func Open(ctx context.Context, cfg Config) (Pool, error) {
	if cfg.URL == "" {
		return nil, errors.New("db: empty connection URL")
	}
	// TODO: detect scheme; route to pgx or sqlite implementation.
	return nil, fmt.Errorf("db: not implemented yet — see internal/db/pgx.go")
}
