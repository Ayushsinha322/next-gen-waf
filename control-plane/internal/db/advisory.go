package db

import (
	"context"
	"fmt"
)

// Session-scoped advisory locking, used for singleton election.
//
// A session-scoped advisory lock (`pg_try_advisory_lock`, not the `_xact_`
// variant) is held for as long as the holding CONNECTION lives. That is exactly
// the property leader election needs: if the holder crashes, is partitioned away,
// or its connection is severed by a Postgres failover, the lock is released by the
// server without anyone having to notice or time anything out. There is no lease
// to renew and no clock to trust.
//
// Under CloudNativePG the -rw service always points at the primary, so all
// contenders race for the same lock on the same node, and a primary failover drops
// every connection and forces a clean re-election.

// AdvisorySession is a held session-scoped advisory lock, with the dedicated
// connection that owns it. Release it with Unlock; it is not safe for concurrent
// use from multiple goroutines.
type AdvisorySession struct {
	conn interface {
		Release()
	}
	// ping executes a trivial statement to confirm the owning connection is still
	// alive; if it fails, the lock is presumed lost.
	ping   func(ctx context.Context) error
	unlock func(ctx context.Context) error
	key    int64
	done   bool
}

// Ping verifies the lock-owning connection is still usable.
//
// This is the liveness check for leadership: the lock is only as good as the
// connection holding it, so a leader must confirm the connection rather than
// assume it still has the lock.
func (s *AdvisorySession) Ping(ctx context.Context) error {
	if s == nil || s.done {
		return fmt.Errorf("db: advisory session already released")
	}
	return s.ping(ctx)
}

// Unlock releases the advisory lock and returns the connection to the pool.
// Safe to call more than once.
func (s *AdvisorySession) Unlock(ctx context.Context) {
	if s == nil || s.done {
		return
	}
	s.done = true
	// Best-effort: if the unlock statement fails the connection is already broken,
	// and releasing it back to the pool discards it — which frees the lock anyway.
	_ = s.unlock(ctx)
	s.conn.Release()
}

// Key is the advisory-lock key this session holds.
func (s *AdvisorySession) Key() int64 { return s.key }

// TryAdvisoryLock attempts to take the session-scoped advisory lock identified by
// `key`, without blocking.
//
// Returns (nil, nil) when the lock is held by someone else — that is the ordinary
// "another node is leader" outcome, not an error. A non-nil error means Postgres
// could not be reached or the query failed.
func (p *pgxPool) TryAdvisoryLock(ctx context.Context, key int64) (*AdvisorySession, error) {
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("db: acquire advisory conn: %w", err)
	}

	var acquired bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&acquired); err != nil {
		conn.Release()
		return nil, fmt.Errorf("db: pg_try_advisory_lock: %w", err)
	}
	if !acquired {
		// Someone else holds it. Give the connection straight back — holding a
		// pool connection per losing contender would starve the pool.
		conn.Release()
		return nil, nil
	}

	return &AdvisorySession{
		conn: conn,
		key:  key,
		ping: func(ctx context.Context) error {
			var one int
			return conn.QueryRow(ctx, `SELECT 1`).Scan(&one)
		},
		unlock: func(ctx context.Context) error {
			var released bool
			return conn.QueryRow(ctx, `SELECT pg_advisory_unlock($1)`, key).Scan(&released)
		},
	}, nil
}

// AdvisoryLocker is the subset of Pool needed for leader election. Declared so
// callers can depend on the capability rather than the concrete pool type, and so
// tests can substitute a fake.
type AdvisoryLocker interface {
	TryAdvisoryLock(ctx context.Context, key int64) (*AdvisorySession, error)
}

// Exec runs a statement outside any tenant context, for cluster-wide bookkeeping
// that is not tenant-scoped (e.g. the leader identity row). Tenant data must go
// through BeginTenant so RLS applies.
func (p *pgxPool) Exec(ctx context.Context, sql string, args ...any) error {
	_, err := p.pool.Exec(ctx, sql, args...)
	return err
}

// QueryRowGlobal runs a single-row query outside any tenant context. Same caveat
// as Exec: not for tenant data.
func (p *pgxPool) QueryRowGlobal(ctx context.Context, sql string, args ...any) Row {
	return p.pool.QueryRow(ctx, sql, args...)
}

// QueryGlobal runs a multi-row query outside any tenant context. Same caveat as
// Exec: not for tenant data.
func (p *pgxPool) QueryGlobal(ctx context.Context, sql string, args ...any) (Rows, error) {
	rows, err := p.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return &pgxRows{rows: rows}, nil
}

// GlobalQuerier is the non-tenant-scoped query surface used by cluster
// bookkeeping.
type GlobalQuerier interface {
	Exec(ctx context.Context, sql string, args ...any) error
	QueryRowGlobal(ctx context.Context, sql string, args ...any) Row
	QueryGlobal(ctx context.Context, sql string, args ...any) (Rows, error)
}
