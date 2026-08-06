package db

import (
	"context"
	"fmt"
	"time"
)

// RevokeToken adds a token's jti to the denylist until its natural expiry.
// Node-global (jti is not tenant-scoped); idempotent.
func (s *Store) RevokeToken(ctx context.Context, jti string, expiresAt time.Time) error {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return fmt.Errorf("store: pool is not a *pgxPool")
	}
	_, err := pg.pool.Exec(ctx,
		`INSERT INTO revoked_tokens (jti, expires_at) VALUES ($1, $2)
		 ON CONFLICT (jti) DO NOTHING`,
		jti, expiresAt)
	if err != nil {
		return fmt.Errorf("revoke token: %w", err)
	}
	return nil
}

// IsTokenRevoked reports whether a jti is on the denylist. Called on every
// Validate, so it is a single indexed PK lookup.
func (s *Store) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return false, fmt.Errorf("store: pool is not a *pgxPool")
	}
	var exists bool
	err := pg.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM revoked_tokens WHERE jti = $1)`, jti).Scan(&exists)
	return exists, err
}

// CleanupExpiredRevokedTokens prunes denylist rows past their expiry (a revoked
// token that has expired anyway no longer needs listing). Returns rows removed.
func (s *Store) CleanupExpiredRevokedTokens(ctx context.Context) (int64, error) {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return 0, fmt.Errorf("store: pool is not a *pgxPool")
	}
	ct, err := pg.pool.Exec(ctx, `DELETE FROM revoked_tokens WHERE expires_at < now()`)
	if err != nil {
		return 0, err
	}
	return ct.RowsAffected(), nil
}
