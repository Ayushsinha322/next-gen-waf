package db

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// APIKeyRow is an API key as shown in the admin API. It NEVER carries the raw
// key or its hash — only a non-sensitive preview.
type APIKeyRow struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"tenant_id"`
	Name       string     `json:"name"`
	Role       string     `json:"role"`
	Scopes     []string   `json:"scopes"`
	Preview    string     `json:"preview"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// APIKeyAuth is the result of a pre-auth lookup by key hash (machine auth).
type APIKeyAuth struct {
	ID        string
	TenantID  string
	CreatedBy string
	Role      string
	Scopes    []string
}

// hashAPIKey mirrors auth.HashAPIKey (hex(sha256(key))). Duplicated here to keep
// the db package free of an auth import (avoids an import cycle).
func hashAPIKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

// generateAPIKey returns a crypto-random key ("sk-live-<b64url(32B)>").
func generateAPIKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("api key rand: %w", err)
	}
	return "sk-live-" + base64.RawURLEncoding.EncodeToString(b), nil
}

func keyPreview(full string) string {
	if len(full) <= 16 {
		return full[:len(full)/2] + "…"
	}
	return full[:12] + "…" + full[len(full)-4:]
}

// CreateAPIKey generates a crypto-random key, stores ONLY its sha256 hash, and
// returns the row plus the plaintext key (shown to the caller exactly once).
func (s *Store) CreateAPIKey(ctx context.Context, tenantID, actorID, name, role string, scopes []string, expiresAt *time.Time) (APIKeyRow, string, error) {
	if role == "" {
		role = "viewer"
	}
	full, err := generateAPIKey()
	if err != nil {
		return APIKeyRow{}, "", err
	}
	keyHash := hashAPIKey(full)

	tx, err := s.pool.BeginTenant(ctx, tenantID, actorID)
	if err != nil {
		return APIKeyRow{}, "", err
	}
	defer tx.Rollback(ctx)

	var row APIKeyRow
	err = tx.QueryRow(ctx, `
		INSERT INTO api_keys (tenant_id, created_by, name, key_hash, role, scopes, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, tenant_id, name, role, scopes, expires_at, revoked_at, last_used_at, created_at`,
		tenantID, actorID, name, keyHash, role, scopes, expiresAt,
	).Scan(&row.ID, &row.TenantID, &row.Name, &row.Role, &row.Scopes,
		&row.ExpiresAt, &row.RevokedAt, &row.LastUsedAt, &row.CreatedAt)
	if err != nil {
		return APIKeyRow{}, "", fmt.Errorf("create api key: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return APIKeyRow{}, "", err
	}
	row.Preview = keyPreview(full)
	return row, full, nil
}

// ListAPIKeys returns the tenant's keys (never the hash or raw key).
func (s *Store) ListAPIKeys(ctx context.Context, tenantID, actorID string) ([]APIKeyRow, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, actorID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	// Explicit tenant_id predicate (defense-in-depth): do not rely on RLS alone.
	rows, err := tx.Query(ctx, `
		SELECT id, tenant_id, name, role, scopes, expires_at, revoked_at, last_used_at, created_at
		FROM api_keys
		WHERE tenant_id = $1
		ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}
	defer rows.Close()

	var out []APIKeyRow
	for rows.Next() {
		var k APIKeyRow
		if err := rows.Scan(&k.ID, &k.TenantID, &k.Name, &k.Role, &k.Scopes,
			&k.ExpiresAt, &k.RevokedAt, &k.LastUsedAt, &k.CreatedAt); err != nil {
			return nil, err
		}
		k.Preview = "sk-live-••••" // full key is unrecoverable; only the hash is stored
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}

// RevokeAPIKey marks a key revoked (tenant-scoped).
func (s *Store) RevokeAPIKey(ctx context.Context, tenantID, actorID, id string) error {
	tx, err := s.pool.BeginTenant(ctx, tenantID, actorID)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var got string
	err = tx.QueryRow(ctx, `UPDATE api_keys SET revoked_at = now() WHERE id = $1 AND tenant_id = $2 AND revoked_at IS NULL RETURNING id`, id, tenantID).Scan(&got)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("api key not found or already revoked")
		}
		// A real DB/permission/timeout failure must NOT be reported as
		// "already revoked" — an operator could believe a live key is dead.
		return fmt.Errorf("revoke api key: %w", err)
	}
	return tx.Commit(ctx)
}

// LookupAPIKeyByHash resolves a key hash to its identity for machine auth. It is
// pre-tenant (the caller's tenant is unknown), so it goes through the
// SECURITY DEFINER carve-out (works under the non-superuser sentinel_app role
// with FORCE RLS). Returns an error if no active, non-expired, non-revoked key
// matches.
func (s *Store) LookupAPIKeyByHash(ctx context.Context, keyHash string) (APIKeyAuth, error) {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return APIKeyAuth{}, fmt.Errorf("store: pool is not a *pgxPool")
	}
	var a APIKeyAuth
	var createdBy *string // created_by is a nullable FK (ON DELETE SET NULL)
	err := pg.pool.QueryRow(ctx,
		`SELECT id, tenant_id, created_by, role, scopes FROM sentinel_apikey_lookup($1)`,
		keyHash).Scan(&a.ID, &a.TenantID, &createdBy, &a.Role, &a.Scopes)
	if err != nil {
		return APIKeyAuth{}, err
	}
	if createdBy != nil {
		a.CreatedBy = *createdBy
	}
	// Best-effort last-used stamp; never fail auth on this.
	_, _ = pg.pool.Exec(ctx, `SELECT sentinel_apikey_touch($1)`, a.ID)
	return a, nil
}
