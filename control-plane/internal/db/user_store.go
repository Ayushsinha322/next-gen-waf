package db

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"golang.org/x/crypto/argon2"
)

// UserRow is a user as returned to the admin API. It NEVER carries the password
// hash. MFAEnabled is derived from whether an MFA secret is set.
type UserRow struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"tenant_id"`
	Email       string     `json:"email"`
	Name        string     `json:"name"`
	Role        string     `json:"role"`
	Status      string     `json:"status"`
	MFAEnabled  bool       `json:"mfa_enabled"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// hashPassword produces an "argon2id$<hexSalt>$<hexHash>" string using the same
// parameters as seed.go / checkPassword, so ValidatePassword verifies it.
func hashPassword(plain string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password salt: %w", err)
	}
	hash := argon2.IDKey([]byte(plain), salt, 1, 64*1024, 4, 32)
	return fmt.Sprintf("argon2id$%s$%s", hex.EncodeToString(salt), hex.EncodeToString(hash)), nil
}

// CreateUser inserts a real, tenant-scoped user with an argon2id password hash.
// RLS (via BeginTenant) confines the row to actorID's tenant.
func (s *Store) CreateUser(ctx context.Context, tenantID, actorID, email, name, role, password string) (UserRow, error) {
	pwHash, err := hashPassword(password)
	if err != nil {
		return UserRow{}, err
	}
	tx, err := s.pool.BeginTenant(ctx, tenantID, actorID)
	if err != nil {
		return UserRow{}, err
	}
	defer tx.Rollback(ctx)

	var u UserRow
	var lastLogin *time.Time
	var mfaSecret *string
	err = tx.QueryRow(ctx, `
		INSERT INTO users (tenant_id, email, name, password_hash, role, status)
		VALUES ($1, $2, $3, $4, $5, 'active')
		RETURNING id, tenant_id, email, name, role, status, mfa_secret, last_login_at, created_at`,
		tenantID, email, name, pwHash, role,
	).Scan(&u.ID, &u.TenantID, &u.Email, &u.Name, &u.Role, &u.Status, &mfaSecret, &lastLogin, &u.CreatedAt)
	if err != nil {
		return UserRow{}, fmt.Errorf("create user: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return UserRow{}, err
	}
	u.MFAEnabled = mfaSecret != nil && *mfaSecret != ""
	u.LastLoginAt = lastLogin
	return u, nil
}

// ListUsers returns the tenant's users (no password hashes).
func (s *Store) ListUsers(ctx context.Context, tenantID, actorID string) ([]UserRow, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, actorID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, `
		SELECT id, tenant_id, email, name, role, status,
		       (mfa_secret IS NOT NULL AND mfa_secret <> '') AS mfa_enabled,
		       last_login_at, created_at
		FROM users
		ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var out []UserRow
	for rows.Next() {
		var u UserRow
		if err := rows.Scan(&u.ID, &u.TenantID, &u.Email, &u.Name, &u.Role, &u.Status,
			&u.MFAEnabled, &u.LastLoginAt, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}

// UpdateUser changes a user's role and/or status (empty values are left as-is).
func (s *Store) UpdateUser(ctx context.Context, tenantID, actorID, userID, role, status string) error {
	tx, err := s.pool.BeginTenant(ctx, tenantID, actorID)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var got string
	err = tx.QueryRow(ctx, `
		UPDATE users
		SET role   = COALESCE(NULLIF($2, ''), role),
		    status = COALESCE(NULLIF($3, ''), status)
		WHERE id = $1
		RETURNING id`,
		userID, role, status).Scan(&got)
	if err != nil {
		return fmt.Errorf("user not found")
	}
	return tx.Commit(ctx)
}

// DeleteUser removes a user from the tenant.
func (s *Store) DeleteUser(ctx context.Context, tenantID, actorID, userID string) error {
	tx, err := s.pool.BeginTenant(ctx, tenantID, actorID)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var got string
	err = tx.QueryRow(ctx, `DELETE FROM users WHERE id = $1 RETURNING id`, userID).Scan(&got)
	if err != nil {
		return fmt.Errorf("user not found")
	}
	return tx.Commit(ctx)
}
