package db

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
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

	// Explicit tenant_id predicate (defense-in-depth): isolation must not depend
	// solely on RLS being active for the connecting role.
	rows, err := tx.Query(ctx, `
		SELECT id, tenant_id, email, name, role, status,
		       (mfa_secret IS NOT NULL AND mfa_secret <> '') AS mfa_enabled,
		       last_login_at, created_at
		FROM users
		WHERE tenant_id = $1
		ORDER BY created_at ASC`, tenantID)
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
		    status = COALESCE(NULLIF($3, ''), status),
		    -- A role change or a disable ends the user's sessions on EVERY
		    -- control-plane node. The role travels inside the access token, so
		    -- without a cut-off a demoted admin kept admin rights until the token
		    -- expired; and the in-memory cut-off the handler sets reaches only the
		    -- node that ran the write — the others learn from this column.
		    sessions_valid_from = CASE
		        WHEN ($2 <> '' AND $2 <> role)
		          OR ($3 <> '' AND $3 <> status AND $3 <> 'active') THEN now()
		        ELSE sessions_valid_from END
		WHERE id = $1 AND tenant_id = $4
		RETURNING id`,
		userID, role, status, tenantID).Scan(&got)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("user not found")
		}
		return fmt.Errorf("update user: %w", err)
	}
	return tx.Commit(ctx)
}

// MarkLogin stamps a successful sign-in on the user row.
//
// The column has existed since the first migration and NOTHING EVER WROTE IT.
// Every account read "Never" on the Settings page, including the one looking at
// the screen, which during an access review is indistinguishable from a dormant
// account that should be removed. The console was also reading the wrong field
// name, so fixing that alone would have swapped one permanent "Never" for
// another; both halves are needed for the column to mean anything.
//
// Deliberately NOT wrapped in the caller's audit transaction: the audit entry
// records that a login happened, and this is a convenience timestamp. A failure
// here must never cost someone their session, so the caller treats it as
// best-effort — but it logs, rather than discarding the error silently.
func (s *Store) MarkLogin(ctx context.Context, tenantID, userID string) error {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Explicit tenant predicate alongside the id, matching every other write in
	// this file: isolation must not depend solely on RLS being active.
	var got string
	err = tx.QueryRow(ctx, `
		UPDATE users
		SET last_login_at = now()
		WHERE id = $1 AND tenant_id = $2
		RETURNING id`,
		userID, tenantID).Scan(&got)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("user not found")
		}
		return fmt.Errorf("mark login: %w", err)
	}
	return tx.Commit(ctx)
}

// DeleteUser removes a user from the tenant.
// DeleteUser removes the account and returns the email and role it had, so the
// caller can write them into the user.delete audit entry: once the row is gone
// that entry is the only place left that says who the account was, and the
// audit list reads it to name a deleted user's past actions.
func (s *Store) DeleteUser(ctx context.Context, tenantID, actorID, userID string) (email, role string, err error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, actorID)
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback(ctx)

	err = tx.QueryRow(ctx, `DELETE FROM users WHERE id = $1 AND tenant_id = $2 RETURNING email, role`, userID, tenantID).Scan(&email, &role)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", fmt.Errorf("user not found")
		}
		return "", "", fmt.Errorf("delete user: %w", err)
	}
	return email, role, tx.Commit(ctx)
}

// RefreshUser re-reads a user's CURRENT role and status by id, tenant-scoped, so
// the refresh path can re-derive privileges from the database instead of
// trusting a (possibly stale) refresh token's frozen claims. Returns
// ErrUserInactive if the user is gone or no longer active — the caller must
// reject the refresh in that case, so disabling/deleting a user actually
// terminates their session within one access-token lifetime.
func (s *Store) RefreshUser(ctx context.Context, tenantID, userID string) (role, status string, err error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback(ctx)

	err = tx.QueryRow(ctx,
		`SELECT role, status FROM users WHERE id = $1 AND tenant_id = $2`,
		userID, tenantID).Scan(&role, &status)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", ErrUserInactive
		}
		return "", "", fmt.Errorf("refresh user: %w", err)
	}
	if status != "active" {
		return "", "", ErrUserInactive
	}
	return role, status, tx.Commit(ctx)
}

// SessionCutoff returns the session cut-off for a user, or the zero time when
// the account has never had its sessions invalidated. Used by the refresh path
// to reject a refresh token minted before a password change.
func (s *Store) SessionCutoff(ctx context.Context, tenantID, userID string) (time.Time, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return time.Time{}, err
	}
	defer tx.Rollback(ctx)

	var validFrom *time.Time
	if err := tx.QueryRow(ctx,
		`SELECT sessions_valid_from FROM users WHERE id = $1 AND tenant_id = $2`,
		userID, tenantID).Scan(&validFrom); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return time.Time{}, ErrUserInactive
		}
		return time.Time{}, fmt.Errorf("session cutoff: %w", err)
	}
	tx.Commit(ctx)
	if validFrom == nil {
		return time.Time{}, nil
	}
	return *validFrom, nil
}

// ErrUserInactive is returned when a session's user no longer exists or is not
// active (disabled/deleted) — used to fail the refresh path closed.
var ErrUserInactive = errors.New("user is inactive or does not exist")

// LookupSSOUser maps a verified SSO (OIDC) email to a provisioned active user's
// id, tenant, and role — via the cross-tenant carve-out (works under the
// non-superuser role with FORCE RLS). Errors if no active user matches.
func (s *Store) LookupSSOUser(ctx context.Context, email string) (userID, tenantID, role string, err error) {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return "", "", "", fmt.Errorf("store: pool is not a *pgxPool")
	}
	err = pg.pool.QueryRow(ctx,
		`SELECT id, tenant_id, role FROM sentinel_sso_lookup($1)`, email).
		Scan(&userID, &tenantID, &role)
	return userID, tenantID, role, err
}

// SetMFASecret sets (or clears, when secret == "") a user's TOTP secret.
func (s *Store) SetMFASecret(ctx context.Context, tenantID, userID, secret string) error {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var got string
	// Reset the replay guard whenever the secret changes (fresh enroll or
	// disable) so a newly enrolled secret starts from a clean step counter.
	err = tx.QueryRow(ctx,
		`UPDATE users SET mfa_secret = NULLIF($2, ''), mfa_last_step = 0 WHERE id = $1 AND tenant_id = $3 RETURNING id`,
		userID, secret, tenantID).Scan(&got)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("user not found")
		}
		return fmt.Errorf("set mfa secret: %w", err)
	}
	return tx.Commit(ctx)
}

// ConsumeMFAStep atomically records a successfully verified TOTP step and
// rejects replay: it succeeds only when step is strictly greater than the user's
// last consumed step. Returns false (no error) when the step was already used —
// i.e. the presented code is a replay of one accepted within the skew window.
func (s *Store) ConsumeMFAStep(ctx context.Context, tenantID, userID string, step int64) (bool, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)

	var got string
	err = tx.QueryRow(ctx,
		`UPDATE users SET mfa_last_step = $3
		   WHERE id = $1 AND tenant_id = $2 AND mfa_last_step < $3
		   RETURNING id`,
		userID, tenantID, step).Scan(&got)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil // step already consumed -> replay
		}
		return false, fmt.Errorf("consume mfa step: %w", err)
	}
	return true, tx.Commit(ctx)
}

// GetMFASecret returns a user's TOTP secret ("" if MFA is not enabled).
func (s *Store) GetMFASecret(ctx context.Context, tenantID, userID string) (string, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	var secret *string
	if err := tx.QueryRow(ctx, `SELECT mfa_secret FROM users WHERE id = $1 AND tenant_id = $2`, userID, tenantID).Scan(&secret); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	if secret == nil {
		return "", nil
	}
	return *secret, nil
}
