package db

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ResetAdmin is the break-glass way back into a tenant. The account `email`
// (created if the tenant has none by that name) gets a new random password,
// the admin role if it held a lesser one, an active status and no MFA, and
// loses every earlier session and unused reset link. It returns the password,
// whether the account was created, and its id.
//
// For `controllerd reset-admin`, which only someone who can exec into the
// control-plane container — root on the host — can run. Before it, an
// administrator who lost the password on an installation with no mail relay
// had no way back in short of editing the database by hand.
func (s *Store) ResetAdmin(ctx context.Context, tenantID, email string) (password string, created bool, userID string, err error) {
	email = strings.TrimSpace(email)
	if !strings.Contains(email, "@") {
		return "", false, "", fmt.Errorf("%q is not an email address", email)
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", false, "", fmt.Errorf("generate password: %w", err)
	}
	password = hex.EncodeToString(buf)
	pwHash, err := hashPassword(password)
	if err != nil {
		return "", false, "", err
	}

	tx, err := s.pool.BeginTenant(ctx, tenantID, "")
	if err != nil {
		return "", false, "", err
	}
	defer tx.Rollback(ctx)

	now := time.Now().UTC()
	err = tx.QueryRow(ctx, `
		UPDATE users
		   SET password_hash       = $3,
		       password_changed_at = $4,
		       sessions_valid_from = $4,
		       status              = 'active',
		       role                = CASE WHEN role IN ('owner', 'admin') THEN role ELSE 'admin' END,
		       mfa_secret          = NULL,
		       mfa_last_step       = 0
		 WHERE tenant_id = $1 AND lower(email) = lower($2)
		 RETURNING id`,
		tenantID, email, pwHash, now).Scan(&userID)
	switch {
	case err == nil:
	case errors.Is(err, pgx.ErrNoRows):
		created = true
		if err := tx.QueryRow(ctx, `
			INSERT INTO users (tenant_id, email, name, password_hash, role, status,
			                   password_changed_at, sessions_valid_from)
			VALUES ($1, $2, 'Administrator', $3, 'admin', 'active', $4, $4)
			RETURNING id`,
			tenantID, email, pwHash, now).Scan(&userID); err != nil {
			return "", false, "", fmt.Errorf("create administrator: %w", err)
		}
	default:
		return "", false, "", fmt.Errorf("reset administrator: %w", err)
	}

	if err := tx.Exec(ctx, `DELETE FROM password_reset_tokens WHERE user_id = $1`, userID); err != nil {
		return "", false, "", fmt.Errorf("clear reset links: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", false, "", err
	}
	return password, created, userID, nil
}
