package db

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ResetTokenBytes is the entropy of a reset token before encoding. 32 bytes of
// crypto/rand is the same strength as the API keys this product already issues;
// anything smaller invites offline guessing against a stolen database, and the
// token is machine-handled so length costs nothing.
const ResetTokenBytes = 32

// DefaultResetTTL is how long a reset link stays usable. Short enough that a
// link left in an unattended inbox stops mattering quickly, long enough that a
// user who steps away mid-flow does not have to start over.
const DefaultResetTTL = 30 * time.Minute

// ErrResetTokenInvalid is returned for every unusable token — unknown, expired,
// or already burned. Deliberately ONE error for all three: telling a caller
// which of those it was would confirm that a token existed, and the redemption
// endpoint is unauthenticated.
var ErrResetTokenInvalid = errors.New("db: reset token is invalid or expired")

// ResetAccount is the minimum an unauthenticated reset needs about an account.
// It carries no password hash and no role on purpose — nothing here is a secret,
// so a bug that logged this struct would not leak credentials.
type ResetAccount struct {
	UserID   string
	TenantID string
	Email    string
	Name     string
}

// hashResetToken maps a raw token to the value stored in the database.
//
// SHA-256 rather than argon2: unlike a password, this token is 256 bits of
// uniform randomness, so there is no dictionary to grind and no benefit to a
// slow KDF — while a slow KDF on the redemption path would hand an attacker a
// cheap CPU-exhaustion lever on an UNAUTHENTICATED endpoint.
func hashResetToken(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

// LookupResetAccount resolves an email to an active account, pre-auth.
//
// Returns found=false (not an error) when there is no such account, because the
// caller must behave identically either way — see the handler, which sends the
// same response and spends the same time regardless.
func (s *Store) LookupResetAccount(ctx context.Context, email string) (ResetAccount, bool, error) {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return ResetAccount{}, false, fmt.Errorf("store: pool is not a *pgxPool")
	}
	var a ResetAccount
	err := pg.pool.QueryRow(ctx,
		`SELECT id, tenant_id, email, name FROM sentinel_reset_lookup($1)`,
		strings.TrimSpace(email),
	).Scan(&a.UserID, &a.TenantID, &a.Email, &a.Name)
	if err != nil {
		// No row is the overwhelmingly common case (typo, or probing). Anything
		// else is a real failure the caller should log — but the caller still
		// must not change its response.
		if strings.Contains(err.Error(), "no rows") {
			return ResetAccount{}, false, nil
		}
		return ResetAccount{}, false, fmt.Errorf("store: reset lookup: %w", err)
	}
	return a, true, nil
}

// CreateResetToken mints a single-use reset token and stores only its hash.
//
// The RAW token is returned to the caller and never persisted, so it exists only
// in memory here and in the mail the caller sends. Any outstanding tokens for the
// user are invalidated first: requesting a new link must retire the previous one,
// otherwise every request permanently widens the window.
func (s *Store) CreateResetToken(ctx context.Context, acct ResetAccount, ttl time.Duration,
	requestIP, initiatedBy string) (string, time.Time, error) {

	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return "", time.Time{}, fmt.Errorf("store: pool is not a *pgxPool")
	}
	if ttl <= 0 {
		ttl = DefaultResetTTL
	}
	if initiatedBy != "admin" {
		initiatedBy = "self"
	}

	buf := make([]byte, ResetTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", time.Time{}, fmt.Errorf("store: reset token entropy: %w", err)
	}
	raw := base64.RawURLEncoding.EncodeToString(buf)
	expiresAt := time.Now().UTC().Add(ttl)

	tx, err := pg.pool.Begin(ctx)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("store: reset token begin: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		`DELETE FROM password_reset_tokens WHERE user_id = $1`, acct.UserID); err != nil {
		return "", time.Time{}, fmt.Errorf("store: retire prior reset tokens: %w", err)
	}

	// requestIP is passed as a nullable text cast to inet: an empty string must
	// become NULL, not a cast error that fails the whole request.
	var ipArg any
	if requestIP != "" {
		ipArg = requestIP
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO password_reset_tokens
		    (token_hash, tenant_id, user_id, expires_at, requested_ip, initiated_by)
		 VALUES ($1, $2, $3, $4, $5::inet, $6)`,
		hashResetToken(raw), acct.TenantID, acct.UserID, expiresAt, ipArg, initiatedBy,
	); err != nil {
		return "", time.Time{}, fmt.Errorf("store: insert reset token: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return "", time.Time{}, fmt.Errorf("store: reset token commit: %w", err)
	}
	return raw, expiresAt, nil
}

// ConsumeResetToken burns a token and returns the account it belonged to.
//
// Single-use is enforced inside sentinel_reset_consume by a conditional UPDATE,
// so two concurrent redemptions of the same link cannot both succeed: exactly one
// matches the row, the other gets ErrResetTokenInvalid.
func (s *Store) ConsumeResetToken(ctx context.Context, rawToken string) (ResetAccount, string, error) {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return ResetAccount{}, "", fmt.Errorf("store: pool is not a *pgxPool")
	}
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return ResetAccount{}, "", ErrResetTokenInvalid
	}

	var userID, tenantID, initiatedBy string
	err := pg.pool.QueryRow(ctx,
		`SELECT user_id, tenant_id, initiated_by FROM sentinel_reset_consume($1)`,
		hashResetToken(rawToken),
	).Scan(&userID, &tenantID, &initiatedBy)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return ResetAccount{}, "", ErrResetTokenInvalid
		}
		return ResetAccount{}, "", fmt.Errorf("store: consume reset token: %w", err)
	}

	// The token is already burned at this point. Fetch the address so the caller
	// can send the "your password was changed" notice; failing to read it must
	// not undo a redemption that has legitimately succeeded.
	acct := ResetAccount{UserID: userID, TenantID: tenantID}
	_ = pg.pool.QueryRow(ctx,
		`SELECT email, name FROM users WHERE id = $1`, userID).Scan(&acct.Email, &acct.Name)
	return acct, initiatedBy, nil
}

// SetPassword writes a new argon2id hash and cuts every session that predates it.
//
// The three writes are one transaction on purpose. A new password with the old
// sessions still live is not a completed reset — an attacker holding a stolen
// refresh token would keep the account. Likewise any unused reset token must die
// here, or a second link mailed minutes earlier would still work afterwards.
func (s *Store) SetPassword(ctx context.Context, tenantID, actorID, userID, newPassword string) error {
	pwHash, err := hashPassword(newPassword)
	if err != nil {
		return err
	}
	tx, err := s.pool.BeginTenant(ctx, tenantID, actorID)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	now := time.Now().UTC()
	var got string
	if err := tx.QueryRow(ctx,
		`UPDATE users
		    SET password_hash       = $2,
		        password_changed_at = $3,
		        sessions_valid_from = $3
		  WHERE id = $1 AND tenant_id = $4
		  RETURNING id`,
		userID, pwHash, now, tenantID).Scan(&got); err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return fmt.Errorf("user not found")
		}
		return fmt.Errorf("store: set password: %w", err)
	}

	if err := tx.Exec(ctx,
		`DELETE FROM password_reset_tokens WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("store: clear reset tokens: %w", err)
	}
	return tx.Commit(ctx)
}

// VerifyUserPassword checks a password for an already-authenticated user.
//
// Used by self-service change, which requires the CURRENT password so that a
// briefly unattended browser cannot be turned into a permanent takeover.
func (s *Store) VerifyUserPassword(ctx context.Context, tenantID, userID, password string) (bool, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)

	var pwHash string
	if err := tx.QueryRow(ctx,
		`SELECT password_hash FROM users WHERE id = $1 AND tenant_id = $2`,
		userID, tenantID).Scan(&pwHash); err != nil {
		return false, fmt.Errorf("store: read password hash: %w", err)
	}
	tx.Commit(ctx)
	return checkPassword(password, pwHash), nil
}

// SessionEpochs returns every user's session cut-off, for the in-process guard
// that rejects access tokens minted before a password change.
//
// Only users who have ever reset appear (the column is NULL otherwise), so this
// stays small on a real deployment and is cheap to poll.
func (s *Store) SessionEpochs(ctx context.Context) (map[string]time.Time, error) {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return nil, fmt.Errorf("store: pool is not a *pgxPool")
	}
	rows, err := pg.pool.Query(ctx,
		`SELECT id, sessions_valid_from FROM users WHERE sessions_valid_from IS NOT NULL`)
	if err != nil {
		return nil, fmt.Errorf("store: session epochs: %w", err)
	}
	defer rows.Close()

	out := make(map[string]time.Time)
	for rows.Next() {
		var id string
		var ts time.Time
		if err := rows.Scan(&id, &ts); err != nil {
			return nil, err
		}
		out[id] = ts
	}
	return out, rows.Err()
}

// UserIDs lists every user id, across tenants. Used by the session cache to
// notice an account that has been DELETED: its row — and so its session
// cut-off — is gone, which a node that did not run the delete could otherwise
// never learn, and would keep honouring the user's access token until expiry.
func (s *Store) UserIDs(ctx context.Context) (map[string]struct{}, error) {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return nil, fmt.Errorf("store: pool is not a *pgxPool")
	}
	rows, err := pg.pool.Query(ctx, `SELECT id FROM users`)
	if err != nil {
		return nil, fmt.Errorf("store: user ids: %w", err)
	}
	defer rows.Close()
	out := make(map[string]struct{})
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = struct{}{}
	}
	return out, rows.Err()
}

// CleanupExpiredResetTokens prunes spent and expired tokens. Returns rows removed.
func (s *Store) CleanupExpiredResetTokens(ctx context.Context) (int64, error) {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return 0, fmt.Errorf("store: pool is not a *pgxPool")
	}
	ct, err := pg.pool.Exec(ctx,
		`DELETE FROM password_reset_tokens WHERE expires_at < now() OR used_at IS NOT NULL`)
	if err != nil {
		return 0, err
	}
	return ct.RowsAffected(), nil
}
