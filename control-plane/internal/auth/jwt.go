// Package auth provides JWT token creation/validation, OIDC discovery,
// and authentication middleware for the Sentinel control plane.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Common auth errors.
var (
	ErrTokenExpired     = errors.New("auth: token expired")
	ErrTokenInvalid     = errors.New("auth: token invalid")
	ErrTokenMissing     = errors.New("auth: token missing")
	ErrTokenNotBefore   = errors.New("auth: token not yet valid")
	ErrSignatureInvalid = errors.New("auth: signature invalid")
	ErrUserDisabled     = errors.New("auth: user disabled")
)

// Claims carries the identity and permissions of an authenticated caller.
type Claims struct {
	jwt.RegisteredClaims
	// TenantID is the multi-tenant compartment the caller belongs to.
	TenantID string `json:"tenant_id"`
	// UserID is the UUID of the authenticated user (empty for API-key auth).
	UserID string `json:"user_id,omitempty"`
	// Role is the RBAC role (owner/admin/editor/viewer/auditor).
	Role string `json:"role"`
	// Scopes are API-key scopes when authenticated via API key.
	Scopes []string `json:"scopes,omitempty"`
	// AuthMethod is "password", "oidc", or "apikey".
	AuthMethod string `json:"auth_method"`
	// RefreshJTI links an access token to its paired refresh token's jti so
	// logout can revoke the refresh token server-side WITHOUT the client having
	// to resend it. Set on both tokens of a pair (the refresh token points at
	// itself) and preserved across refresh so a re-minted access token still
	// carries it.
	RefreshJTI string `json:"rjti,omitempty"`
}

// JWTConfig holds settings for JWT token issuance and validation.
type JWTConfig struct {
	// Secret is the HMAC-SHA256 signing key.
	Secret string `yaml:"secret" json:"-"`

	// AccessTokenTTL is how long access tokens live (default 15m).
	AccessTokenTTL time.Duration `yaml:"access_token_ttl" json:"access_token_ttl,omitempty"`

	// RefreshTokenTTL is how long refresh tokens live (default 7d).
	RefreshTokenTTL time.Duration `yaml:"refresh_token_ttl" json:"refresh_token_ttl,omitempty"`

	// Issuer is the "iss" claim value (default "sentinel-waf").
	Issuer string `yaml:"issuer" json:"issuer,omitempty"`
}

// DefaultJWTConfig returns sensible defaults.
func DefaultJWTConfig() JWTConfig {
	return JWTConfig{
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		Issuer:          "sentinel-waf",
	}
}

// TokenPair contains an access token and a refresh token.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"` // seconds
	TokenType    string `json:"token_type"` // "Bearer"
}

// JWTService creates and validates JWT tokens.
type JWTService struct {
	cfg JWTConfig
	key []byte
	// revoked, if set, reports whether a token's jti has been revoked (logout /
	// forced sign-out). Injected from main() so the auth package needn't import
	// db. Called on every Validate, so it should be cheap.
	revoked func(jti string) bool
	// sessionOK, if set, reports whether a token issued at a given time for a
	// given user is still within that account's valid session window. See
	// SetSessionGuard.
	sessionOK func(userID string, issuedAt time.Time) bool
}

// SetRevocationChecker wires a jti-denylist check into Validate. Every token
// path (HTTP middleware, gRPC, SSE, refresh) goes through Validate, so a single
// check here covers them all.
func (s *JWTService) SetRevocationChecker(f func(jti string) bool) {
	s.revoked = f
}

// SetSessionGuard wires a per-user session cut-off into Validate.
//
// The denylist above can only revoke tokens whose jti is known, which is fine
// for logout (the caller presents the token) and useless for "sign this account
// out everywhere" after a password reset — nothing records the jtis a user is
// currently holding. This guard answers the question the reset flow actually
// asks: was this token issued before the account's credentials changed?
//
// f reports whether a token issued at issuedAt for userID is still acceptable.
// It is called on every Validate, so the implementation must be cheap — the
// control plane backs it with an in-process map, not a query.
func (s *JWTService) SetSessionGuard(f func(userID string, issuedAt time.Time) bool) {
	s.sessionOK = f
}

// NewJWTService creates a JWTService. If cfg.Secret is empty, a random 256-bit
// key is generated (appropriate for single-node dev, not for HA clusters).
func NewJWTService(cfg JWTConfig) (*JWTService, error) {
	if cfg.AccessTokenTTL == 0 {
		cfg.AccessTokenTTL = 15 * time.Minute
	}
	if cfg.RefreshTokenTTL == 0 {
		cfg.RefreshTokenTTL = 7 * 24 * time.Hour
	}
	if cfg.Issuer == "" {
		cfg.Issuer = "sentinel-waf"
	}

	key := []byte(cfg.Secret)
	if len(key) == 0 {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("auth: generating random JWT key: %w", err)
		}
	}

	return &JWTService{cfg: cfg, key: key}, nil
}

// IssueAccessToken creates a short-lived JWT for the given identity.
func (s *JWTService) IssueAccessToken(claims Claims) (string, error) {
	now := time.Now()
	claims.RegisteredClaims = jwt.RegisteredClaims{
		Issuer:    s.cfg.Issuer,
		Subject:   claims.UserID,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(s.cfg.AccessTokenTTL)),
		NotBefore: jwt.NewNumericDate(now),
		ID:        newTokenID(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.key)
}

// IssueRefreshToken creates a longer-lived token used only for obtaining new
// access tokens.
func (s *JWTService) IssueRefreshToken(claims Claims) (string, error) {
	now := time.Now()
	claims.RegisteredClaims = jwt.RegisteredClaims{
		Issuer:    s.cfg.Issuer,
		Subject:   claims.UserID,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(s.cfg.RefreshTokenTTL)),
		ID:        newTokenID(),
	}
	claims.AuthMethod = "refresh"
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.key)
}

// IssueTokenPair returns both an access and refresh token, linked by a shared
// refresh jti so logout can revoke the refresh token without the client
// resending it.
func (s *JWTService) IssueTokenPair(claims Claims) (*TokenPair, error) {
	// Pre-generate the refresh jti and stamp it on BOTH tokens. The refresh
	// token points at itself so that access tokens later minted from it (via
	// refresh) inherit the same rjti and remain revocable at logout.
	refreshJTI := newTokenID()
	now := time.Now()

	refreshClaims := claims
	refreshClaims.AuthMethod = "refresh"
	refreshClaims.RefreshJTI = refreshJTI
	refreshClaims.RegisteredClaims = jwt.RegisteredClaims{
		Issuer:    s.cfg.Issuer,
		Subject:   claims.UserID,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(s.cfg.RefreshTokenTTL)),
		ID:        refreshJTI,
	}
	refresh, err := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString(s.key)
	if err != nil {
		return nil, err
	}

	accessClaims := claims
	accessClaims.RefreshJTI = refreshJTI
	access, err := s.IssueAccessToken(accessClaims)
	if err != nil {
		return nil, err
	}
	return &TokenPair{
		AccessToken:  access,
		RefreshToken: refresh,
		ExpiresIn:    int64(s.cfg.AccessTokenTTL.Seconds()),
		TokenType:    "Bearer",
	}, nil
}

// RefreshTTL exposes the configured refresh-token lifetime so callers (logout)
// can set a denylist retention that outlives the refresh token.
func (s *JWTService) RefreshTTL() time.Duration { return s.cfg.RefreshTokenTTL }

// Validate parses and validates a JWT token string, returning the embedded
// claims if the token is valid.
func (s *JWTService) Validate(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("auth: unexpected signing method: %v", t.Header["alg"])
		}
		return s.key, nil
	})
	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenExpired):
			return nil, ErrTokenExpired
		case errors.Is(err, jwt.ErrTokenNotValidYet):
			return nil, ErrTokenNotBefore
		case errors.Is(err, jwt.ErrSignatureInvalid):
			return nil, ErrSignatureInvalid
		default:
			return nil, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
		}
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrTokenInvalid
	}
	// Denylist check (logout / forced revocation). Covers all token paths since
	// they all funnel through Validate.
	if s.revoked != nil && claims.ID != "" && s.revoked(claims.ID) {
		return nil, ErrTokenInvalid
	}
	// Session cut-off (password reset / forced sign-out of an account). Tokens
	// minted before the account's cut-off are rejected even though they are
	// correctly signed and unexpired.
	if s.sessionOK != nil && claims.UserID != "" && claims.IssuedAt != nil {
		if !s.sessionOK(claims.UserID, claims.IssuedAt.Time) {
			return nil, ErrTokenInvalid
		}
	}
	return claims, nil
}

// HashAPIKey returns the SHA-256 hash of an API key for storage.
func HashAPIKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

// newTokenID generates a random 16-byte token identifier.
func newTokenID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
