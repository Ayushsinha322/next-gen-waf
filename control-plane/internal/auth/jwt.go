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

// IssueTokenPair returns both an access and refresh token.
func (s *JWTService) IssueTokenPair(claims Claims) (*TokenPair, error) {
	access, err := s.IssueAccessToken(claims)
	if err != nil {
		return nil, err
	}
	refresh, err := s.IssueRefreshToken(claims)
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
