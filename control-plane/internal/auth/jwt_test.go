package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestJWTService_IssueAndValidate(t *testing.T) {
	svc, err := NewJWTService(JWTConfig{
		Secret:         "test-secret-key-1234567890123456",
		AccessTokenTTL: 5 * time.Minute,
		Issuer:         "sentinel-test",
	})
	require.NoError(t, err)

	claims := Claims{
		TenantID:   "tenant-1",
		UserID:     "user-1",
		Role:       "admin",
		AuthMethod: "password",
	}

	token, err := svc.IssueAccessToken(claims)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	parsed, err := svc.Validate(token)
	require.NoError(t, err)
	require.Equal(t, "tenant-1", parsed.TenantID)
	require.Equal(t, "user-1", parsed.UserID)
	require.Equal(t, "admin", parsed.Role)
	require.Equal(t, "password", parsed.AuthMethod)
	require.Equal(t, "sentinel-test", parsed.Issuer)
}

func TestJWTService_ExpiredToken(t *testing.T) {
	svc, err := NewJWTService(JWTConfig{
		Secret:          "test-secret",
		AccessTokenTTL:  1 * time.Millisecond,
		RefreshTokenTTL: 1 * time.Millisecond,
		Issuer:          "sentinel-test",
	})
	require.NoError(t, err)

	claims := Claims{TenantID: "t1", UserID: "u1", Role: "viewer"}
	token, err := svc.IssueAccessToken(claims)
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)

	_, err = svc.Validate(token)
	require.ErrorIs(t, err, ErrTokenExpired)
}

func TestJWTService_InvalidToken(t *testing.T) {
	svc, err := NewJWTService(JWTConfig{Secret: "test-secret"})
	require.NoError(t, err)

	_, err = svc.Validate("not.a.valid.token")
	require.ErrorIs(t, err, ErrTokenInvalid)
}

func TestJWTService_TokenPair(t *testing.T) {
	svc, err := NewJWTService(JWTConfig{Secret: "pair-test-secret", AccessTokenTTL: time.Hour})
	require.NoError(t, err)

	claims := Claims{TenantID: "t2", UserID: "u2", Role: "editor"}
	pair, err := svc.IssueTokenPair(claims)
	require.NoError(t, err)
	require.NotEmpty(t, pair.AccessToken)
	require.NotEmpty(t, pair.RefreshToken)
	require.Equal(t, "Bearer", pair.TokenType)

	// Validate access token.
	access, err := svc.Validate(pair.AccessToken)
	require.NoError(t, err)
	require.Equal(t, "editor", access.Role)

	// Validate refresh token (auth method should be "refresh").
	refresh, err := svc.Validate(pair.RefreshToken)
	require.NoError(t, err)
	require.Equal(t, "refresh", refresh.AuthMethod)
}

func TestJWTService_WrongSecret(t *testing.T) {
	svc, err := NewJWTService(JWTConfig{Secret: "correct-secret"})
	require.NoError(t, err)

	claims := Claims{TenantID: "t", UserID: "u", Role: "admin"}
	token, err := svc.IssueAccessToken(claims)
	require.NoError(t, err)

	svc2, err := NewJWTService(JWTConfig{Secret: "different-secret"})
	require.NoError(t, err)

	_, err = svc2.Validate(token)
	require.ErrorIs(t, err, ErrSignatureInvalid)
}

func TestBearerToken(t *testing.T) {
	tok, err := BearerToken("")
	require.ErrorIs(t, err, ErrTokenMissing)
	require.Empty(t, tok)

	tok, err = BearerToken("Basic xyz")
	require.ErrorIs(t, err, ErrTokenInvalid)

	tok, err = BearerToken("Bearer ")
	require.ErrorIs(t, err, ErrTokenMissing)

	tok, err = BearerToken("Bearer abc123")
	require.NoError(t, err)
	require.Equal(t, "abc123", tok)
}

func TestHashAPIKey(t *testing.T) {
	hash := HashAPIKey("sk-12345")
	require.Len(t, hash, 64) // SHA-256 hex
	require.NotEqual(t, "sk-12345", hash)
}

func TestNewState(t *testing.T) {
	s1, err := NewState()
	require.NoError(t, err)
	s2, err := NewState()
	require.NoError(t, err)
	require.NotEmpty(t, s1)
	require.NotEmpty(t, s2)
	require.NotEqual(t, s1, s2)
}
