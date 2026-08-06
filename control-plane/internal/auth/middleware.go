package auth

import (
	"context"
	"errors"
	"strings"

	"github.com/gin-gonic/gin"
)

// Context keys for storing auth info in context.Context.
type contextKey string

const (
	// ClaimsKey stores the parsed *Claims in context.
	ClaimsKey contextKey = "auth.claims"
	// TenantIDKey stores the tenant ID in context (mirrors Claims.TenantID).
	TenantIDKey contextKey = "auth.tenant_id"
)

// GetClaims extracts the auth Claims from a context.
func GetClaims(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(ClaimsKey).(*Claims)
	return c, ok
}

// GetTenantID extracts the tenant ID from a context.
func GetTenantID(ctx context.Context) (string, bool) {
	t, ok := ctx.Value(TenantIDKey).(string)
	return t, ok
}

// MustGetTenantID extracts the tenant ID or panics (for internal-only paths).
func MustGetTenantID(ctx context.Context) string {
	t, ok := GetTenantID(ctx)
	if !ok {
		panic("auth: tenant_id not found in context")
	}
	return t
}

// BearerToken extracts a Bearer token from an HTTP Authorization header.
func BearerToken(authHeader string) (string, error) {
	if authHeader == "" {
		return "", ErrTokenMissing
	}
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", ErrTokenInvalid
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		return "", ErrTokenMissing
	}
	return token, nil
}

// ---------------------------------------------------------------------------
// Gin (HTTP) middleware
// ---------------------------------------------------------------------------

// GinAuthMiddleware returns a gin.HandlerFunc that validates JWT tokens from
// the Authorization header and injects the claims into the request context.
func GinAuthMiddleware(jwt *JWTService, adminOnly bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := BearerToken(c.GetHeader("Authorization"))
		if err != nil {
			abortWithAuthError(c, err)
			return
		}

		claims, err := jwt.Validate(token)
		if err != nil {
			abortWithAuthError(c, err)
			return
		}

		// A refresh token is not an access credential. Only the /auth/refresh
		// endpoint (which validates the body token itself) may consume it;
		// rejecting it here stops a 7-day refresh token from authenticating
		// protected routes for a week.
		if claims.AuthMethod == "refresh" {
			abortWithAuthError(c, ErrTokenInvalid)
			return
		}

		if adminOnly && claims.Role != "owner" && claims.Role != "admin" {
			abortWithAuthError(c, errors.New("auth: admin role required"))
			return
		}

		ctx := context.WithValue(c.Request.Context(), ClaimsKey, claims)
		ctx = context.WithValue(ctx, TenantIDKey, claims.TenantID)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// APIKeyResolver authenticates an API key by its (sha256) hash, returning
// synthesized Claims (AuthMethod "apikey") or an error. Wired in main() to the
// DB (LookupAPIKeyByHash); kept as a func so the auth package needn't import db.
type APIKeyResolver func(ctx context.Context, keyHash string) (*Claims, error)

// GinAuthMiddlewareWithAPIKey is GinAuthMiddleware plus an X-API-Key fallback:
// when there is no Bearer token but an X-API-Key header is present, the key is
// hashed and resolved to machine Claims. Bearer JWTs take precedence and behave
// exactly as GinAuthMiddleware.
func GinAuthMiddlewareWithAPIKey(jwt *JWTService, adminOnly bool, resolve APIKeyResolver) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		apiKey := c.GetHeader("X-API-Key")

		// API-key path — only when no Bearer token is presented.
		if authHeader == "" && apiKey != "" {
			if resolve == nil {
				abortWithAuthError(c, ErrTokenInvalid)
				return
			}
			claims, err := resolve(c.Request.Context(), HashAPIKey(apiKey))
			if err != nil {
				abortWithAuthError(c, ErrTokenInvalid)
				return
			}
			if adminOnly && claims.Role != "owner" && claims.Role != "admin" {
				abortWithAuthError(c, errors.New("auth: admin role required"))
				return
			}
			injectClaims(c, claims)
			c.Next()
			return
		}

		// Bearer JWT path (default), identical to GinAuthMiddleware.
		token, err := BearerToken(authHeader)
		if err != nil {
			abortWithAuthError(c, err)
			return
		}
		claims, err := jwt.Validate(token)
		if err != nil {
			abortWithAuthError(c, err)
			return
		}
		if claims.AuthMethod == "refresh" {
			abortWithAuthError(c, ErrTokenInvalid)
			return
		}
		if adminOnly && claims.Role != "owner" && claims.Role != "admin" {
			abortWithAuthError(c, errors.New("auth: admin role required"))
			return
		}
		injectClaims(c, claims)
		c.Next()
	}
}

// injectClaims puts the claims + tenant id into the request context.
func injectClaims(c *gin.Context, claims *Claims) {
	ctx := context.WithValue(c.Request.Context(), ClaimsKey, claims)
	ctx = context.WithValue(ctx, TenantIDKey, claims.TenantID)
	c.Request = c.Request.WithContext(ctx)
}

// GinOptionalAuth validates the token if present but does not abort on missing
// token.  Useful for public endpoints that behave differently when
// authenticated.
func GinOptionalAuth(jwt *JWTService) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := BearerToken(c.GetHeader("Authorization"))
		if err != nil {
			c.Next()
			return
		}

		claims, err := jwt.Validate(token)
		if err != nil {
			c.Next()
			return
		}

		ctx := context.WithValue(c.Request.Context(), ClaimsKey, claims)
		ctx = context.WithValue(ctx, TenantIDKey, claims.TenantID)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

func abortWithAuthError(c *gin.Context, err error) {
	code := 401
	if errors.Is(err, ErrTokenInvalid) || errors.Is(err, ErrSignatureInvalid) {
		code = 401
	} else if errors.Is(err, ErrTokenExpired) {
		code = 401
	} else {
		code = 403
	}
	c.AbortWithStatusJSON(code, gin.H{"error": err.Error()})
}
