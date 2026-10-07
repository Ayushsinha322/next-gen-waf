package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	chreader "github.com/your-org/sentinel-waf/control-plane/internal/clickhouse"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/leader"
	"github.com/your-org/sentinel-waf/control-plane/internal/logs"
	"github.com/your-org/sentinel-waf/control-plane/internal/rbac"
	"go.uber.org/zap"

	"github.com/your-org/sentinel-waf/control-plane/internal/version"
)

// configVersion is incremented on every site create / delete / status change.
// The data-plane proxy polls /api/v1/internal/config and only re-fetches the
// full site list when this number changes — keeps polling cheap.
var configVersion atomic.Int64

// ---------------------------------------------------------------------------
// Auth handlers
// ---------------------------------------------------------------------------

type loginRequest struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
	// MFACode is the 6-digit TOTP, required only when the account has MFA on.
	MFACode string `json:"mfa_code"`
}

// devLoginEnabled reports whether the no-database admin/admin123 backdoor is
// explicitly permitted (local development only).
func devLoginEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SENTINEL_DEV_LOGIN"))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// requirePerm enforces an RBAC permission inside a route closure for handlers
// that don't take the enforcer directly (telemetry/status reads). Returns true
// when allowed; otherwise writes the appropriate 401/403 and returns false.
func requirePerm(c *gin.Context, enf *rbac.Enforcer, resource, action string) bool {
	claims, ok := auth.GetClaims(c.Request.Context())
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthenticated"})
		return false
	}
	if !enf.Allow(rbac.Role(claims.Role), resource, action) {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return false
	}
	return true
}

func handleLogin(c *gin.Context, jwtSvc *auth.JWTService, store *db.Store, hub *logs.Hub, log *zap.Logger) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": clientError(err)})
		return
	}

	// Brute-force lockout: reject early if either the account OR the source IP
	// is currently locked out (per-account guards password guessing; per-IP
	// guards credential stuffing across many accounts from one source).
	loginKey := strings.ToLower(strings.TrimSpace(req.Email))
	ipKey := "ip:" + c.ClientIP()
	if locked, wait := loginAttempts.locked(loginKey); locked {
		c.Header("Retry-After", fmt.Sprintf("%d", int(wait.Seconds())+1))
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many failed attempts; try again later"})
		return
	}
	if locked, wait := ipLoginAttempts.locked(ipKey); locked {
		c.Header("Retry-After", fmt.Sprintf("%d", int(wait.Seconds())+1))
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many failed attempts; try again later"})
		return
	}
	// recordFail notes a failure against both the account and the source IP.
	recordFail := func() {
		loginAttempts.recordFailure(loginKey)
		ipLoginAttempts.recordFailure(ipKey)
	}

	// Validate credentials.  When a DB pool is available we check the users
	// table; otherwise fall back to the hardcoded dev backdoor.
	var claims auth.Claims
	var loginResult = auditSuccess
	if store != nil {
		ok, userID, userTenant, role, err := store.ValidatePassword(c.Request.Context(),
			db.DevTenantID, req.Email, req.Password)
		if err != nil || !ok {
			loginResult = auditFailure
			recordFail()
			// Record the OUTCOME and the attempted email. Previously the
			// computed FAILURE was assigned and then discarded (`_ =
			// loginResult`), and the attempted address was not stored at all —
			// so a failed login was byte-identical in shape to a success apart
			// from a nil actor, and "was this account being brute-forced?"
			// could not be answered from the audit log at all. The email is the
			// identifier under attack; the password is never recorded.
			writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
				TenantID:   db.DevTenantID,
				Action:     "user.login",
				TargetKind: "user",
				Diff: auditDiff(auditFailure, map[string]any{
					"email":  loginKey,
					"reason": "invalid_credentials",
				}),
			})
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid email or password"})
			return
		}
		// Issue the token with the user's REAL tenant so per-tenant RLS and the
		// query predicates actually scope this session to that tenant.
		claims = auth.Claims{
			TenantID:   userTenant,
			UserID:     userID,
			Role:       role,
			AuthMethod: "password",
		}

		// Second factor: if the account has TOTP enabled, a valid code is
		// required. An empty code returns mfa_required (so the client prompts,
		// not counted as a failure); a wrong code is a failed attempt.
		mfaSecret, mfaErr := store.GetMFASecret(c.Request.Context(), userTenant, userID)
		if mfaErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "mfa check failed"})
			return
		}
		if mfaSecret != "" {
			if req.MFACode == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "mfa_required", "mfa_required": true})
				return
			}
			ok, step := auth.VerifyTOTPStep(mfaSecret, req.MFACode)
			if !ok {
				recordFail()
				// A wrong second factor means someone holds the password but
				// not the device — the single strongest signal of a real
				// compromise in this product, and it wrote no audit row at all.
				// The code itself is a credential and is never recorded.
				writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
					TenantID:    userTenant,
					ActorUserID: &userID,
					Action:      "user.mfa.verify",
					TargetKind:  "user",
					TargetID:    &userID,
					Diff: auditDiff(auditFailure, map[string]any{
						"email":  loginKey,
						"reason": "invalid_totp_code",
					}),
				})
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid mfa code"})
				return
			}
			// Burn the step so an observed code can't be replayed within the
			// ±1 skew window (RFC 6238 §5.2).
			consumed, cerr := store.ConsumeMFAStep(c.Request.Context(), userTenant, userID, step)
			if cerr != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "mfa verification failed"})
				return
			}
			if !consumed {
				recordFail()
				// A replayed code means the code was OBSERVED — shoulder-surfed,
				// phished, or captured. Distinct reason from a wrong code so
				// triage can tell the two apart.
				writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
					TenantID:    userTenant,
					ActorUserID: &userID,
					Action:      "user.mfa.verify",
					TargetKind:  "user",
					TargetID:    &userID,
					Diff: auditDiff(auditFailure, map[string]any{
						"email":  loginKey,
						"reason": "totp_code_replayed",
					}),
				})
				c.JSON(http.StatusUnauthorized, gin.H{"error": "mfa code already used"})
				return
			}
		}
	} else {
		// No user database. The built-in admin/admin123 backdoor exists only for
		// local development and must be explicitly enabled — otherwise a
		// misconfigured prod node (DB unreachable at boot) would expose a known
		// credential. Off by default; opt in with SENTINEL_DEV_LOGIN=1.
		if !devLoginEnabled() {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "authentication unavailable: no user database configured",
			})
			return
		}
		if req.Email != "admin@sentinel.local" || req.Password != "admin123" {
			recordFail()
			writeAuditEntry(c, nil, hub, &db.WriteAuditRequest{
				TenantID:   db.DevTenantID,
				Action:     "user.login",
				TargetKind: "user",
				Diff: auditDiff(auditFailure, map[string]any{
					"email":  loginKey,
					"reason": "invalid_credentials",
				}),
			})
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid email or password"})
			return
		}
		claims = auth.Claims{
			TenantID:   db.DevTenantID,
			UserID:     db.DevAdminID,
			Role:       "admin",
			AuthMethod: "password",
		}
	}

	loginAttempts.recordSuccess(loginKey)

	// Stamp the sign-in. Best-effort: a failure here must not cost the user
	// their session, since the login itself has already succeeded and the audit
	// entry below is the record that matters. But it is LOGGED rather than
	// dropped — a column that silently stops updating is how this one came to
	// read "Never" for every account since the first migration.
	//
	// Skipped for the no-store dev backdoor, which has no row to stamp.
	if store != nil {
		if err := store.MarkLogin(c.Request.Context(), claims.TenantID, claims.UserID); err != nil {
			log.Warn("could not stamp last login",
				zap.String("user_id", claims.UserID), zap.Error(err))
		}
	}

	pair, err := jwtSvc.IssueTokenPair(claims)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue token"})
		return
	}

	// Write successful login audit entry (scoped to the user's real tenant).
	userID := claims.UserID
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &userID,
		Action:      "user.login",
		TargetKind:  "user",
		TargetID:    &userID,
		// Stated, not implied. A reader filtering `diff->>'result'` must get
		// every login, not only the failures.
		Diff: auditDiff(loginResult, map[string]any{
			"email":       loginKey,
			"auth_method": claims.AuthMethod,
			"mfa":         claims.AuthMethod == "password" && req.MFACode != "",
		}),
	})

	c.JSON(http.StatusOK, gin.H{
		"access_token":  pair.AccessToken,
		"refresh_token": pair.RefreshToken,
		"expires_in":    pair.ExpiresIn,
		"token_type":    pair.TokenType,
		"user": gin.H{
			"id":    claims.UserID,
			"email": req.Email,
			"role":  claims.Role,
		},
	})
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

func handleRefresh(c *gin.Context, jwtSvc *auth.JWTService, store *db.Store) {
	var req refreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": clientError(err)})
		return
	}
	claims, err := jwtSvc.Validate(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}
	if claims.AuthMethod != "refresh" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not a refresh token"})
		return
	}
	// Re-derive privileges from the database rather than trusting the refresh
	// token's frozen claims: if the user was disabled, deleted, or had their
	// role changed, that must take effect on the next refresh (bounding stale
	// access to one access-token lifetime) instead of persisting for the full
	// refresh window. Skipped only in degraded/no-DB mode (dev/mock).
	if store != nil {
		role, _, rerr := store.RefreshUser(c.Request.Context(), claims.TenantID, claims.UserID)
		if rerr != nil {
			if errors.Is(rerr, db.ErrUserInactive) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "session no longer valid"})
				return
			}
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "cannot verify session"})
			return
		}
		claims.Role = role

		// Session cut-off, read from the database rather than the in-process
		// cache. The refresh token lives for days against the access token's
		// minutes, so it is the credential a password reset most needs to kill —
		// and checking it here makes "signed out everywhere" true on every node
		// immediately, without waiting for cache propagation.
		if cutoff, cerr := store.SessionCutoff(c.Request.Context(), claims.TenantID, claims.UserID); cerr == nil {
			if !cutoff.IsZero() && claims.IssuedAt != nil &&
				claims.IssuedAt.Time.Before(cutoff.Truncate(time.Second)) {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error": "session ended by a password change — please sign in again",
				})
				return
			}
		}
	}
	claims.AuthMethod = "refresh_rotation"
	accessToken, err := jwtSvc.IssueAccessToken(*claims)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"access_token": accessToken, "token_type": "Bearer"})
}

// handleLogout revokes the caller's current access token (and, if supplied, the
// refresh token) by adding their jti to the shared denylist — so the session is
// dead across the whole HA cluster, not just this node. Mounted on the
// authenticated (protected) group so the access-token claims are available.
func handleLogout(c *gin.Context, jwtSvc *auth.JWTService, store *db.Store, hub *logs.Hub) {
	claims, ok := auth.GetClaims(c.Request.Context())
	if !ok || claims == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	// Revoke the current access token.
	if claims.ID != "" && claims.ExpiresAt != nil {
		if err := store.RevokeToken(c.Request.Context(), claims.ID, claims.ExpiresAt.Time); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "logout failed"})
			return
		}
	}
	// Revoke the PAIRED refresh token server-side using the rjti embedded in the
	// access token — so logout kills the session without the client having to
	// resend the refresh token. Retain the denylist entry past the refresh TTL.
	if claims.RefreshJTI != "" {
		_ = store.RevokeToken(c.Request.Context(), claims.RefreshJTI, time.Now().Add(jwtSvc.RefreshTTL()))
	}
	// Best-effort: also honor an explicitly-supplied refresh token (older tokens
	// issued before rjti binding, or belt-and-suspenders).
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := c.ShouldBindJSON(&body); err == nil && body.RefreshToken != "" {
		if rc, err := jwtSvc.Validate(body.RefreshToken); err == nil && rc.ID != "" && rc.ExpiresAt != nil {
			_ = store.RevokeToken(c.Request.Context(), rc.ID, rc.ExpiresAt.Time)
		}
	}
	// Sessions ended with no record at all: the audit trail showed logins and
	// never the logouts, so a session's span could not be reconstructed and an
	// account still "logged in" from the log's point of view might have been
	// closed hours earlier. Cheap to record and needed to bound an incident.
	logoutUser := claims.UserID
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &logoutUser,
		Action:      "user.logout",
		TargetKind:  "user",
		TargetID:    &logoutUser,
		Diff:        auditDiff(auditSuccess, nil),
	})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// handleMFAEnroll generates a new TOTP secret + provisioning URI for the caller.
// The secret is returned but NOT stored yet — the user must prove a working code
// via /auth/mfa/confirm before MFA is activated (so a mistyped QR can't lock
// them out).
func handleMFAEnroll(c *gin.Context) {
	claims, ok := auth.GetClaims(c.Request.Context())
	if !ok || claims == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}
	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"secret":      secret,
		"otpauth_uri": auth.TOTPURI(version.Name, claims.UserID, secret),
		"note":        "Add to an authenticator app, then POST {secret, code} to /auth/mfa/confirm to activate.",
	})
}

// handleMFAConfirm activates MFA once the user proves a working code.
func handleMFAConfirm(c *gin.Context, store *db.Store) {
	claims, ok := auth.GetClaims(c.Request.Context())
	if !ok || claims == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	// Step-up: refuse to overwrite an already-enrolled secret via confirm. To
	// rotate MFA the user must first disable it (which requires a CURRENT code),
	// so a stolen access token cannot silently replace the second factor and
	// lock the real user out.
	if cur, cerr := store.GetMFASecret(c.Request.Context(), claims.TenantID, claims.UserID); cerr == nil && cur != "" {
		c.JSON(http.StatusConflict, gin.H{"error": "mfa already enabled; disable it first (requires a current code)"})
		return
	}
	var req struct {
		Secret string `json:"secret" binding:"required"`
		Code   string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": clientError(err)})
		return
	}
	if !auth.VerifyTOTP(req.Secret, req.Code) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid code"})
		return
	}
	if err := store.SetMFASecret(c.Request.Context(), claims.TenantID, claims.UserID, req.Secret); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "mfa_enabled": true})
}

// handleMFADisable turns MFA off after verifying a current code.
func handleMFADisable(c *gin.Context, store *db.Store) {
	claims, ok := auth.GetClaims(c.Request.Context())
	if !ok || claims == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": clientError(err)})
		return
	}
	secret, err := store.GetMFASecret(c.Request.Context(), claims.TenantID, claims.UserID)
	if err != nil || secret == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "mfa not enabled"})
		return
	}
	if !auth.VerifyTOTP(secret, req.Code) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid code"})
		return
	}
	if err := store.SetMFASecret(c.Request.Context(), claims.TenantID, claims.UserID, ""); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "mfa_enabled": false})
}

// oidcStateCookie holds the per-login CSRF state that binds the /login redirect
// to its /callback.
const oidcStateCookie = "sentinel_oidc_state"

// oidcNonceCookie holds the per-login OIDC nonce so the callback can verify that
// the returned id_token was minted for THIS authorization request.
//
// The nonce used to be generated and sent upstream but never persisted, so
// nothing could compare it on the way back — it was write-only, and
// authorization-code replay was undetectable. Storing it browser-side in an
// HttpOnly cookie mirrors how `state` is already handled.
const oidcNonceCookie = "sentinel_oidc_nonce"

// oidcConfigFromEnv builds the OIDC config from server-side environment ONLY.
//
// The issuer is never taken from a request parameter: previously both handlers
// read `?provider=`, so an unauthenticated attacker could point the callback at
// their own IdP and receive a valid editor token. OIDC is now opt-in — disabled
// unless an HTTPS issuer and a client secret are configured — and the issuer is
// pinned here, so the exchange can only ever talk to the operator's provider.
func oidcConfigFromEnv() (auth.OIDCConfig, bool) {
	issuer := strings.TrimSpace(os.Getenv("SENTINEL_OIDC_ISSUER"))
	secret := os.Getenv("SENTINEL_OIDC_CLIENT_SECRET")
	// Fail closed when not explicitly configured, and only trust an HTTPS
	// issuer (blocks MITM and SSRF to plaintext/internal endpoints).
	if issuer == "" || secret == "" || !strings.HasPrefix(issuer, "https://") {
		return auth.OIDCConfig{}, false
	}
	cfg := auth.OIDCConfig{
		ProviderURL:  issuer,
		ClientID:     osGetenv("SENTINEL_OIDC_CLIENT_ID", "sentinel"),
		ClientSecret: secret,
		RedirectURL:  osGetenv("SENTINEL_OIDC_REDIRECT_URL", "http://localhost:9501/api/v1/auth/oidc/callback"),
	}
	if doms := strings.TrimSpace(os.Getenv("SENTINEL_OIDC_ALLOWED_DOMAINS")); doms != "" {
		for _, d := range strings.Split(doms, ",") {
			if d = strings.TrimSpace(d); d != "" {
				cfg.AllowedDomains = append(cfg.AllowedDomains, d)
			}
		}
	}
	return cfg, true
}

// handleOIDCStatus reports whether OIDC single sign-on is usable on this
// deployment. It exists so the login page can show an SSO button only when
// pressing it would work.
//
// It was added because the login page shipped a button reading "Sign in with
// SAML / LDAP" whose onClick was the ordinary password handler. Neither SAML nor
// LDAP exists anywhere in this control plane, while OIDC — which does — had no
// button at all. A security product advertising an authentication method it does
// not implement is worse than one that offers fewer.
//
// Returns only a boolean. Never the issuer, client id, secret or redirect URL:
// those would tell an unauthenticated caller which identity provider to attack.
func handleOIDCStatus(c *gin.Context) {
	_, ok := oidcConfigFromEnv()
	c.JSON(http.StatusOK, gin.H{"configured": ok})
}

func handleOIDCLogin(c *gin.Context, jwtSvc *auth.JWTService, log *zap.Logger) {
	cfg, ok := oidcConfigFromEnv()
	if !ok {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "OIDC login is not configured"})
		return
	}
	oidcSvc := auth.NewOIDCService(cfg)
	state, err := auth.NewState()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start login"})
		return
	}
	nonce, err := auth.NewNonce()
	if err != nil {
		// Fail the login rather than proceeding with an empty nonce: the callback
		// now requires one, and a blank value would make the replay check
		// vacuous.
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start login"})
		return
	}
	authURL, err := oidcSvc.AuthURL(c.Request.Context(), state, nonce)
	if err != nil {
		log.Error("oidc auth url", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build auth URL"})
		return
	}
	// Bind `state` and `nonce` to the browser via short-lived HttpOnly cookies so
	// the callback can verify both (CSRF / login-fixation, and id_token replay).
	// SameSite=Lax lets them ride the top-level redirect back from the IdP.
	secure := strings.HasPrefix(cfg.RedirectURL, "https://")
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(oidcStateCookie, state, 300, "/", "", secure, true)
	c.SetCookie(oidcNonceCookie, nonce, 300, "/", "", secure, true)
	c.Redirect(http.StatusFound, authURL)
}

func handleOIDCCallback(c *gin.Context, jwtSvc *auth.JWTService, store *db.Store, log *zap.Logger) {
	cfg, ok := oidcConfigFromEnv()
	if !ok {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "OIDC login is not configured"})
		return
	}
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing code"})
		return
	}
	// Verify the state parameter against the cookie set when the login started.
	// Combined with the server-pinned issuer, this is what makes the callback
	// un-forgeable: no valid cookie + matching state, no token.
	wantState, err := c.Cookie(oidcStateCookie)
	if err != nil || wantState == "" ||
		subtle.ConstantTimeCompare([]byte(wantState), []byte(c.Query("state"))) != 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or missing OIDC state"})
		return
	}
	// Recover the nonce minted for this login so the id_token can be bound to it.
	// Absent cookie => this callback does not correspond to a login we started.
	wantNonce, err := c.Cookie(oidcNonceCookie)
	if err != nil || wantNonce == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or missing OIDC nonce"})
		return
	}

	// One-time use: clear both cookies immediately.
	secure := strings.HasPrefix(cfg.RedirectURL, "https://")
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(oidcStateCookie, "", -1, "/", "", secure, true)
	c.SetCookie(oidcNonceCookie, "", -1, "/", "", secure, true)

	oidcSvc := auth.NewOIDCService(cfg)
	userInfo, err := oidcSvc.ExchangeToken(c.Request.Context(), code, wantNonce)
	if err != nil {
		log.Error("oidc exchange", zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "OIDC token exchange failed"})
		return
	}
	// Map the verified identity to a REAL provisioned user (its tenant + role),
	// instead of minting a fixed dev-tenant editor for anyone who can complete
	// the OIDC exchange. Unknown identities are rejected — an admin must
	// provision the user first.
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "user database unavailable"})
		return
	}
	userID, tenantID, role, err := store.LookupSSOUser(c.Request.Context(), userInfo.Email)
	if err != nil {
		log.Warn("oidc login for unprovisioned identity", zap.String("email", userInfo.Email))
		c.JSON(http.StatusForbidden, gin.H{"error": "no account for this identity — ask an admin to provision your user"})
		return
	}
	claims := auth.Claims{
		TenantID:   tenantID,
		UserID:     userID,
		Role:       role,
		AuthMethod: "oidc",
	}
	pair, err := jwtSvc.IssueTokenPair(claims)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue token"})
		return
	}
	c.JSON(http.StatusOK, pair)
}

// ---------------------------------------------------------------------------
// Dashboard stats
// ---------------------------------------------------------------------------

func handleDashboardStats(c *gin.Context, enf *rbac.Enforcer, store *db.Store) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceSite, rbac.ActionRead) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}

	if store != nil {
		stats, err := store.GetDashboardStats(c.Request.Context(), claims.TenantID, claims.UserID)
		if err == nil {
			c.JSON(http.StatusOK, gin.H{"tenant_id": claims.TenantID, "stats": stats})
			return
		}
	}

	// Fallback mock
	c.JSON(http.StatusOK, gin.H{
		"tenant_id": claims.TenantID,
		"stats": gin.H{
			"total_sites": 5, "active_sites": 4, "total_rules": 341,
			"enabled_rules": 339, "open_alerts": 5, "critical_alerts": 2,
		},
	})
}

// ---------------------------------------------------------------------------
// Sites
// ---------------------------------------------------------------------------

func handleListSites(c *gin.Context, enf *rbac.Enforcer, store *db.Store) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceSite, rbac.ActionList) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	// A site list MUST come from the database or fail loudly.
	//
	// This handler used to answer a database outage with five hardcoded sites
	// (dvwa.local, juice.local, api.acme.com, shop.corp.io, legacy.app.net),
	// three of them marked "active"/"blocking", returned as 200 OK with the
	// caller's real tenant_id stamped on them. The client had no way to tell
	// them from real data, so an operator during a Postgres outage would see
	// applications they do not own and believe traffic was being filtered for
	// them. The underlying error was discarded rather than logged.
	//
	// Every other site handler here already returns 503 on store failure;
	// this one now matches. Never invent rows to keep a screen populated.
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	sites, err := store.ListSites(c.Request.Context(), claims.TenantID, claims.UserID)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	if sites == nil {
		sites = []db.SiteRow{}
	}
	c.JSON(http.StatusOK, gin.H{"sites": sites, "tenant_id": claims.TenantID})
}

func handleCreateSite(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *leader.Elector) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceSite, rbac.ActionCreate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	var req db.CreateSiteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": clientError(err)})
		return
	}
	if req.Upstream == nil {
		req.Upstream = json.RawMessage(`{"servers":[],"lb":"round_robin"}`)
	}
	if req.WafPolicy == nil {
		req.WafPolicy = json.RawMessage(defaultWafPolicyJSON)
	}
	// Validate BEFORE committing. An unconvertible site used to be accepted here
	// and then silently dropped by the data-plane config sync, leaving the site
	// unprotected while the dashboard still showed it active.
	if problems := append(
		validateSiteConfig(req.Name, req.Domains, req.Upstream, req.WafPolicy),
		validateSitePluginNames(c, store, claims.TenantID, claims.UserID, req.WafPolicy)...,
	); len(problems) > 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":    "site configuration is not usable by the data plane",
			"problems": problems,
		})
		return
	}
	// Reject a hostname another site already claims. The data plane routes by
	// Host header alone, so two sites claiming one domain BOTH match and the
	// policy that applies depends on which node loaded last — silently.
	if existing, lerr := store.ListSites(c.Request.Context(), claims.TenantID, claims.UserID); lerr == nil {
		if conflicts := domainConflicts(existing, req.Domains, ""); len(conflicts) > 0 {
			c.JSON(http.StatusConflict, gin.H{
				"error":    "one or more domains are already served by another site",
				"problems": conflicts,
			})
			return
		}
	} else {
		// Refuse rather than skip the check: creating a colliding site is worse
		// than failing to create one, and a silent skip would make the guard
		// disappear exactly when the database is unhealthy.
		zap.L().Warn("site create: could not read existing sites for domain-conflict check",
			zap.Error(lerr))
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "cannot verify domain uniqueness right now — site not created",
		})
		return
	}
	if !requireLeader(c, cl) {
		return
	}
	site, err := store.CreateSite(c.Request.Context(), claims.TenantID, claims.UserID, req)
	if err != nil {
		// A duplicate site NAME used to surface as 500 with the raw Postgres
		// text ("duplicate key value violates unique constraint ..."), which
		// reads as a server fault rather than "pick another name" — and
		// first-site.sh derives the name from the domain, so re-running it hit
		// this every time.
		respondStoreError(c, err)
		return
	}
	configVersion.Add(1)
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &claims.UserID,
		Action:      "site.create",
		TargetKind:  "site",
		TargetID:    &site.ID,
		// The posture a site is BORN with is as security-relevant as any later
		// change — a site created directly in blocking mode, or at a threshold
		// nobody benchmarked, is a decision worth being able to trace.
		Diff: auditDiff(auditSuccess, map[string]any{"created": siteEnforcementFacts(site)}),
	})
	c.JSON(http.StatusCreated, gin.H{"site": site})
}

func handleGetSite(c *gin.Context, enf *rbac.Enforcer, store *db.Store) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceSite, rbac.ActionRead) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	siteID := c.Param("id")
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	site, err := store.GetSite(c.Request.Context(), claims.TenantID, siteID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "site not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"site": site})
}

// siteEnforcementFacts pulls the fields that decide whether, and how hard, a
// site is protected: enforcement mode, lifecycle status, anomaly threshold and
// paranoia level. These are the settings whose change an auditor actually needs
// to see — "site X was updated" cannot distinguish a renamed label from
// protection being switched off.
func siteEnforcementFacts(row *db.SiteRow) map[string]any {
	if row == nil {
		return nil
	}
	out := map[string]any{"status": row.Status, "name": row.Name}
	var policy struct {
		Mode             *string `json:"mode"`
		AnomalyThreshold *int    `json:"anomaly_threshold"`
		ParanoiaLevel    *int    `json:"paranoia_level"`
	}
	if len(row.WafPolicy) > 0 && json.Unmarshal(row.WafPolicy, &policy) == nil {
		if policy.Mode != nil {
			out["mode"] = *policy.Mode
		}
		if policy.AnomalyThreshold != nil {
			out["anomaly_threshold"] = *policy.AnomalyThreshold
		}
		if policy.ParanoiaLevel != nil {
			out["paranoia_level"] = *policy.ParanoiaLevel
		}
	}
	return out
}

// siteChangeDiff renders a before/after pair, keeping ONLY the fields that
// actually changed so the diff reads as a change record rather than a snapshot.
// Returns a diff carrying just the outcome when nothing material moved (a
// domain or upstream edit, say) — the mutation is still recorded, it simply had
// no enforcement effect worth highlighting.
func siteChangeDiff(before, after *db.SiteRow) json.RawMessage {
	b, a := siteEnforcementFacts(before), siteEnforcementFacts(after)
	changed := map[string]any{}
	for k, av := range a {
		bv, had := b[k]
		if !had || fmt.Sprint(bv) != fmt.Sprint(av) {
			changed[k] = map[string]any{"from": bv, "to": av}
		}
	}
	if len(changed) == 0 {
		return auditDiff(auditSuccess, nil)
	}
	return auditDiff(auditSuccess, map[string]any{"changed": changed})
}

func handleUpdateSite(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *leader.Elector, log *zap.Logger) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceSite, rbac.ActionUpdate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	siteID := c.Param("id")
	var req db.UpdateSiteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": clientError(err)})
		return
	}
	// Validate the MERGED result, not just the submitted fields: a patch can be
	// individually fine yet produce an unusable site when combined with what is
	// already stored (e.g. replacing a good upstream with an empty one).
	cur, curErr := store.GetSite(c.Request.Context(), claims.TenantID, siteID)
	if curErr != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "site not found"})
		return
	}
	name, domains, upstream, waf := mergedSiteForValidation(*cur, req)
	if problems := append(
		validateSiteConfig(name, domains, upstream, waf),
		validateSitePluginNames(c, store, claims.TenantID, claims.UserID, waf)...,
	); len(problems) > 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":    "the resulting site configuration is not usable by the data plane",
			"problems": problems,
		})
		return
	}
	// Same collision check as create, excluding this site's own domains.
	if len(req.Domains) > 0 {
		if existing, lerr := store.ListSites(c.Request.Context(), claims.TenantID, claims.UserID); lerr == nil {
			if conflicts := domainConflicts(existing, req.Domains, siteID); len(conflicts) > 0 {
				c.JSON(http.StatusConflict, gin.H{
					"error":    "one or more domains are already served by another site",
					"problems": conflicts,
				})
				return
			}
		} else {
			zap.L().Warn("site update: could not read existing sites for domain-conflict check",
				zap.Error(lerr))
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "cannot verify domain uniqueness right now — site not updated",
			})
			return
		}
	}
	if !requireLeader(c, cl) {
		return
	}
	// Record an undo point before changing live protection settings.
	snapshotBeforeMutation(c, store, log, "site.update")
	site, err := store.UpdateSite(c.Request.Context(), claims.TenantID, claims.UserID, siteID, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
		return
	}
	configVersion.Add(1)
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &claims.UserID,
		Action:      "site.update",
		TargetKind:  "site",
		TargetID:    &siteID,
		// `cur` was already read above to validate the merged result, so a real
		// before/after costs nothing. Without it, flipping a site from blocking
		// to off — disabling protection outright — recorded only THAT the site
		// was updated.
		Diff: siteChangeDiff(cur, site),
	})
	c.JSON(http.StatusOK, gin.H{"site": site})
}

// handleValidateSite is the dry-run endpoint: it reports whether a proposed site
// configuration would be accepted and usable, without writing anything.
//
// This exists so an operator (or Config-as-Code pipeline) can check a change
// before applying it, instead of discovering at sync time that a site quietly
// stopped being protected.
func handleValidateSite(c *gin.Context, enf *rbac.Enforcer, store *db.Store) {
	claims, _ := auth.GetClaims(c.Request.Context())
	// Dry-run mutates nothing, but it reveals whether a config is viable, so gate
	// it on the same permission as the write it previews.
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceSite, rbac.ActionUpdate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}

	var req struct {
		// SiteID, when set, validates a PATCH against the stored site.
		SiteID    string          `json:"site_id"`
		Name      string          `json:"name"`
		Domains   []string        `json:"domains"`
		Upstream  json.RawMessage `json:"upstream"`
		WafPolicy json.RawMessage `json:"waf_policy"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": clientError(err)})
		return
	}

	name, domains, upstream, waf := req.Name, req.Domains, req.Upstream, req.WafPolicy
	if req.SiteID != "" {
		if store == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
			return
		}
		cur, err := store.GetSite(c.Request.Context(), claims.TenantID, req.SiteID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "site not found"})
			return
		}
		patch := db.UpdateSiteRequest{Domains: req.Domains, Upstream: req.Upstream, WafPolicy: req.WafPolicy}
		if req.Name != "" {
			patch.Name = &req.Name
		}
		name, domains, upstream, waf = mergedSiteForValidation(*cur, patch)
	}

	problems := append(
		validateSiteConfig(name, domains, upstream, waf),
		validateSitePluginNames(c, store, claims.TenantID, claims.UserID, waf)...,
	)
	// The same domain-ownership check create and update make. Without it the
	// wizard's dry-run said a site claiming `juice` — owned by another site — was
	// fine, and the save then failed with a 409 the operator had just been told
	// would not happen.
	if store != nil {
		if existing, lerr := store.ListSites(c.Request.Context(), claims.TenantID, claims.UserID); lerr == nil {
			problems = append(problems, domainConflicts(existing, domains, req.SiteID)...)
		}
	}
	// 200 either way: the dry-run itself succeeded. `valid` carries the verdict, so
	// a client cannot mistake "your config is bad" for "the request failed".
	c.JSON(http.StatusOK, gin.H{
		"valid":    len(problems) == 0,
		"problems": problems,
		"resolved": gin.H{"name": name, "domains": domains},
	})
}

func handleDeleteSite(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *leader.Elector, log *zap.Logger) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceSite, rbac.ActionDelete) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	siteID := c.Param("id")
	if !requireLeader(c, cl) {
		return
	}
	// Read what is about to disappear. After the delete this is unrecoverable
	// from the row itself, so an audit entry naming only the site's UUID would
	// leave "which application stopped being protected, and how was it
	// configured?" answerable only from a database backup.
	doomed, _ := store.GetSite(c.Request.Context(), claims.TenantID, siteID)
	// Record an undo point before removing a site from protection.
	snapshotBeforeMutation(c, store, log, "site.delete")
	if err := store.DeleteSite(c.Request.Context(), claims.TenantID, siteID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
		return
	}
	configVersion.Add(1)
	delDiff := auditDiff(auditSuccess, nil)
	if doomed != nil {
		delDiff = auditDiff(auditSuccess, map[string]any{
			"deleted": siteEnforcementFacts(doomed),
			"domains": doomed.Domains,
		})
	}
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &claims.UserID,
		Action:      "site.delete",
		TargetKind:  "site",
		TargetID:    &siteID,
		Diff:        delDiff,
	})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func handleUpdateSiteStatus(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *leader.Elector) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceSite, rbac.ActionUpdate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	siteID := c.Param("id")
	var body struct {
		Status string `json:"status"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || (body.Status != "active" && body.Status != "paused") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status must be 'active' or 'paused'"})
		return
	}
	if !requireLeader(c, cl) {
		return
	}
	prior, _ := store.GetSite(c.Request.Context(), claims.TenantID, siteID)
	if err := store.UpdateSiteStatus(c.Request.Context(), claims.TenantID, siteID, body.Status); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
		return
	}
	configVersion.Add(1)
	statusFrom := any(nil)
	if prior != nil {
		statusFrom = prior.Status
	}
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &claims.UserID,
		Action:      "site.status." + body.Status,
		TargetKind:  "site",
		TargetID:    &siteID,
		// Pausing a site stops it being protected. The action name carried the
		// destination but not the origin, so a repeated pause and a real
		// transition were indistinguishable.
		Diff: auditDiff(auditSuccess, map[string]any{
			"changed": map[string]any{
				"status": map[string]any{"from": statusFrom, "to": body.Status},
			},
		}),
	})
	c.JSON(http.StatusOK, gin.H{"ok": true, "status": body.Status})
}

// ruleExclusionSpec mirrors the Rust RuleExclusion struct. Stored inside a
// site's waf_policy.rule_exclusions array and emitted verbatim to the data
// plane by buildRustWaf.
type ruleExclusionSpec struct {
	RuleID         int      `json:"rule_id"`
	ExcludeTargets []string `json:"exclude_targets,omitempty"`
	Disable        bool     `json:"disable,omitempty"`
}

// handleAddSiteExclusion adds (or updates) a rule exclusion on a site's
// waf_policy — the learning report's one-click tuning action. Body:
//
//	{ "rule_id": 942100, "disable": true }                       // drop the whole rule
//	{ "rule_id": 942100, "exclude_targets": ["ARGS:q"] }         // strip targets only
//
// Re-uses the standard site-update path so the change is proposed through the
// cluster, persisted, and hot-synced to the proxy via configVersion.
func handleAddSiteExclusion(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *leader.Elector) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceSite, rbac.ActionUpdate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	siteID := c.Param("id")
	var body ruleExclusionSpec
	if err := c.ShouldBindJSON(&body); err != nil || body.RuleID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "rule_id is required"})
		return
	}
	if msg := inspectionLimitExclusionProblem(body.RuleID); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}
	// Default to disabling the whole rule when no targets are given — the most
	// common learning-report action for a confirmed false positive.
	if len(body.ExcludeTargets) == 0 {
		body.Disable = true
	}

	site, err := store.GetSite(c.Request.Context(), claims.TenantID, siteID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "site not found"})
		return
	}
	waf, excl := parseExclusions(site.WafPolicy)

	// Upsert by rule_id.
	found := false
	for i := range excl {
		if excl[i].RuleID == body.RuleID {
			excl[i] = body
			found = true
			break
		}
	}
	if !found {
		excl = append(excl, body)
	}

	newPolicy, err := encodeExclusions(waf, excl)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
		return
	}
	req := db.UpdateSiteRequest{WafPolicy: newPolicy}
	if !requireLeader(c, cl) {
		return
	}
	updated, err := store.UpdateSite(c.Request.Context(), claims.TenantID, claims.UserID, siteID, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
		return
	}
	configVersion.Add(1)
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &claims.UserID,
		Action:      "site.exclusion.add.rule_" + strconv.Itoa(body.RuleID),
		TargetKind:  "site",
		TargetID:    &siteID,
	})
	c.JSON(http.StatusOK, gin.H{"site": updated, "rule_exclusions": excl})
}

// handleDeleteSiteExclusion removes the exclusion for a given rule_id from a
// site's waf_policy (undo a tuning action / re-enable a rule).
func handleDeleteSiteExclusion(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *leader.Elector) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceSite, rbac.ActionUpdate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	siteID := c.Param("id")
	ruleID, err := strconv.Atoi(c.Param("rule_id"))
	if err != nil || ruleID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rule_id"})
		return
	}
	site, err := store.GetSite(c.Request.Context(), claims.TenantID, siteID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "site not found"})
		return
	}
	waf, excl := parseExclusions(site.WafPolicy)
	kept := excl[:0]
	for _, e := range excl {
		if e.RuleID == ruleID {
			// 932236 is auto-injected by buildRustWaf; a plain removal would be
			// silently re-added. Leave an empty opt-out marker so the rule stays
			// fully enabled across rebuilds.
			if ruleID == 932236 {
				kept = append(kept, ruleExclusionSpec{RuleID: 932236})
			}
			continue
		}
		kept = append(kept, e)
	}
	newPolicy, err := encodeExclusions(waf, kept)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
		return
	}
	req := db.UpdateSiteRequest{WafPolicy: newPolicy}
	if !requireLeader(c, cl) {
		return
	}
	updated, err := store.UpdateSite(c.Request.Context(), claims.TenantID, claims.UserID, siteID, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
		return
	}
	configVersion.Add(1)
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &claims.UserID,
		Action:      "site.exclusion.remove.rule_" + strconv.Itoa(ruleID),
		TargetKind:  "site",
		TargetID:    &siteID,
	})
	c.JSON(http.StatusOK, gin.H{"site": updated, "rule_exclusions": kept})
}

// parseExclusions splits a waf_policy blob into the generic policy map (minus
// rule_exclusions) and the typed exclusion list. A nil/empty policy yields an
// empty map and nil slice.
func parseExclusions(raw json.RawMessage) (map[string]json.RawMessage, []ruleExclusionSpec) {
	waf := map[string]json.RawMessage{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &waf)
	}
	var excl []ruleExclusionSpec
	if rx, ok := waf["rule_exclusions"]; ok {
		_ = json.Unmarshal(rx, &excl)
	}
	delete(waf, "rule_exclusions")
	return waf, excl
}

// encodeExclusions reassembles a waf_policy blob with the given exclusion list.
func encodeExclusions(waf map[string]json.RawMessage, excl []ruleExclusionSpec) (json.RawMessage, error) {
	rx, err := json.Marshal(excl)
	if err != nil {
		return nil, err
	}
	waf["rule_exclusions"] = rx
	return json.Marshal(waf)
}

// internalSecretOK gates the unauthenticated-by-design internal endpoints with
// the shared secret (X-Sentinel-Internal == SENTINEL_INTERNAL_SECRET). When the
// secret is unset (co-located dev), it allows the call for backward-compat — the
// data-plane sync client likewise sends no header in that mode. Constant-time
// compare to avoid leaking the secret via timing.
func internalSecretOK(c *gin.Context) bool {
	secret := os.Getenv("SENTINEL_INTERNAL_SECRET")
	if secret == "" {
		// Fail closed. With no shared secret configured, only accept the
		// data-plane sync from a loopback peer (same host) — a remote caller on
		// the exposed REST port must not be able to read site topology. Set
		// SENTINEL_INTERNAL_SECRET when the data plane runs on another host or
		// in a separate container.
		host, _, err := net.SplitHostPort(c.Request.RemoteAddr)
		if err != nil {
			host = c.Request.RemoteAddr
		}
		ip := net.ParseIP(host)
		return ip != nil && ip.IsLoopback()
	}
	got := c.GetHeader("X-Sentinel-Internal")
	return subtle.ConstantTimeCompare([]byte(got), []byte(secret)) == 1
}

// handleInternalConfig is called by the Rust data-plane proxy to sync the active
// site list. It is gated by the shared internal secret (not JWT): exposing the
// REST port must not leak site topology (upstreams, rules) to anyone who can
// reach it. Returns the sites in a format the proxy deserializes into
// Vec<SiteConfig>.
// siteSetFingerprint derives a stable freshness signal from the site set itself.
//
// Used when the DB-derived config counter (migration 0012) is unavailable. FNV-1a
// over the canonical JSON encoding: encoding/json sorts map keys, so the same set
// of sites always hashes to the same value, and any real change — a new site, an
// edited upstream, a policy tweak — changes it. Masked to 63 bits so the value is
// always positive, since the data plane parses it as an unsigned version.
func siteSetFingerprint(sites []map[string]any) int64 {
	b, err := json.Marshal(sites)
	if err != nil {
		// Cannot hash what will not marshal. Return a constant rather than a
		// timestamp: a constant means "no detectable change", which is the safer
		// failure here — the alternative churns the rule engine forever.
		return 1
	}
	h := fnv.New64a()
	_, _ = h.Write(b)
	return int64(h.Sum64() & 0x7fffffffffffffff)
}

// The three reads a config sync is built from. Variables only so a test can
// fail or order them; production always uses the store.
var (
	syncConfigVersion = func(ctx context.Context, s *db.Store) (int64, error) { return s.ConfigVersion(ctx) }
	syncActiveSites   = func(ctx context.Context, s *db.Store) ([]db.SiteRow, error) { return s.ListAllActiveSites(ctx) }
	syncCustomRules   = func(ctx context.Context, s *db.Store) (map[string][]db.DeployableRule, error) {
		return s.ListDeployableRules(ctx)
	}
)

func handleInternalConfig(c *gin.Context, store *db.Store, log *zap.Logger) {
	if !internalSecretOK(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "db unavailable"})
		return
	}
	ctx := c.Request.Context()
	// The version is read BEFORE the content it labels. Read after it, a write
	// landing between the two reads labelled the older site list with the newer
	// version: every node cached it as current and never fetched that write
	// until some later edit. Read first, the content can only be newer than its
	// label, which costs one extra fetch on the next poll.
	version, verr := syncConfigVersion(ctx, store)
	// Node-global: the shared data plane serves EVERY tenant's sites, so this
	// sync must list all active sites across tenants (not one tenant's view).
	sites, err := syncActiveSites(ctx, store)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
		return
	}
	// Operator-authored rules, attached per site below. A sync without them is
	// refused rather than sent: it carried the real version, so every node
	// cached a config with NO custom rules — virtual patches included — as
	// current, and stayed that way after the read recovered, until some later
	// edit bumped the version. A refusal keeps each node on the config it has;
	// the next poll tries again.
	rulesByTenant, err := syncCustomRules(ctx, store)
	if err != nil {
		log.Error("CONFIG SYNC REFUSED: custom rules could not be read; nodes keep their "+
			"current config and retry on the next poll", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "custom rules could not be read; nodes keep their current config",
		})
		return
	}

	rustSites := make([]map[string]any, 0, len(sites))
	// Sites that cannot be converted are REPORTED, not silently skipped.
	//
	// This loop used to `continue` on error, so a site with malformed upstream or
	// waf_policy JSON simply vanished from the config the data plane received: no
	// error, no log, no alert. The dashboard still listed it as active while it was
	// no longer protected — a config error that failed open and was invisible.
	//
	// Writes are now validated (see validateSiteConfig), so new records cannot get
	// into this state. This remains the backstop for records written before that
	// validation existed, and it is deliberately noisy.
	skipped := make([]map[string]any, 0)
	for _, s := range sites {
		if s.Status == "paused" || s.Status == "deleted" {
			continue
		}
		// Surface silently-dropped policy keys here rather than at write time:
		// this is the point where the config is built FOR the data plane, so it
		// also covers sites stored before a key was added or removed.
		warnUnknownWafPolicyKeys(s.Name, s.WafPolicy, log)
		rs, err := siteRowToRustConfig(s)
		if err != nil {
			log.Error("CONFIG SYNC: site is UNPROTECTED — its stored configuration cannot be "+
				"converted for the data plane and is being excluded from the sync",
				zap.String("site", s.Name),
				zap.String("site_id", s.ID),
				zap.String("tenant_id", s.TenantID),
				zap.Error(err))
			skipped = append(skipped, map[string]any{
				"site_id":   s.ID,
				"name":      s.Name,
				"tenant_id": s.TenantID,
				"error":     err.Error(),
			})
			continue
		}
		attachInlineRules(rs, s.ID, rulesByTenant[s.TenantID])
		rustSites = append(rustSites, rs)
	}
	// Shared, DB-derived, restart-surviving freshness signal (migration 0012),
	// read above. On a read error (e.g. before the migration applies) fall back
	// to a content fingerprint.
	versionSource := "generation"
	if verr != nil {
		versionSource = "fingerprint"
		// The old fallback was time.Now().UnixNano(), reasoning that re-syncing beats
		// latching a stale version. That is right for a TRANSIENT read error and badly
		// wrong for a PERMANENT one: where migration 0012 has not been applied,
		// sentinel_config_version() does not exist, so EVERY poll returned a new
		// version and every data-plane node re-synced and rebuilt its entire rule
		// engine — measured at 1,268 rules every 5 seconds, indefinitely, on a
		// completely idle system.
		//
		// A content hash fixes both horns: it changes when, and only when, the site
		// set actually changes. Propagation stays correct, the churn stops, and it
		// needs nothing from the database.
		version = siteSetFingerprint(rustSites)
		log.Warn("config version unavailable — using a content hash of the site set "+
			"instead (apply migration 0012 for the shared DB-derived counter)",
			zap.Error(verr), zap.Int64("fingerprint", version))
	}
	resp := gin.H{
		"version": version,
		// "generation": the database's config counter, so a higher version is a
		// later state of the same database — what lets a node accept a sync
		// that removes every site. "fingerprint": a content hash, which has no
		// order.
		"version_source": versionSource,
		"sites":          rustSites,
	}
	// Surfaced in the response as well as the log, so the condition is observable
	// by the data plane and by anyone curling this endpoint — not just by whoever
	// happens to be reading control-plane logs.
	if len(skipped) > 0 {
		resp["skipped_sites"] = skipped
	}
	c.JSON(http.StatusOK, resp)
}

// handleProxyHealth probes the local WAF proxy's /healthz endpoint and
// returns a summary the dashboard can use for live status.
func handleProxyHealth(c *gin.Context) {
	client := &http.Client{Timeout: 3 * time.Second}
	// Probe the data plane at its configured base URL (SENTINEL_DATAPLANE_URL),
	// not a hardcoded port: prod/K8s bind :8080, only the dev config uses :9080.
	resp, err := client.Get(dataPlaneBaseURL() + "/healthz")
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"waf_running": false, "error": err.Error()})
		return
	}
	defer resp.Body.Close()

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		c.JSON(http.StatusOK, gin.H{"waf_running": true, "raw_status": "ok (unparseable)"})
		return
	}
	body["waf_running"] = true
	c.JSON(http.StatusOK, body)
}

// sentinelRuleFiles are OUR OWN rule files, loaded for every site whose mode is
// not "off", in addition to whichever CRS categories the operator selected.
//
// They are deliberately NOT entries in crsCategoryFiles: that map models "which
// class of attack do you want covered", and these files are not a class of attack.
// They are cross-cutting precision and visibility supplements that the measured
// configuration treats as baseline:
//
//   - placement.conf (9900100-9900101) runs libinjection across EVERY injection
//     point — arbitrary headers, any cookie, the URL path — which stock CRS does
//     not. Without it, custom-header XSS and header SQLi return 200.
//   - coverage.conf (9900200-9900215) covers the classes CRS 4.x measures near
//     zero on (CRLF, SMTP/IMAP, LDAP, SSTI, NoSQL) and, critically, carries the
//     t:base64Decode transform chains. 66 of 72 bypasses in the 2026-07-19
//     analysis were Base64-encoded: on the wire a Base64 payload is opaque, so
//     rules go blind and no amount of category selection helps.
//
// These 18 rules are what took App-TP from 80.30% to 99.09%; the published
// composite of 99.60% is not achievable without them. deploy/load-test/
// waf-detection.yaml lists them explicitly, but nothing generated BY THE CONTROL
// PLANE could load them, so every site created through the API or dashboard ran
// stock CRS only — confirmed on the deploy VM, where no 99xxxxx rule had fired
// once across the entire waf_events history.
var sentinelRuleFiles = []string{
	"rules/custom/placement.conf",
	"rules/custom/coverage.conf",
}

// crsCategoryFiles maps the UI-friendly OWASP CRS category keys exposed in the
// dashboard to the underlying .conf rule files shipped with the proxy. Keeping
// this map here lets operators toggle protection categories per-site from the
// UI while the data plane keeps loading concrete files.
var crsCategoryFiles = map[string]string{
	"method":          "rules/owasp-crs/rules/REQUEST-911-METHOD-ENFORCEMENT.conf",
	"scanner":         "rules/owasp-crs/rules/REQUEST-913-SCANNER-DETECTION.conf",
	"protocol":        "rules/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
	"protocol_attack": "rules/owasp-crs/rules/REQUEST-921-PROTOCOL-ATTACK.conf",
	"lfi":             "rules/owasp-crs/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf",
	"rfi":             "rules/owasp-crs/rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf",
	"rce":             "rules/owasp-crs/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf",
	"php":             "rules/owasp-crs/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf",
	"generic":         "rules/owasp-crs/rules/REQUEST-934-APPLICATION-ATTACK-GENERIC.conf",
	"xss":             "rules/owasp-crs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf",
	"sqli":            "rules/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
	"session":         "rules/owasp-crs/rules/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf",
	"java":            "rules/owasp-crs/rules/REQUEST-944-APPLICATION-ATTACK-JAVA.conf",
	// Multipart body-part header attacks. This file sat in crsUnwiredFiles until
	// 2026-08-21 for a reason that no longer holds: every one of its SecRules
	// targets MULTIPART_PART_HEADERS, which the engine did not implement, so it
	// imported ZERO rules and a toggle would have advertised protection that
	// detected nothing. That target — and regex capture, which two of the rules
	// chain on — now exist, so all four import.
	//
	// Default-on with the other request families, but with one carve-out. 922120
	// (deprecated Content-Transfer-Encoding) and 922130 (out-of-range bytes in a
	// part header name) CONTRIBUTE +5 to the anomaly score, so neither can block
	// on its own against a threshold of 10 — measured clean against ordinary
	// uploads.
	//
	// 922110 is different and is DISABLED BY DEFAULT in defaultRuleExclusions: it
	// carries `block` on its chain starter, so it hard-blocks a single match with
	// no threshold to moderate it, and CRS's allowed-charset list holds only four
	// entries. Measured: us-ascii, utf-16, shift_jis and euc-kr are all blocked
	// outright. See the exclusion entry for the reasoning and how to enable it.
	"multipart": "rules/owasp-crs/rules/REQUEST-922-MULTIPART-ATTACK.conf",

	// RESPONSE-* families. The image has always shipped these files and the data
	// plane has always been able to run them — phase1_headers seeds
	// DETECTION_PARANOIA_LEVEL, the response path buffers scannable bodies up to
	// RESPONSE_SCAN_CAP and calls evaluate(Phase::ResponseBody) — but nothing in
	// the control plane could NAME them, so no site configuration could reach
	// them. 108 importable rules of data-leakage and web-shell detection were
	// shipped, compiled and unreachable.
	//
	// They are opt-in (see crsResponseCategories) because unlike the request
	// families they are NOT free: enabling one makes the proxy buffer every
	// HTML, plain-text and XML response for that site, and the response is
	// judged on its own outbound score against CRS's outbound threshold (4, or
	// the site's crs_policy outbound_anomaly_score_threshold) — so a single
	// critical leak blocks on its own. (These rules were long described here
	// as carrying `block` directly; they carry `block` plus an outbound-score
	// setvar, which the importer used to drop, compiling them to hard blocks.)
	"leak_generic": "rules/owasp-crs/rules/RESPONSE-950-DATA-LEAKAGES.conf",
	"leak_sql":     "rules/owasp-crs/rules/RESPONSE-951-DATA-LEAKAGES-SQL.conf",
	"leak_java":    "rules/owasp-crs/rules/RESPONSE-952-DATA-LEAKAGES-JAVA.conf",
	"leak_php":     "rules/owasp-crs/rules/RESPONSE-953-DATA-LEAKAGES-PHP.conf",
	"leak_iis":     "rules/owasp-crs/rules/RESPONSE-954-DATA-LEAKAGES-IIS.conf",
	"web_shells":   "rules/owasp-crs/rules/RESPONSE-955-WEB-SHELLS.conf",
}

// crsResponseCategories are the response-body families. Membership here means
// "never enabled implicitly": crsFilesForCategories omits them when a site names
// no categories at all, so the thousands of existing sites whose stored policy
// predates these keys keep byte-identical behaviour instead of silently
// acquiring response buffering and single-match response blocking.
var crsResponseCategories = map[string]bool{
	"leak_generic": true,
	"leak_sql":     true,
	"leak_java":    true,
	"leak_php":     true,
	"leak_iis":     true,
	"web_shells":   true,
}

// crsUnwiredFiles records the CRS files this product ships but deliberately does
// NOT offer, so that "why is RESPONSE-959 not in the map?" has an answer in the
// code rather than in someone's memory. Each entry is a decision, not an
// oversight, and crs_wiring_test.go asserts this list stays exhaustive.
//
//	REQUEST-901-INITIALIZATION   26 rules. Seeds tx.* constants the VM already
//	    resolves natively. Loading it would ALSO set
//	    tx.inbound_anomaly_score_threshold=5 and tx.blocking_paranoia_level=1,
//	    fighting the site's own tuned threshold (default 10) and paranoia level
//	    (default 2). The 10-not-5 choice is what measured TN 99.29%.
//	REQUEST-949 / RESPONSE-959   26 rules each. CRS's anomaly-mode blocking
//	    evaluators. Redundant: the importer maps every
//	    tx.inbound_anomaly_score_plN and tx.outbound_anomaly_score_plN delta
//	    straight onto the rule's score, so the VM accumulates both totals itself
//	    and blocks against the site's anomaly_threshold (request) and the
//	    outbound threshold (response). Loading these would add a SECOND deny
//	    path at CRS's defaults (inbound 5, outbound 4) beside the tuned one.
//	RESPONSE-980-CORRELATION     19 rules. Reports on the
//	    blocking_/detection_ aggregates that only 949/959 produce.
//	REQUEST-905-COMMON-EXCEPTIONS 2 importable rules, both Apache-pinger
//	    exceptions whose payload is ctl:ruleRemoveByTag=OWASP_CRS. `ctl:` is an
//	    explicit no-op in the importer, so they are inert today — zero benefit,
//	    and a loopback-shaped hole the day ctl: is implemented.
var crsUnwiredFiles = []string{
	"rules/owasp-crs/rules/REQUEST-901-INITIALIZATION.conf",
	"rules/owasp-crs/rules/REQUEST-905-COMMON-EXCEPTIONS.conf",
	"rules/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf",
	"rules/owasp-crs/rules/RESPONSE-959-BLOCKING-EVALUATION.conf",
	"rules/owasp-crs/rules/RESPONSE-980-CORRELATION.conf",
}

// crsCategoryOrder is the canonical load order for the categories above.
// Response families sort last, matching CRS's own numbering. Ordering across
// phases is presentational rather than semantic — the compiler builds a separate
// instruction program per phase (ruleset.phase_programs), so a RESPONSE file
// listed before a REQUEST one cannot change evaluation — but keeping CRS order
// means a site's rule list reads the way the upstream project documents it.
var crsCategoryOrder = []string{
	"method", "scanner", "protocol", "protocol_attack", "multipart", "lfi",
	"rfi", "rce", "php", "generic", "xss", "sqli", "session", "java",
	"leak_generic", "leak_sql", "leak_java", "leak_php", "leak_iis", "web_shells",
}

// crsFilesForCategories returns the concrete .conf files for a set of UI
// category keys, preserving canonical load order. An empty/nil selection means
// "all categories" so existing sites keep full protection.
func crsFilesForCategories(cats []string) []string {
	if len(cats) == 0 {
		// "All categories" means all REQUEST categories. Response families are
		// opt-in and must never arrive by default — a stored policy written
		// before these keys existed has to keep behaving exactly as it did.
		files := make([]string, 0, len(crsCategoryOrder))
		for _, k := range crsCategoryOrder {
			if crsResponseCategories[k] {
				continue
			}
			files = append(files, crsCategoryFiles[k])
		}
		return files
	}
	want := make(map[string]bool, len(cats))
	for _, c := range cats {
		want[c] = true
	}
	files := make([]string, 0, len(cats))
	for _, k := range crsCategoryOrder {
		if want[k] {
			files = append(files, crsCategoryFiles[k])
		}
	}
	return files
}

// siteRowToRustConfig converts a DB SiteRow into the JSON shape that the Rust
// SiteConfig serde deserializer expects. It is backward compatible with the
// legacy minimal blobs while passing through the full rich configuration that
// the dashboard now lets operators set per-site (multi-server upstreams with
// weights + per-server TLS, health checks, rate limiting, bot detection,
// anti-DDoS, GeoIP, ML, IP reputation, request limits and rule exclusions).
func siteRowToRustConfig(s db.SiteRow) (map[string]any, error) {
	upstream, err := buildRustUpstream(s.Upstream)
	if err != nil {
		return nil, err
	}
	waf, err := buildRustWaf(s.WafPolicy)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"id":        s.Name,     // proxy matches by site ID — use name (e.g., "dvwa.local")
		"tenant_id": s.TenantID, // propagated so per-request telemetry is tenant-scoped
		"domains":   s.Domains,
		"upstream":  upstream,
		"waf":       waf,
		"plugins":   []any{},
		// Per-site TLS intent (the dashboard nests it under waf_policy.tls) lifted
		// to the top-level Rust SiteConfig.tls, so the data plane honors per-site
		// cert mode (ACME auto-issuance/renewal, manual cert paths). Serving certs
		// by SNI works regardless of this; mode=acme additionally drives issuance.
		"tls": buildRustSiteTLS(s.WafPolicy),
	}, nil
}

// buildRustSiteTLS extracts the per-site TLS intent the dashboard nests under
// waf_policy.tls and converts it to the Rust SiteTlsConfig shape
// (mode: off | self_signed | manual | acme). Dashboard modes map as:
//
//	auto     -> acme (+ acme{email,provider,challenge}) — drives auto-issue/renew
//	manual   -> manual{cert,key} when the operator chose "path on WAF node";
//	            a pasted PEM is already in the cert repository (served by SNI) -> off
//	existing -> off (the chosen repo cert is served by SNI for the domain)
//	off / "" -> off
//
// It always returns a valid SiteTlsConfig so the config-sync never fails to parse.
func buildRustSiteTLS(raw json.RawMessage) map[string]any {
	off := map[string]any{"mode": "off"}
	if len(raw) == 0 {
		return off
	}
	var p struct {
		TLS *struct {
			Mode        string `json:"mode"`
			Email       string `json:"email"`
			Provider    string `json:"provider"`
			CaServer    string `json:"ca_server"`
			Challenge   string `json:"challenge"`
			Staging     bool   `json:"staging"`
			RenewBefore uint32 `json:"renew_before_days"`
			Custom      *struct {
				Priority string `json:"priority"`
				CertPath string `json:"cert_path"`
				KeyPath  string `json:"key_path"`
			} `json:"custom"`
		} `json:"tls"`
	}
	if err := json.Unmarshal(raw, &p); err != nil || p.TLS == nil {
		return off
	}
	t := p.TLS
	switch t.Mode {
	case "auto":
		if t.Email == "" {
			return off // ACME needs a contact email; nothing to do without one
		}
		acme := map[string]any{"email": t.Email}
		// The console's "staging" switch was read by nothing, so a test site's
		// orders went to the production CA and spent its rate limits.
		if t.Staging && (t.Provider == "" || rustAcmeProvider(t.Provider) == "lets_encrypt") {
			t.Provider = "letsencrypt_staging"
		}
		if prov := rustAcmeProvider(t.Provider); prov != "" {
			acme["provider"] = prov
		}
		// The console has offered "override ACME directory URL" all along and
		// this struct did not parse it, so the value was stored, echoed back to
		// the operator, and dropped here — every issuance went to Let's Encrypt
		// regardless. Same shape as the other allowlist drops.
		//
		// https only, matching the data plane: its ACME client is built
		// https-only, so forwarding an http:// URL would just move the silent
		// failure one layer down.
		if cs := strings.TrimSpace(t.CaServer); strings.HasPrefix(cs, "https://") {
			acme["ca_server"] = cs
		}
		if ch := rustAcmeChallenge(t.Challenge); ch != "" {
			acme["challenge"] = ch
		}
		if t.RenewBefore > 0 {
			acme["renew_before_days"] = t.RenewBefore
		}
		return map[string]any{"mode": "acme", "acme": acme}
	case "manual":
		if t.Custom != nil && t.Custom.Priority == "file" && t.Custom.CertPath != "" && t.Custom.KeyPath != "" {
			return map[string]any{"mode": "manual", "cert": t.Custom.CertPath, "key": t.Custom.KeyPath}
		}
		return off // pasted PEM lives in the cert repository; served by SNI
	case "self_signed":
		return map[string]any{"mode": "self_signed"}
	default: // "existing", "off", "" → served by SNI / no per-site action
		return off
	}
}

// rustAcmeProvider maps the dashboard provider id to the Rust AcmeProvider serde
// value; returns "" to let the Rust default (lets_encrypt) apply.
func rustAcmeProvider(p string) string {
	switch p {
	case "letsencrypt", "lets_encrypt":
		return "lets_encrypt"
	case "letsencrypt_staging", "lets_encrypt_staging":
		return "lets_encrypt_staging"
	case "zerossl", "zero_ssl":
		return "zero_ssl"
	default:
		return ""
	}
}

// rustAcmeChallenge maps the dashboard challenge id to the Rust AcmeChallengeType
// serde value; returns "" to let the Rust default (http01) apply. DNS-01 is not
// supported by the data plane yet, so it falls back to the default.
func rustAcmeChallenge(c string) string {
	switch c {
	case "http_01", "http01":
		return "http01"
	case "tls_alpn_01", "tls_alpn01":
		return "tls_alpn01"
	default:
		return ""
	}
}

// buildRustUpstream accepts both the legacy shape
//
//	{"servers":["host:port"],"lb":"round_robin"}
//
// and the rich shape
//
//	{"load_balancer":"least_conn",
//	 "servers":[{"host":"h","port":8080,"weight":2,"tls":true}],
//	 "health_check":{"path":"/","interval":"10s","timeout":"3s"}}
func buildRustUpstream(raw json.RawMessage) (map[string]any, error) {
	var generic struct {
		Servers      json.RawMessage `json:"servers"`
		LB           string          `json:"lb"`
		LoadBalancer string          `json:"load_balancer"`
		HealthCheck  json.RawMessage `json:"health_check"`
		TimeoutSecs  *uint64         `json:"timeout_secs"`
		// Promoted alongside timeout_secs: the operator types a duration string in
		// `proxy.connect_timeout`, the dashboard converts it, and this is the value
		// the data plane reads.
		ConnectTimeoutSecs *uint64 `json:"connect_timeout_secs"`
		// The dashboard nests reverse-proxy options under `proxy`. Only the keys
		// named here reach the data plane; anything else in the object is stored and
		// echoed back but enforces nothing. Add a key here only alongside the
		// data-plane code that reads it — a forwarded key with no reader is the
		// silently-inert defect this allowlist exists to make visible.
		Proxy struct {
			Websocket  *bool   `json:"websocket"`
			Keepalive  *bool   `json:"keepalive"`
			HostHeader *string `json:"host_header"`
			SSLSni     *bool   `json:"ssl_sni"`
			SSLSniName *string `json:"ssl_sni_name"`
		} `json:"proxy"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &generic); err != nil {
			return nil, err
		}
	}

	lb := generic.LoadBalancer
	if lb == "" {
		lb = generic.LB
	}
	if lb == "" {
		lb = "round_robin"
	}

	rustServers := make([]map[string]any, 0)
	if len(generic.Servers) > 0 {
		// Try object form first: [{host,port,weight,tls}]
		var objs []struct {
			Host   string `json:"host"`
			Port   int    `json:"port"`
			Weight int    `json:"weight"`
			TLS    bool   `json:"tls"`
		}
		if err := json.Unmarshal(generic.Servers, &objs); err == nil && len(objs) > 0 && objs[0].Host != "" {
			for _, o := range objs {
				port := o.Port
				if port == 0 {
					port = 80
				}
				weight := o.Weight
				if weight == 0 {
					weight = 1
				}
				rustServers = append(rustServers, map[string]any{
					"host": o.Host, "port": port, "weight": weight, "tls": o.TLS,
				})
			}
		} else {
			// Fall back to string form: ["host:port"]
			var strs []string
			if err := json.Unmarshal(generic.Servers, &strs); err != nil {
				return nil, err
			}
			for _, addr := range strs {
				host, portStr, err := net.SplitHostPort(addr)
				if err != nil {
					host, portStr = addr, "80"
				}
				port, _ := strconv.Atoi(portStr)
				if port == 0 {
					port = 80
				}
				rustServers = append(rustServers, map[string]any{
					"host": host, "port": port, "weight": 1, "tls": false,
				})
			}
		}
	}

	upstream := map[string]any{
		"load_balancer": lb,
		"servers":       rustServers,
	}

	if len(generic.HealthCheck) > 0 {
		var hc map[string]any
		if err := json.Unmarshal(generic.HealthCheck, &hc); err == nil && len(hc) > 0 {
			upstream["health_check"] = hc
		}
	}

	// Per-site response-header timeout. Omitted when unset or 0 so the Rust
	// side falls back to the deployment default rather than being handed a
	// value nobody chose. Bounded because an unbounded wait would pin a
	// request task (and its admission permit) on a hung origin.
	if generic.TimeoutSecs != nil && *generic.TimeoutSecs > 0 {
		secs := *generic.TimeoutSecs
		if secs > maxUpstreamTimeoutSecs {
			secs = maxUpstreamTimeoutSecs
		}
		upstream["timeout_secs"] = secs
	}

	// WebSocket upgrades, off unless the site asks for them. Always emitted, even
	// when false, so the value the data plane enforces is the one the operator
	// chose rather than a default inferred from an absent key. A config that never
	// mentioned WebSockets resolves to false: this gate replaces an ungated relay
	// that upgraded on any origin 101, so treating silence as "allowed" would keep
	// that fail-open behaviour alive for every pre-existing site.
	upstream["websocket"] = generic.Proxy.Websocket != nil && *generic.Proxy.Websocket

	// Upstream keep-alive. Defaults to TRUE when absent — the opposite of
	// websocket above, and deliberately so: connection reuse is what a reverse
	// proxy should do, and a legacy config that never mentioned it was getting
	// reuse. Treating silence as "off" here would quietly add a TCP (and TLS)
	// handshake to every request on every existing site.
	upstream["keepalive"] = generic.Proxy.Keepalive == nil || *generic.Proxy.Keepalive

	// Host header override. Omitted when blank so the data plane's "None" means
	// pass the client's Host through, rather than "send an empty Host".
	if generic.Proxy.HostHeader != nil {
		if hh := strings.TrimSpace(*generic.Proxy.HostHeader); hh != "" {
			upstream["host_header"] = hh
		}
	}

	// Per-site connect timeout, clamped here as well as in the data plane so the
	// API rejects nonsense at the edge rather than relying on the far side.
	if generic.ConnectTimeoutSecs != nil && *generic.ConnectTimeoutSecs > 0 {
		secs := *generic.ConnectTimeoutSecs
		if secs > maxUpstreamConnectTimeoutSecs {
			secs = maxUpstreamConnectTimeoutSecs
		}
		upstream["connect_timeout_secs"] = secs
	}

	// SNI override for an HTTPS origin. Requires BOTH the toggle and a name: a
	// name with the toggle off is not an intent to override, and the toggle on
	// with no name has nothing to present. Only forwarded when it would do
	// something, since an empty override is indistinguishable from none.
	if generic.Proxy.SSLSni != nil && *generic.Proxy.SSLSni && generic.Proxy.SSLSniName != nil {
		if sni := strings.TrimSpace(*generic.Proxy.SSLSniName); sni != "" {
			upstream["sni_name"] = sni
		}
	}

	return upstream, nil
}

// maxUpstreamConnectTimeoutSecs mirrors MAX_SITE_CONNECT_TIMEOUT_SECS in
// crates/sentinel-proxy/src/upstream.rs. A connect timeout longer than this
// defeats the purpose of having one — it pins a request task on an unreachable
// origin for minutes.
const maxUpstreamConnectTimeoutSecs uint64 = 60

// maxUpstreamTimeoutSecs caps the per-site upstream timeout at 10 minutes.
// Slow report/export endpoints are the reason the knob exists; anything longer
// than this is an application bug, not a WAF setting.
const maxUpstreamTimeoutSecs uint64 = 600

// buildRustWaf accepts the legacy minimal blob and the rich dashboard blob and
// produces the Rust WafConfig JSON. Unknown/empty sections are omitted so the
// Rust defaults apply.
// knownWafPolicyKeys is every waf_policy key the platform does something with.
//
// It exists because buildRustWaf is an allowlist: a key it does not name is
// stored, echoed back to the dashboard, and silently dropped on the way to the
// data plane. block_page shipped that way — the wizard offered branding, the
// API persisted it, the site page redisplayed it, and blocked visitors kept
// getting the default page, with nothing anywhere reporting a fault. Nothing
// failed, so it went unnoticed until someone looked at what a visitor actually
// received.
//
// Anything absent here is reported once per site at WARN. Keep it in step when
// adding a field — a new key is either forwarded, or it is inert and the log
// should say so.
var knownWafPolicyKeys = map[string]struct{}{
	// Forwarded to the data plane by buildRustWaf.
	"mode": {}, "paranoia_level": {}, "anomaly_threshold": {},
	"rule_categories": {}, "rule_exclusions": {}, "path_overrides": {},
	"crs_policy":    {},
	"max_body_size": {}, "max_uri_length": {}, "max_header_count": {},
	"max_inspected_args": {}, "max_inspected_arg_bytes": {}, "inspection_time_budget_ms": {},
	"allowed_methods": {}, "api_discovery": {}, "security_headers": {},
	"rate_limit": {}, "anti_ddos": {}, "bot_detection": {}, "geoip": {},
	"ip_reputation": {}, "ml": {}, "jwt": {}, "graphql": {}, "grpc": {},
	"enabled_plugins": {},
	"dlp":             {}, "fusion": {}, "block_page": {},
	// Consumed by buildRustSiteTLS into the top-level SiteConfig.tls rather
	// than by buildRustWaf, so its absence from the struct above is correct.
	"tls": {},
	// Deliberately stored-only: TLS termination and the HTTP protocol set are
	// properties of the WAF *listener*, shared by every site on a node, so
	// there is no per-site plumbing to forward these to. The wizard's Front
	// Service step is tagged "stored" and says so to the operator.
	"frontend": {},
}

// warnedUnknownWafKeys dedupes the warning below. /internal/config is polled
// every 5s by every data-plane node, so warning per call would bury the signal
// under thousands of identical lines a day. Once per (site, key-set) per
// process is enough to be seen after a deploy — and a control-plane restart
// re-reports, which is exactly when someone is looking.
var warnedUnknownWafKeys sync.Map

// unknownWafPolicyKeys returns the waf_policy keys nothing will act on, sorted
// so the output is stable and diffable.
func unknownWafPolicyKeys(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(raw, &all); err != nil {
		// Malformed policy is buildRustWaf's error to report, not ours.
		return nil
	}
	var unknown []string
	for k := range all {
		if _, ok := knownWafPolicyKeys[k]; !ok {
			unknown = append(unknown, k)
		}
	}
	sort.Strings(unknown)
	return unknown
}

// warnUnknownWafPolicyKeys reports, once per site per process, any waf_policy
// key that reaches neither the data plane nor a known stored-only path.
func warnUnknownWafPolicyKeys(site string, raw json.RawMessage, log *zap.Logger) {
	unknown := unknownWafPolicyKeys(raw)
	if len(unknown) == 0 || log == nil {
		return
	}
	key := site + "\x00" + strings.Join(unknown, ",")
	if _, seen := warnedUnknownWafKeys.LoadOrStore(key, struct{}{}); seen {
		return
	}
	log.Warn("waf_policy contains keys nothing acts on — they are stored and "+
		"returned to the dashboard but NEVER reach the data plane, so any setting "+
		"they represent is inert; add them to buildRustWaf or to knownWafPolicyKeys",
		zap.String("site", site),
		zap.Strings("ignored_keys", unknown))
}

func buildRustWaf(raw json.RawMessage) (map[string]any, error) {
	var p struct {
		Mode             string          `json:"mode"`
		ParanoiaLevel    int             `json:"paranoia_level"`
		AnomalyThreshold int             `json:"anomaly_threshold"`
		RuleCategories   []string        `json:"rule_categories"`
		RuleExclusions   json.RawMessage `json:"rule_exclusions"`
		RateLimit        json.RawMessage `json:"rate_limit"`
		BotDetection     json.RawMessage `json:"bot_detection"`
		Graphql          json.RawMessage `json:"graphql"`
		Jwt              json.RawMessage `json:"jwt"`
		Grpc             json.RawMessage `json:"grpc"`
		Dlp              json.RawMessage `json:"dlp"`
		Fusion           json.RawMessage `json:"fusion"`
		AntiDdos         json.RawMessage `json:"anti_ddos"`
		GeoIP            json.RawMessage `json:"geoip"`
		ML               json.RawMessage `json:"ml"`
		IPReputation     json.RawMessage `json:"ip_reputation"`
		EnabledPlugins   []string        `json:"enabled_plugins"`
		MaxBodySize      *uint64         `json:"max_body_size"`
		MaxURILength     *uint32         `json:"max_uri_length"`
		MaxHeaderCount   *uint32         `json:"max_header_count"`
		APIDiscovery     bool            `json:"api_discovery"`
		AllowedMethods   []string        `json:"allowed_methods"`
		// Inspection limits: what inspecting one request may cost the rule
		// engine. Pointers because absent means the data plane's defaults,
		// while 0 is a legal value meaning "no limit".
		MaxInspectedArgs       *uint32 `json:"max_inspected_args"`
		MaxInspectedArgBytes   *uint64 `json:"max_inspected_arg_bytes"`
		InspectionTimeBudgetMs *uint32 `json:"inspection_time_budget_ms"`
		// CRS policy lists (tx.*) the rule engine gates on. Empty by default:
		// upstream CRS ships every one of these commented out, so they are
		// opt-in policy rather than a default. See seed_crs_policy in the proxy.
		CrsPolicy       map[string]string `json:"crs_policy"`
		SecurityHeaders json.RawMessage   `json:"security_headers"`
		PathOverrides   json.RawMessage   `json:"path_overrides"`
		// Every field here is an ALLOWLIST entry: a waf_policy key absent from
		// this struct is stored in the database, echoed back to the dashboard,
		// and silently dropped on the way to the data plane. block_page was
		// exactly that — the wizard offered branding, the API persisted it, the
		// site detail page redisplayed it, and the visitor still got the default
		// page, with nothing anywhere reporting a problem.
		BlockPage json.RawMessage `json:"block_page"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
	}

	if p.Mode == "" {
		p.Mode = "blocking"
	}
	if p.ParanoiaLevel == 0 {
		p.ParanoiaLevel = 2
	}
	if p.AnomalyThreshold == 0 {
		// 10, not 5: requiring two correlated signals instead of one is what the
		// detection benchmark measured at composite 99.60% / true-negative 99.29%
		// (deploy/load-test/waf-detection.yaml). At 5 a single weak +5 heuristic
		// blocks on its own, which is where most benign false-positives came from.
		p.AnomalyThreshold = 10
	}

	// Never nil: a nil slice marshals as JSON null, and the data plane's
	// `rules: Vec<String>` rejects null (serde's default covers an ABSENT field,
	// not a null one). For a site in mode "off" that null used to make every node
	// reject the WHOLE config sync — one click on Off froze config delivery for
	// every site on the fleet, with nothing in the console saying so.
	rules := []string{}
	if p.Mode != "off" {
		rules = crsFilesForCategories(p.RuleCategories)
		// Appended, not prepended: CRS sets up tx.anomaly_score and friends, and
		// our rules contribute to that score, so they must be evaluated after the
		// CRS files that establish it.
		rules = append(rules, sentinelRuleFiles...)
	}

	waf := map[string]any{
		"mode":              p.Mode,
		"paranoia_level":    p.ParanoiaLevel,
		"anomaly_threshold": p.AnomalyThreshold,
		"rules":             rules,
		"api_discovery":     p.APIDiscovery,
	}

	// Rule exclusions — the defaults in defaultRuleExclusions are applied to every
	// site alongside any operator-defined ones (e.g. one-click disables from the
	// learning report).
	//
	// An operator can fully re-enable a defaulted rule by storing an *empty* entry
	// for its id (no targets, not disabled): that acts as an opt-out marker — it
	// suppresses the injected default and is itself dropped (a no-op to the data
	// plane). `handleDeleteSiteExclusion` leaves this marker when such an entry is
	// removed, so the default isn't silently re-added on the next build.
	ex := []map[string]any{}
	seen := make(map[int]bool, len(defaultRuleExclusions))
	out := make([]map[string]any, 0, len(ex)+len(defaultRuleExclusions))
	if len(p.RuleExclusions) > 0 {
		if err := json.Unmarshal(p.RuleExclusions, &ex); err != nil {
			ex = []map[string]any{}
		}
		for _, e := range ex {
			isDefaulted := false
			for _, d := range defaultRuleExclusions {
				if ruleIDEquals(e["rule_id"], d.id) {
					isDefaulted = true
					seen[d.id] = true
					break
				}
			}
			if isDefaulted && isEmptyExclusion(e) {
				continue // opt-out marker — drop it, don't emit to the proxy
			}
			out = append(out, e)
		}
	}
	for _, d := range defaultRuleExclusions {
		if !seen[d.id] {
			out = append(out, d.entry())
		}
	}
	waf["rule_exclusions"] = out

	attachRawObject(waf, "rate_limit", p.RateLimit)
	attachRawObject(waf, "bot_detection", p.BotDetection)
	attachRawObject(waf, "graphql", p.Graphql)
	attachRawObject(waf, "jwt", p.Jwt)
	attachRawObject(waf, "grpc", p.Grpc)
	attachRawObject(waf, "dlp", p.Dlp)
	attachRawObject(waf, "fusion", p.Fusion)
	attachRawObject(waf, "ml", p.ML)
	attachRawObject(waf, "ip_reputation", p.IPReputation)
	// Per-site plugin selection. Always emitted, including empty: plugins are
	// opt-in per site, and an absent key and an empty list mean the same thing
	// (this site runs none) — sending it explicitly keeps "deselected on
	// purpose" legible in a request log and in the effective-config diff.
	names := make([]string, 0, len(p.EnabledPlugins))
	for _, n := range p.EnabledPlugins {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}
	waf["enabled_plugins"] = names
	attachRawObject(waf, "block_page", p.BlockPage)

	// Per-path overrides pass through verbatim as an ARRAY (attachRawObject only
	// handles objects). Validation has already rejected empty prefixes, per-path
	// paranoia_level and per-path rule_exclusions, so what reaches the data plane
	// is only what it can actually honour.
	if len(p.PathOverrides) > 0 {
		var ov []map[string]any
		if err := json.Unmarshal(p.PathOverrides, &ov); err == nil && len(ov) > 0 {
			waf["path_overrides"] = ov
		}
	}

	// anti_ddos — only attach when explicitly enabled.
	if len(p.AntiDdos) > 0 {
		var ad map[string]any
		if err := json.Unmarshal(p.AntiDdos, &ad); err == nil {
			if enabled, _ := ad["enabled"].(bool); enabled {
				waf["anti_ddos"] = ad
			}
		}
	}

	// geoip — Rust requires db_path; inject a default and only attach when the
	// operator selected at least one country to allow/block.
	if len(p.GeoIP) > 0 {
		var g map[string]any
		if err := json.Unmarshal(p.GeoIP, &g); err == nil {
			block, _ := g["block_countries"].([]any)
			allow, _ := g["allow_countries"].([]any)
			if len(block) > 0 || len(allow) > 0 {
				if _, ok := g["db_path"]; !ok || g["db_path"] == "" {
					g["db_path"] = osGetenv("SENTINEL_GEOIP_DB", "/var/lib/sentinel/geoip/dbip-country-lite.mmdb")
				}
				waf["geoip"] = g
			}
		}
	}

	if p.MaxBodySize != nil {
		waf["max_body_size"] = *p.MaxBodySize
	}
	if p.MaxURILength != nil {
		waf["max_uri_length"] = *p.MaxURILength
	}
	if p.MaxHeaderCount != nil {
		waf["max_header_count"] = *p.MaxHeaderCount
	}
	if p.MaxInspectedArgs != nil {
		waf["max_inspected_args"] = *p.MaxInspectedArgs
	}
	if p.MaxInspectedArgBytes != nil {
		waf["max_inspected_arg_bytes"] = *p.MaxInspectedArgBytes
	}
	if p.InspectionTimeBudgetMs != nil {
		waf["inspection_time_budget_ms"] = *p.InspectionTimeBudgetMs
	}

	// Method allow-list and response/security headers — pass through so the
	// data plane can actually enforce what the wizard collects (a full method
	// list means "no restriction"; an empty/partial list restricts).
	if len(p.AllowedMethods) > 0 {
		waf["allowed_methods"] = p.AllowedMethods
	}
	if len(p.CrsPolicy) > 0 {
		waf["crs_policy"] = p.CrsPolicy
	}
	attachRawObject(waf, "security_headers", p.SecurityHeaders)

	return waf, nil
}

// ruleIDEquals compares a JSON-decoded rule_id (which may be float64, json.Number,
// or int) against an expected integer.
// attachInlineRules puts a tenant's operator-authored rules into the site's waf
// block as `inline_rules`, which the data plane parses as SRL alongside its
// file-based ruleset (see load_site_engine).
//
// Source rather than compiled bytecode: shipping bytecode would tie the control
// plane's compiler version to the data plane's, so a version skew during a rolling
// upgrade could mis-execute a rule instead of failing visibly. The data plane owns
// the only compiler.
//
// A rule with no site_id is deployment-wide, which is the right default for what
// the feature exists for: a virtual patch for a CVE should cover everything, not
// one hostname. A rule scoped to a site reaches only that site, because tuning is
// inherently per-site — a rule written for one application's checkout flow can
// only cost latency and false-positive risk everywhere else.
//
// siteID is the site being configured; pass "" and only deployment-wide rules
// attach.
//
// A site with mode "off" gets nothing: off means off, matching buildRustWaf.
func attachInlineRules(rs map[string]any, siteID string, rules []db.DeployableRule) {
	if len(rules) == 0 {
		return
	}
	waf, ok := rs["waf"].(map[string]any)
	if !ok {
		return
	}
	if mode, _ := waf["mode"].(string); mode == "off" {
		return
	}
	inline := make([]map[string]any, 0, len(rules))
	for _, r := range rules {
		if strings.TrimSpace(r.DSL) == "" {
			continue
		}
		// Deployment-wide (empty SiteID) or scoped to exactly this site.
		if r.SiteID != "" && r.SiteID != siteID {
			continue
		}
		inline = append(inline, map[string]any{"name": r.Name, "dsl": r.DSL})
	}
	if len(inline) > 0 {
		waf["inline_rules"] = inline
	}
}

// defaultWafPolicyJSON is the policy stored for a site created without one. The
// threshold matches buildRustWaf's default and the benchmarked configuration —
// keep the two in step, or a site's stored policy and its effective policy drift.
//
// Mode is LEARNING, not blocking. A caller who sends no policy at all is by
// definition a caller who has not decided one, and for a WAF the unsafe default
// is the enforcing one: it blocks real users against a false-positive rate
// nobody has measured for that application. Learning records exactly the same
// detections and blocks nothing, so the cost of this default being wrong is a
// site that observes for a while; the cost of the other default being wrong is
// an outage on someone else's application.
//
// This also removes the last disagreement between the three creation paths. The
// wizard defaults to learning, first-site.sh sends learning explicitly, and this
// — the raw API path — used to enforce. Three sources of a site's initial
// posture that did not agree is how the console and the CLI ended up shipping
// opposite behaviour for the same action.
// The path overrides exist because a threshold of 10 means NO SINGLE rule ever
// blocks. CRS scores a CRITICAL detection at 5, so enforcement needs two
// independent findings — a deliberately permissive posture that keeps the
// false-positive rate low on ordinary traffic.
//
// It also means recon walks straight through. Measured on .71 on 2026-08-31,
// against a scanner probing the demo site: requests for `/.git/config`,
// `/.git/HEAD`, `/.env`, `/.env.production` and `/.env.backup` each fired rule
// 930130 "Restricted File Access Attempt" for a score of 5 — and were passed
// to the origin, `would_block=false`. A leaked `.git` directory or `.env` file
// is a full compromise, and it is one of the most-probed things on the public
// internet.
//
// These prefixes carry no legitimate traffic, so the threshold is lowered for
// them alone rather than globally. The global default is left at 10: the only
// real-traffic sample available is 96% one path, which is not enough to justify
// changing the posture for every site — that is what the FPR pilot is for.
//
// `/.well-known/` is deliberately NOT here. It is legitimate and load-bearing:
// ACME HTTP-01 challenges live there, so blocking it would break certificate
// issuance. That is why these are specific prefixes and not a blanket `/.`.
const defaultWafPolicyJSON = `{"mode":"learning","paranoia_level":2,"anomaly_threshold":10,` +
	`"path_overrides":[` +
	`{"path_prefix":"/.git","anomaly_threshold":5},` +
	`{"path_prefix":"/.env","anomaly_threshold":5},` +
	`{"path_prefix":"/.svn","anomaly_threshold":5},` +
	`{"path_prefix":"/.aws","anomaly_threshold":5},` +
	`{"path_prefix":"/.ssh","anomaly_threshold":5},` +
	`{"path_prefix":"/.htpasswd","anomaly_threshold":5}` +
	`]}`

// defaultRuleExclusions are the CRS suppressions applied to every site unless the
// operator explicitly opts out. Both come from measured false-positive work:
//
//   - 932236 on ARGS_NAMES — the `?id=42` false positive (see CRS importer notes).
//   - 920230 disabled outright — "multiple URL encoding detected" is a weak +3
//     heuristic that dominated benign false-positives. Disabling it is one half of
//     the tuned configuration measured at composite 99.60% / true-negative 99.29%
//     (deploy/load-test/waf-detection.yaml); the other half is anomaly_threshold
//     10, defaulted in buildRustWaf.
//
// entry is a constructor, not a shared map: buildRustWaf hands these to the data
// plane per request, and a shared map would let one site's edit leak into another's.
var defaultRuleExclusions = []struct {
	id    int
	entry func() map[string]any
}{
	{932236, func() map[string]any {
		return map[string]any{"rule_id": 932236, "exclude_targets": []string{"ARGS_NAMES"}}
	}},
	{920230, func() map[string]any {
		return map[string]any{"rule_id": 920230, "disable": true}
	}},
	// 922110 — "Illegal MIME Multipart Header content-type: charset parameter".
	//
	// It no longer HARD-blocks: chained rules now inherit their inner link's
	// anomaly-score contribution, so this is a +5 like its neighbours rather than
	// an unconditional refusal. It stays disabled for the reason that survives
	// that fix — CRS's allowed list holds only utf-8, iso-8859-1, iso-8859-15 and
	// windows-1252, and everything else in a part's Content-Type scores.
	//
	// Measured against the shipped rule: us-ascii (an RFC-standard charset),
	// utf-16, shift_jis and euc-kr all match. A customer serving Japanese or
	// Korean content would therefore carry a standing +5 on every upload, needing
	// only one more weak signal to cross a threshold of 10 — a half-blocked site
	// that looks intermittent rather than misconfigured.
	//
	// This is a charset POLICY check, not an attack signature. The other two 922
	// rules stay active, so multipart part-header protection is still on by
	// default. An operator who wants the policy adds an empty exclusion entry for
	// 922110, which suppresses this default (see buildRustWaf).
	{922110, func() map[string]any {
		return map[string]any{"rule_id": 922110, "disable": true}
	}},
}

func ruleIDEquals(v any, want int) bool {
	switch n := v.(type) {
	case float64:
		return int(n) == want
	case int:
		return n == want
	case json.Number:
		i, _ := n.Int64()
		return int(i) == want
	}
	return false
}

// isEmptyExclusion reports whether a decoded exclusion is a no-op: not a
// whole-rule disable and with no target list. Such an entry only ever serves as
// an explicit "keep this rule fully enabled" opt-out marker (see buildRustWaf).
func isEmptyExclusion(e map[string]any) bool {
	if dis, _ := e["disable"].(bool); dis {
		return false
	}
	if t, ok := e["exclude_targets"].([]any); ok && len(t) > 0 {
		return false
	}
	return true
}

// attachRawObject decodes a raw JSON object and attaches it under key when
// non-empty. Invalid/empty sections are silently skipped.
func attachRawObject(dst map[string]any, key string, raw json.RawMessage) {
	if len(raw) == 0 {
		return
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err == nil && len(obj) > 0 {
		dst[key] = obj
	}
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

func handleListRules(c *gin.Context, enf *rbac.Enforcer, store *db.Store) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceRule, rbac.ActionList) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store != nil {
		rules, err := store.ListRules(c.Request.Context(), claims.TenantID, claims.UserID)
		if err == nil {
			if rules == nil {
				rules = []db.RuleRow{}
			}
			c.JSON(http.StatusOK, gin.H{
				"rules":     annotateRuleEnforcement(c.Request.Context(), store, rules),
				"tenant_id": claims.TenantID,
			})
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"rules": []interface{}{}, "tenant_id": claims.TenantID})
}

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------

func handleListAlerts(c *gin.Context, enf *rbac.Enforcer, store *db.Store) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceAlert, rbac.ActionList) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	stateFilter := c.DefaultQuery("state", "")
	if store != nil {
		alerts, err := store.ListAlerts(c.Request.Context(), claims.TenantID, claims.UserID, stateFilter)
		if err == nil {
			if alerts == nil {
				alerts = []db.AlertRow{}
			}
			c.JSON(http.StatusOK, gin.H{"alerts": alerts, "tenant_id": claims.TenantID})
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"alerts": []interface{}{}, "tenant_id": claims.TenantID})
}

func handleAckAlert(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *leader.Elector) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceAlert, rbac.ActionUpdate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	id := c.Param("id")
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	if !requireLeader(c, cl) {
		return
	}
	if err := store.AckAlert(c.Request.Context(), claims.TenantID, claims.UserID, id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
		return
	}
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &claims.UserID,
		Action:      "alert.ack",
		TargetKind:  "alert",
		TargetID:    &id,
	})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func handleResolveAlert(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *leader.Elector) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceAlert, rbac.ActionUpdate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	id := c.Param("id")
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	if !requireLeader(c, cl) {
		return
	}
	if err := store.ResolveAlert(c.Request.Context(), claims.TenantID, claims.UserID, id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
		return
	}
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &claims.UserID,
		Action:      "alert.resolve",
		TargetKind:  "alert",
		TargetID:    &id,
	})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// Plugins moved to plugin_handlers.go. The stub that lived here always returned
// a hardcoded empty list, so the Plugins page stayed empty no matter what was
// installed — see handleListPluginsReal.

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

func handleListAudit(c *gin.Context, enf *rbac.Enforcer, store *db.Store) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceAudit, rbac.ActionRead) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	// An empty list and a broken audit store must never look the same. This
	// returned 200 with `entries: []` on a DB error, so an audit-store outage
	// rendered in the console as "no admin activity" — the most reassuring
	// possible display of the least reassuring possible state, and precisely
	// what an attacker who could break the store would want shown.
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "audit log unavailable: no database configured",
		})
		return
	}

	limit := int(atoi64(c.Query("limit")))
	if limit <= 0 {
		limit = 100
	}
	filter := db.AuditFilter{
		Action:       c.Query("action"),
		ActionPrefix: c.Query("action_prefix"),
		Result:       strings.ToUpper(strings.TrimSpace(c.Query("result"))),
		From:         atoi64(c.Query("from")),
		To:           atoi64(c.Query("to")),
		BeforeSeq:    atoi64(c.Query("before_seq")),
		Limit:        limit,
	}
	if filter.Result != "" && filter.Result != auditSuccess && filter.Result != auditFailure {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "result must be SUCCESS or FAILURE",
		})
		return
	}

	entries, err := store.ListAuditLogsFiltered(c.Request.Context(), claims.TenantID, claims.UserID, filter)
	if err != nil {
		zap.L().Warn("audit list failed", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "audit log unavailable: could not read the audit store",
		})
		return
	}
	if entries == nil {
		entries = []db.AuditRow{}
	}
	// Keyset cursor: the caller pages by passing this back as before_seq. Only
	// present when the page was full, so an empty tail is not mistaken for
	// "more available".
	var nextCursor int64
	if len(entries) == limit {
		nextCursor = entries[len(entries)-1].Seq
	}
	c.JSON(http.StatusOK, gin.H{
		"entries":         entries,
		"tenant_id":       claims.TenantID,
		"next_before_seq": nextCursor,
	})
}

// handleVerifyAudit recomputes the audit hash chain and reports the result.
//
// The verifier has existed since the chain was built but was reachable from
// NOTHING — no route, no CLI subcommand, no job — while the console advertised
// the trail as "tamper-evident ... compliance-grade". An auditor asking "prove
// the chain verifies" could not be answered from the product at all. A
// tamper-evidence claim that cannot be exercised is a claim, not a control.
//
// Restricted to the audit-read permission and scoped to the caller's tenant.
func handleVerifyAudit(c *gin.Context, enf *rbac.Enforcer, store *db.Store) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceAudit, rbac.ActionRead) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "audit log unavailable: no database configured",
		})
		return
	}
	limit := int(atoi64(c.Query("limit")))
	rep, err := store.VerifyAuditLog(c.Request.Context(), claims.TenantID, auditHMACKey(), limit)
	if err != nil {
		zap.L().Warn("audit verify failed", zap.Error(err))
		// Never report "verified" because verification could not run.
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":    "could not verify the audit chain",
			"verified": false,
		})
		return
	}
	verified := len(rep.Altered) == 0 && len(rep.ChainBroken) == 0 && len(rep.SeqGaps) == 0
	status := http.StatusOK
	if !verified {
		// A failed verification is not a successful request about a bad chain —
		// it is an integrity alarm, and it must not be a quiet 200 that a
		// dashboard renders as a tick.
		status = http.StatusConflict
	}
	c.JSON(status, gin.H{
		"verified":     verified,
		"checked":      rep.Checked,
		"altered":      rep.Altered,
		"chain_broken": rep.ChainBroken,
		"seq_gaps":     rep.SeqGaps,
		// Rows predating the chain migration are verified with the legacy
		// per-row MAC, so deletions among them cannot be detected. Surfaced so
		// a clean result over legacy rows is never read as a full guarantee.
		"unchained_rows": rep.Unchained,
		"note": "verified=true means every chained row's HMAC recomputes and no row is " +
			"missing or reordered. unchained_rows predate the hash chain and can only be " +
			"checked individually.",
	})
}

// ---------------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------------

func handleListUsers(c *gin.Context, enf *rbac.Enforcer) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceUser, rbac.ActionList) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"users": []interface{}{}, "tenant_id": claims.TenantID})
}

func handleCreateUser(c *gin.Context, enf *rbac.Enforcer) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceUser, rbac.ActionCreate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"message": "user created", "tenant_id": claims.TenantID})
}

func handleListAPIKeys(c *gin.Context, enf *rbac.Enforcer) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceAPIKey, rbac.ActionList) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"api_keys": []interface{}{}, "tenant_id": claims.TenantID})
}

func handleCreateAPIKey(c *gin.Context, enf *rbac.Enforcer) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceAPIKey, rbac.ActionCreate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"message": "api key created", "tenant_id": claims.TenantID})
}

// ---------------------------------------------------------------------------
// SSE log stream  GET /api/v1/logs/stream
// ---------------------------------------------------------------------------
// Query params:
//   kind=access|waf|error|audit|modsec|ml  (empty = all)
//
// The endpoint is protected by JWT.  The token may be passed as either the
// Authorization header (preferred) or as the ?token= query parameter (needed
// when EventSource in the browser cannot set headers).

func handleLogsStream(c *gin.Context, jwtSvc *auth.JWTService, enf *rbac.Enforcer, hub *logs.Hub) {
	// Allow token via query param for browser EventSource compatibility.
	if c.GetHeader("Authorization") == "" {
		if t := c.Query("token"); t != "" {
			c.Request.Header.Set("Authorization", "Bearer "+t)
		}
	}

	// Validate JWT.
	tokenStr, err := auth.BearerToken(c.GetHeader("Authorization"))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
		return
	}
	claims, err := jwtSvc.Validate(tokenStr)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}
	if claims.AuthMethod == "refresh" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token is not valid for API access"})
		return
	}

	// RBAC: only roles that can view operational data may stream, and the audit
	// stream is restricted to roles allowed to read audit logs. Previously any
	// authenticated role (incl. viewer) could read the live audit trail.
	role := rbac.Role(claims.Role)
	canView := enf.Allow(role, rbac.ResourceSite, rbac.ActionList)
	canAudit := enf.Allow(role, rbac.ResourceAudit, rbac.ActionList)
	if !canView && !canAudit {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}

	kindFilter := c.Query("kind") // empty = all
	if kindFilter == "audit" && !canAudit {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions for audit stream"})
		return
	}

	ch := hub.Subscribe()
	defer hub.Unsubscribe(ch)

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")
	c.Status(http.StatusOK)

	flusher, canFlush := c.Writer.(http.Flusher)

	writeEvent := func(entry logs.Entry) {
		data, _ := json.Marshal(entry)
		fmt.Fprintf(c.Writer, "data: %s\n\n", data)
		if canFlush {
			flusher.Flush()
		}
	}
	// SSE comment lines (": …") are ignored by EventSource but reach the wire.
	comment := func(text string) {
		fmt.Fprintf(c.Writer, ": %s\n\n", text)
		if canFlush {
			flusher.Flush()
		}
	}

	// Open the stream NOW. Nothing used to be flushed until the first entry, so
	// on an idle stream — every control-plane restart (empty backlog) on a quiet
	// site — the browser's EventSource never fired onopen and the Logs page sat
	// on "Reconnecting" while the stream was healthy. The periodic comment keeps
	// an idle connection from being reaped by a proxy between here and the
	// browser, which would otherwise turn quiet periods into reconnect churn.
	comment("connected")
	keepAlive := time.NewTicker(20 * time.Second)
	defer keepAlive.Stop()

	notify := c.Request.Context().Done()
	for {
		select {
		case <-notify:
			return
		case <-keepAlive.C:
			comment("keep-alive")
		case entry, ok := <-ch:
			if !ok {
				return
			}
			if kindFilter == "" || entry.Kind == kindFilter {
				// Never leak audit events to a role that can't read audit logs,
				// even on the unfiltered ("all kinds") stream.
				if entry.Kind == "audit" && !canAudit {
					continue
				}
				writeEvent(entry)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Metrics snapshot  GET /api/v1/metrics/snapshot
// ---------------------------------------------------------------------------

func handleMetricsSnapshot(c *gin.Context, hub *logs.Hub) {
	snap := hub.GetSnapshot()
	c.JSON(http.StatusOK, snap)
}

// handleSiteMetrics returns cumulative per-site request/block counters derived
// from the proxy NDJSON stream (keyed by the site label, e.g. "dvwa.local").
func handleSiteMetrics(c *gin.Context, hub *logs.Hub) {
	c.JSON(http.StatusOK, gin.H{"sites": hub.GetSiteStats()})
}

// handleLearningReport returns the would-have-blocked aggregation for the WAF
// learning workflow. Optional ?site=<label> scopes it to one site; omitted =
// across all sites. Optional ?from=&to= (unix seconds) bound the window. The
// "rules" array is sorted by detection count desc.
//
// Served from ClickHouse when it is configured, because the in-memory
// aggregate in logs.Hub is fed by tailing waf.log FROM ITS END: a control-plane
// restart reset the report to empty, and this report is the evidence an
// operator uses to decide a site is safe to flip out of learning mode. The
// stored path is also tenant-scoped, which the in-memory one is not.
//
// `source` is reported so a reader can tell durable evidence from
// since-restart-only evidence instead of having to assume.
func handleLearningReport(c *gin.Context, ch *chreader.Client, hub *logs.Hub) {
	claims, _ := auth.GetClaims(c.Request.Context())
	site := c.Query("site")

	if ch != nil && ch.Enabled() {
		rules, err := ch.LearningStats(
			c.Request.Context(),
			claims.TenantID, // isolation boundary — never from client input
			site,
			atoi64(c.Query("from")),
			atoi64(c.Query("to")),
			0,
		)
		if err == nil {
			// Categories are derived here rather than stored, so both sources
			// classify through the same function.
			for i := range rules {
				rules[i].Category = logs.AttackCategory(rules[i].RuleID)
			}
			if rules == nil {
				rules = []chreader.LearningStat{}
			}
			c.JSON(http.StatusOK, gin.H{
				"site": site, "rules": rules, "source": "clickhouse", "durable": true,
			})
			return
		}
		// Fall through to the in-memory aggregate, but say so: reporting a
		// since-restart view as if it were the full record is how an operator
		// flips a site to blocking on evidence that was quietly incomplete.
		zap.L().Warn("learning report: clickhouse query failed, serving in-memory aggregate",
			zap.Error(err))
		c.JSON(http.StatusOK, gin.H{
			"site": site, "rules": hub.GetLearningStats(site),
			"source": "memory", "durable": false,
			"warning": "event store unreachable — this covers only the period since the " +
				"control plane last restarted, and is not scoped to your tenant",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"site": site, "rules": hub.GetLearningStats(site),
		"source": "memory", "durable": false,
		"warning": "no event store configured — this covers only the period since the " +
			"control plane last restarted",
	})
}

// ---------------------------------------------------------------------------
// Audit helper (fire-and-forget)
// ---------------------------------------------------------------------------

// Audit outcome values recorded inside `diff`.
const (
	auditSuccess = "SUCCESS"
	auditFailure = "FAILURE"
)

// auditDiff builds the `diff` payload for an audit row, always stamping an
// explicit outcome.
//
// The outcome lives in `diff` rather than in a column of its own on purpose.
// `diff` is already covered by the chain HMAC (see auditPayload), so a
// FAILURE cannot be flipped to SUCCESS in the database without breaking
// verification. A new top-level column would either have to join the signed
// payload — invalidating the HMAC of every row written before it existed — or
// stay unsigned, which would leave the single most security-relevant field in
// the table freely editable. Signed-inside-diff needs no migration and no
// chain version bump, and stays queryable via `diff->>'result'`.
//
// Never put a password, token, or secret in here.
func auditDiff(result string, fields map[string]any) json.RawMessage {
	m := map[string]any{"result": result}
	for k, v := range fields {
		if k == "result" {
			continue
		}
		m[k] = v
	}
	b, err := json.Marshal(m)
	if err != nil {
		// A diff that will not marshal must not silently become "no diff" —
		// that would record a failure as an ordinary success.
		return json.RawMessage(`{"result":"` + result + `","diff_error":"marshal failed"}`)
	}
	return json.RawMessage(b)
}

// auditResultOf reads the outcome back out of a diff so the live stream reports
// what actually happened. Absent = SUCCESS, matching the many call sites that
// only audit their happy path.
func auditResultOf(diff json.RawMessage) string {
	if len(diff) == 0 {
		return auditSuccess
	}
	var probe struct {
		Result string `json:"result"`
	}
	if err := json.Unmarshal(diff, &probe); err != nil || probe.Result == "" {
		return auditSuccess
	}
	return probe.Result
}

// writeAuditEntry writes an audit record to the DB (if available) and also
// publishes the entry into the live SSE stream so the dashboard updates in
// real time.  Errors are non-fatal.
func writeAuditEntry(c *gin.Context, store *db.Store, hub *logs.Hub, req *db.WriteAuditRequest) {
	clientIP := c.ClientIP()
	req.IP = &clientIP
	ua := c.GetHeader("User-Agent")
	if ua != "" {
		req.UserAgent = &ua
	}

	actorEmail := "system"
	if req.ActorUserID != nil && *req.ActorUserID != "" {
		actorEmail = *req.ActorUserID
	}
	resource := req.TargetKind
	if req.TargetID != nil && *req.TargetID != "" {
		resource = req.TargetKind + ":" + *req.TargetID
	}
	// Group entries by the session that produced them, using the refresh-token
	// jti the access token carries (rjti) — it is stable for the life of a
	// login and survives token refresh. The previous value was
	// fmt.Sprintf("s-%d", time.Now().UnixNano()%100000): a fresh pseudo-random
	// string per ENTRY, so it looked like a session id, sorted like one, and
	// grouped nothing. Absent (e.g. on the login request itself, which has no
	// token yet) it is reported as "-" rather than invented.
	session := "-"
	if claims, ok := auth.GetClaims(c.Request.Context()); ok && claims != nil && claims.RefreshJTI != "" {
		session = claims.RefreshJTI
	}
	// The real outcome, not a hardcoded one. This stream fed the console's audit
	// view with "result":"SUCCESS" on every entry — including the failed logins
	// that are the whole point of watching it.
	auditData, _ := json.Marshal(map[string]interface{}{
		"ts":       time.Now().UTC().Format("2006-01-02 15:04:05"),
		"user":     actorEmail,
		"action":   req.Action,
		"resource": resource,
		"ip":       clientIP,
		"result":   auditResultOf(req.Diff),
		"session":  session,
	})
	hub.PublishDirect(logs.Entry{Kind: "audit", Data: json.RawMessage(auditData)})

	if store != nil {
		reqCopy := *req
		// Detach from the request context: the HTTP response often returns
		// before this write finishes, which would cancel c.Request.Context()
		// and silently drop the audit row. Use a fresh bounded context so the
		// audit entry is durably persisted regardless of response lifecycle.
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := store.WriteAuditLog(ctx, reqCopy, auditHMACKey()); err != nil {
				zap.L().Warn("audit write failed", zap.String("action", reqCopy.Action), zap.Error(err))
			}
		}()
	}
}

// devAuditHMACKey is the LAST-RESORT key used only when the operator has
// explicitly opted into dev-login mode. Production cannot reach it: run() in
// main.go refuses to start unless SENTINEL_AUDIT_HMAC_KEY is >= 32 chars or
// SENTINEL_DEV_LOGIN is set — the same fail-fast shape as SENTINEL_JWT_SECRET.
//
// It stays a named constant rather than an inline literal so that the one place
// a known key can be used is greppable, and so the dev/prod boundary is stated
// where the key is read rather than only where the process boots.
const devAuditHMACKey = "sentinel-dev-audit-hmac-key-change-in-prod"

// auditHMACKey returns the audit-chain HMAC key.
//
// With a known key the chain is not tamper-evident at all: anyone able to write
// to the database can forge a row and re-sign the chain past it. Hence the boot
// assertion in main.go. Reaching the dev key here therefore means dev-login mode
// was requested deliberately; log it once so it can never be a silent posture.
func auditHMACKey() []byte {
	if k := os.Getenv("SENTINEL_AUDIT_HMAC_KEY"); k != "" {
		return []byte(k)
	}
	warnDevAuditKeyOnce.Do(func() {
		zap.L().Warn("SENTINEL_AUDIT_HMAC_KEY is unset — signing the audit chain with the " +
			"PUBLIC dev key. The audit log is NOT tamper-evident in this state; it is " +
			"reachable only in dev-login mode and must never be used for a real deployment.")
	})
	return []byte(devAuditHMACKey)
}

var warnDevAuditKeyOnce sync.Once

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func osGetenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// Ensure io and fmt are used (SSE formatter needs them).
var _ = io.Discard
var _ = fmt.Sprintf

// ---------------------------------------------------------------------------
// Rule CRUD
// ---------------------------------------------------------------------------

func handleCreateRule(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *leader.Elector) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceRule, rbac.ActionCreate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	var req db.CreateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": clientError(err)})
		return
	}
	// Validate the DSL with the real engine. Unlike an UPDATE there is nothing
	// live to disarm here, so if the validator itself cannot run we store the rule
	// and say so — the enforcement-status layer will report it if the data plane
	// rejects it. An INVALID rule is still refused outright: storing one that can
	// never run is what made "enabled" meaningless in the first place.
	var createValidationSkipped bool
	if strings.TrimSpace(req.DSL) != "" {
		problem, skipped := rejectInvalidDSL(c.Request.Context(), req.DSL)
		if problem != "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "the rule is not valid SRL and was not saved",
				"detail":  problem,
				"invalid": true,
			})
			return
		}
		createValidationSkipped = skipped
	}

	// A rule scoped to a site the caller cannot see would be created and then
	// never delivered anywhere — it would sit in the UI looking enabled and do
	// nothing. Reject it with the reason instead. The tenant-scoped GetSite also
	// stops one tenant scoping a rule onto another tenant's site.
	if req.SiteID != nil && strings.TrimSpace(*req.SiteID) != "" && store != nil {
		if _, err := store.GetSite(c.Request.Context(), claims.TenantID, *req.SiteID); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "site_id does not refer to a site in this tenant; omit it for a " +
					"deployment-wide rule",
			})
			return
		}
	}
	if !requireLeader(c, cl) {
		return
	}
	if store != nil {
		rule, err := store.CreateRule(c.Request.Context(), claims.TenantID, claims.UserID, req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
			return
		}
		writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
			TenantID:    claims.TenantID,
			ActorUserID: &claims.UserID,
			Action:      "rule.create",
			TargetKind:  "rule",
			TargetID:    &rule.ID,
		})
		resp := gin.H{"rule": rule}
		if createValidationSkipped {
			// Honest about what did not happen, rather than implying the rule was
			// checked. The enforcement status will resolve it within seconds.
			resp["warning"] = "the rule was stored without validation because the " +
				"validator was unavailable on this node; check its enforcement status"
		}
		c.JSON(http.StatusCreated, resp)
		return
	}
	id := fmt.Sprintf("custom-%d", time.Now().UnixNano()%100000000)
	c.JSON(http.StatusCreated, gin.H{"rule": gin.H{
		"id": id, "tenant_id": claims.TenantID,
		"name": req.Name, "source": func() string {
			if req.Source != "" {
				return req.Source
			} else {
				return "custom"
			}
		}(),
		"phase": req.Phase, "severity": func() string {
			if req.Severity != "" {
				return req.Severity
			} else {
				return "medium"
			}
		}(),
		"dsl": req.DSL, "enabled": true, "tags": req.Tags,
		"created_at": time.Now(), "updated_at": time.Now(),
	}})
}

func handleToggleRule(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *leader.Elector) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceRule, rbac.ActionUpdate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	id := c.Param("id")
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": clientError(err)})
		return
	}
	if !requireLeader(c, cl) {
		return
	}
	if store != nil {
		if err := store.ToggleRule(c.Request.Context(), claims.TenantID, claims.UserID, id, req.Enabled); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
			return
		}
	}
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &claims.UserID,
		Action: fmt.Sprintf("rule.%s", func() string {
			if req.Enabled {
				return "enable"
			} else {
				return "disable"
			}
		}()),
		TargetKind: "rule",
		TargetID:   &id,
	})
	c.JSON(http.StatusOK, gin.H{"ok": true, "id": id, "enabled": req.Enabled})
}

func handleDeleteRule(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *leader.Elector) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceRule, rbac.ActionDelete) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	id := c.Param("id")
	if !requireLeader(c, cl) {
		return
	}
	if store != nil {
		if err := store.DeleteRule(c.Request.Context(), claims.TenantID, claims.UserID, id); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
			return
		}
	}
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &claims.UserID,
		Action:      "rule.delete",
		TargetKind:  "rule",
		TargetID:    &id,
	})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func handleTestRule(c *gin.Context, enf *rbac.Enforcer) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceRule, rbac.ActionRead) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	var req struct {
		DSL     string `json:"dsl"`
		Payload string `json:"payload"`
		Method  string `json:"method"`
		Path    string `json:"path"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": clientError(err)})
		return
	}

	// Runs the REAL parser, compiler and rule VM via the bundled srl-validate
	// binary. The previous implementation string-scanned for rx('...') and
	// compiled a Go regex, so it reported a fabricated verdict for a DSL the
	// engine would have rejected outright.
	res, err := validateSRL(c.Request.Context(), srlRequest{
		DSL:     req.DSL,
		Payload: req.Payload,
		Path:    req.Path,
		Method:  req.Method,
	})
	if err != nil {
		// Say validation could not run. Do NOT invent a verdict — a made-up
		// answer here is what this endpoint existed to stop being.
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "rule validation is unavailable on this node, so no verdict can " +
				"be given; the rule was not evaluated",
			"detail": err.Error(),
		})
		return
	}
	if !res.Valid {
		c.JSON(http.StatusOK, gin.H{
			"valid":   false,
			"verdict": "INVALID",
			"matched": false,
			"detail":  res.Error,
			"error":   res.Error,
		})
		return
	}

	verdict := "PASS"
	matched := res.Matched != nil && *res.Matched
	if matched {
		verdict = strings.ToUpper(res.Decision)
	}
	score := 0
	if res.Score != nil {
		score = *res.Score
	}
	detail := fmt.Sprintf("compiled %d rule(s)", len(res.Rules))
	if req.Payload == "" {
		detail += "; no payload supplied, so nothing was evaluated"
	} else if matched {
		detail = fmt.Sprintf("matched rule(s) %s", strings.Join(res.MatchedRuleIDs, ", "))
	} else {
		detail += "; the payload did not match"
	}

	c.JSON(http.StatusOK, gin.H{
		"valid":            true,
		"verdict":          verdict,
		"matched":          matched,
		"detail":           detail,
		"anomaly_score":    score,
		"decision":         res.Decision,
		"matched_rule_ids": res.MatchedRuleIDs,
		"rules":            res.Rules,
		"phases_run":       []string{"request_headers", "request_body", "response_headers", "response_body"},
	})
}

// testRuleDSL extracts the rx/contains operator from SRL DSL and tests it

// ---------------------------------------------------------------------------
// ML Stats
// ---------------------------------------------------------------------------

// handleMLStats reports what is MEASURED about the classifier, and explicitly
// reports that quality metrics are not measured rather than inventing them.
//
// This endpoint previously returned hardcoded literals — precision 0.953, recall
// 0.891, fp_rate 0.003 — plus three "Active Models" with invented versions,
// per-model precision/recall, latencies and last_updated dates. The dashboard
// rendered them as live gauges labelled "True positives / (TP + FP)", refreshed
// every 5 seconds, so they read as measurement. Two of the three models did not
// exist in any form: ml-models/bot-classifier and ml-models/anomaly are empty
// directories. `true_positives_today` was set to the raw ML anomaly count, which
// asserts every ML detection was correct — the precise claim nobody can make
// without ground truth.
//
// Precision, recall and false-positive rate CANNOT be computed here, and the
// reason is structural, not a missing feature: they require labelled ground truth
// — knowing which requests were genuinely attacks. The product does not have that
// and cannot until the learning-mode pilot produces triaged real traffic (see
// deploy/LEARNING-MODE-PILOT.md and scripts/fpr-report.sh). Until then the honest
// answer is "not measured", and a WAF that fabricates its own accuracy figures is
// worse than one that admits it has not measured them.
func handleMLStats(c *gin.Context, hub *logs.Hub, store *db.Store) {
	snap := hub.GetSnapshot()
	total := snap.TotalRequests
	blocked := snap.BlockedRequests
	ml := snap.MLAnomalies

	blockRate := 0.0
	if total > 0 {
		blockRate = float64(blocked) / float64(total) * 100
	}

	// model_status used to be the constant string "active". That was doubly
	// wrong: it asserted a state nobody checked, and the state it asserted is
	// false by default — the Rust config defaults ml.enable to false and the site
	// wizard creates sites with ML off, so a stock install runs rules-only.
	// Report the real enablement count instead, which is both true and the thing
	// an operator actually needs to know.
	mlSites, totalSites := 0, 0
	if store != nil {
		if claims, ok := auth.GetClaims(c.Request.Context()); ok {
			if sites, err := store.ListSites(c.Request.Context(), claims.TenantID, claims.UserID); err == nil {
				totalSites = len(sites)
				for _, s := range sites {
					var p struct {
						ML struct {
							Enable bool `json:"enable"`
						} `json:"ml"`
					}
					if json.Unmarshal(s.WafPolicy, &p) == nil && p.ML.Enable {
						mlSites++
					}
				}
			}
		}
	}
	modelStatus := "disabled on all sites"
	switch {
	case totalSites == 0:
		modelStatus = "no sites configured"
	case mlSites == totalSites:
		modelStatus = "enabled"
	case mlSites > 0:
		modelStatus = fmt.Sprintf("enabled on %d of %d sites", mlSites, totalSites)
	}

	c.JSON(http.StatusOK, gin.H{
		// ── Measured. These come from the live hub snapshot. ──
		"total_analyzed":     total,
		"anomalies_detected": ml,
		"block_rate":         blockRate,

		// ── Real enablement state, derived from stored site policy. ──
		"model_status":     modelStatus,
		"ml_enabled_sites": mlSites,
		"total_sites":      totalSites,

		// ── Not measured, and why. The dashboard renders this instead of gauges. ──
		"quality_measured": false,
		"quality_note": "Precision, recall and false-positive rate require labelled ground truth " +
			"and have not been measured on this deployment. Run a learning-mode pilot on real " +
			"traffic, then scripts/fpr-report.sh, to obtain them.",

		// ── The one classifier that actually ships. ──
		// Reported without accuracy figures on purpose: the model file carries
		// architecture and weights, not quality metrics.
		"models": []gin.H{
			{
				"name":         "payload-ngram",
				"kind":         "hashed char n-gram logistic regression",
				"buckets":      32768,
				"status":       "loaded",
				"metrics_note": "accuracy not measured on this deployment",
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Traffic History
// ---------------------------------------------------------------------------

func handleTrafficHistory(c *gin.Context, hub *logs.Hub) {
	buckets := hub.GetTrafficHistory(60)
	c.JSON(http.StatusOK, gin.H{"buckets": buckets})
}

// ---------------------------------------------------------------------------
// Prometheus metrics  GET /metrics
// ---------------------------------------------------------------------------
// Exposes the real, aggregated WAF metrics (from the data-plane NDJSON stream)
// in Prometheus text exposition format. Intended for internal scraping.
//
// If SENTINEL_METRICS_TOKEN is set, a matching `Authorization: Bearer <token>`
// is required (configure it as `authorization` in the Prometheus scrape job);
// when unset the endpoint is open for same-network scraping.

func promMetric(b *strings.Builder, name, typ, help string, val float64) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n%s %g\n", name, help, name, typ, name, val)
}

func handleMetrics(c *gin.Context, hub *logs.Hub) {
	if tok := os.Getenv("SENTINEL_METRICS_TOKEN"); tok != "" {
		got, _ := auth.BearerToken(c.GetHeader("Authorization"))
		if subtle.ConstantTimeCompare([]byte(got), []byte(tok)) != 1 {
			c.String(http.StatusUnauthorized, "unauthorized")
			return
		}
	}
	s := hub.GetSnapshot()
	var b strings.Builder
	promMetric(&b, "sentinel_requests_total", "counter", "Total requests processed by the data plane", float64(s.TotalRequests))
	promMetric(&b, "sentinel_blocked_total", "counter", "Requests blocked by the WAF", float64(s.BlockedRequests))
	promMetric(&b, "sentinel_ml_anomalies_total", "counter", "Requests flagged anomalous by ML", float64(s.MLAnomalies))
	promMetric(&b, "sentinel_errors_total", "counter", "Upstream/proxy errors", float64(s.ErrorCount))
	promMetric(&b, "sentinel_ebpf_drops_total", "counter", "Packets dropped by the L4 blocklist", float64(s.EbpfDrops))
	promMetric(&b, "sentinel_unique_blocked_ips", "gauge", "Distinct client IPs blocked", float64(s.UniqueBlockedIPs))
	promMetric(&b, "sentinel_requests_per_second", "gauge", "Current request rate", s.RPS)
	promMetric(&b, "sentinel_p99_latency_ms", "gauge", "p99 request latency in milliseconds", s.P99LatencyMs)
	promMetric(&b, "sentinel_connected_clients", "gauge", "Currently connected clients", float64(s.ConnectedClients))
	promMetric(&b, "sentinel_mem_used_bytes", "gauge", "Host memory used in bytes", float64(s.MemUsedBytes))

	// Response status classes as a labeled counter.
	b.WriteString("# HELP sentinel_responses_total Responses by HTTP status class\n# TYPE sentinel_responses_total counter\n")
	fmt.Fprintf(&b, "sentinel_responses_total{class=\"2xx\"} %d\n", s.Status2xx)
	fmt.Fprintf(&b, "sentinel_responses_total{class=\"3xx\"} %d\n", s.Status3xx)
	fmt.Fprintf(&b, "sentinel_responses_total{class=\"4xx\"} %d\n", s.Status4xx)
	fmt.Fprintf(&b, "sentinel_responses_total{class=\"5xx\"} %d\n", s.Status5xx)

	// Attack breakdown as a labeled counter (real rule-match categories).
	if len(s.AttackBreakdown) > 0 {
		b.WriteString("# HELP sentinel_attacks_total WAF rule matches by attack category\n# TYPE sentinel_attacks_total counter\n")
		for cat, n := range s.AttackBreakdown {
			fmt.Fprintf(&b, "sentinel_attacks_total{category=%q} %d\n", cat, n)
		}
	}

	c.Data(http.StatusOK, "text/plain; version=0.0.4; charset=utf-8", []byte(b.String()))
}

// ---------------------------------------------------------------------------
// Admin — Users & API Keys (real, DB-backed, tenant-scoped)
// ---------------------------------------------------------------------------

// validUserRole guards the 5-role model before it hits the DB CHECK constraint.
func validUserRole(r string) bool {
	switch r {
	case "owner", "admin", "editor", "viewer", "auditor":
		return true
	}
	return false
}

// respondStoreError maps a store/DB error to a sanitized client response so raw
// driver/schema detail (table names, constraints, SQLSTATE) never leaks to the
// caller: a unique-constraint violation becomes 409, a generic "not found"
// becomes 404, and anything else a generic 500. The raw error is intentionally
// not echoed.
func respondStoreError(c *gin.Context, err error) {
	var pgErr *pgconn.PgError
	switch {
	case errors.As(err, &pgErr) && pgErr.Code == "23505":
		c.JSON(http.StatusConflict, gin.H{"error": "already exists"})
	case err != nil && strings.Contains(err.Error(), "not found"):
		// Store not-found messages are fixed, safe strings (no user input).
		c.JSON(http.StatusNotFound, gin.H{"error": clientError(err)})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
	}
}

func handleListUsersReal(c *gin.Context, enf *rbac.Enforcer, store *db.Store) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceUser, rbac.ActionList) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusOK, gin.H{"users": []db.UserRow{}, "tenant_id": claims.TenantID})
		return
	}
	users, err := store.ListUsers(c.Request.Context(), claims.TenantID, claims.UserID)
	if err != nil {
		respondStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"users": users, "tenant_id": claims.TenantID})
}

func handleCreateUserReal(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceUser, rbac.ActionCreate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Name     string `json:"name"`
		Role     string `json:"role"`
		Password string `json:"password" binding:"required,min=12"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": clientError(err)})
		return
	}
	if req.Role == "" {
		req.Role = "viewer"
	}
	if !validUserRole(req.Role) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role"})
		return
	}
	u, err := store.CreateUser(c.Request.Context(), claims.TenantID, claims.UserID, req.Email, req.Name, req.Role, req.Password)
	if err != nil {
		respondStoreError(c, err)
		return
	}

	// Creating an account is a privileged security action and belongs in the
	// tamper-evident trail. The diff records who was created and with what role;
	// it must never carry the password, which is why only these fields are named.
	actorID := claims.UserID
	newID := u.ID
	diff, _ := json.Marshal(map[string]any{"email": u.Email, "role": u.Role})
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &actorID,
		Action:      "user.create",
		TargetKind:  "user",
		TargetID:    &newID,
		Diff:        diff,
	})

	c.JSON(http.StatusCreated, gin.H{"user": u})
}

func handleUpdateUser(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceUser, rbac.ActionUpdate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	var req struct {
		Role   string `json:"role"`
		Status string `json:"status"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": clientError(err)})
		return
	}
	if req.Role != "" && !validUserRole(req.Role) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role"})
		return
	}
	if problem, status := checkUserChange(c, store, claims.TenantID, claims.UserID, claims.Role, c.Param("id"), req.Role, req.Status, false); problem != "" {
		c.JSON(status, gin.H{"error": problem})
		return
	}
	if err := store.UpdateUser(c.Request.Context(), claims.TenantID, claims.UserID, c.Param("id"), req.Role, req.Status); err != nil {
		respondStoreError(c, err)
		return
	}

	// Role escalation is the single most valuable action an attacker can take
	// with a stolen admin session, and it was previously invisible. The diff
	// records what was requested; empty fields mean "left unchanged".
	actorID := claims.UserID
	targetID := c.Param("id")
	diff, _ := json.Marshal(map[string]any{"role": req.Role, "status": req.Status})
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &actorID,
		Action:      "user.update",
		TargetKind:  "user",
		TargetID:    &targetID,
		Diff:        diff,
	})

	// A disabled account must stop being able to act immediately rather than at
	// the end of its current access token's life.
	// Sign the user out here at once; the other nodes follow from the
	// sessions_valid_from column UpdateUser wrote, within the 5 s refresh.
	if req.Role != "" || strings.EqualFold(req.Status, "disabled") || strings.EqualFold(req.Status, "suspended") {
		sessionEpochs.set(targetID, time.Now().UTC())
	}

	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func handleDeleteUser(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceUser, rbac.ActionDelete) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	if c.Param("id") == claims.UserID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot delete your own account"})
		return
	}
	if problem, status := checkUserChange(c, store, claims.TenantID, claims.UserID, claims.Role, c.Param("id"), "", "", true); problem != "" {
		c.JSON(status, gin.H{"error": problem})
		return
	}
	if err := store.DeleteUser(c.Request.Context(), claims.TenantID, claims.UserID, c.Param("id")); err != nil {
		respondStoreError(c, err)
		return
	}

	// Deleting the account removes the row an audit entry would point at, so the
	// trail is the only remaining record that it ever existed — which is exactly
	// why "create, act, delete" left no trace before this.
	actorID := claims.UserID
	targetID := c.Param("id")
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &actorID,
		Action:      "user.delete",
		TargetKind:  "user",
		TargetID:    &targetID,
	})
	// Here at once; the other nodes notice the missing row on their next refresh.
	sessionEpochs.markDeleted(targetID, time.Now().UTC())

	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func handleListAPIKeysReal(c *gin.Context, enf *rbac.Enforcer, store *db.Store) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceAPIKey, rbac.ActionList) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusOK, gin.H{"api_keys": []db.APIKeyRow{}, "tenant_id": claims.TenantID})
		return
	}
	keys, err := store.ListAPIKeys(c.Request.Context(), claims.TenantID, claims.UserID)
	if err != nil {
		respondStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"api_keys": keys, "tenant_id": claims.TenantID})
}

func handleCreateAPIKeyReal(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceAPIKey, rbac.ActionCreate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	var req struct {
		Name        string   `json:"name" binding:"required"`
		Role        string   `json:"role"`
		Scopes      []string `json:"scopes"`
		ExpiresDays int      `json:"expires_days"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": clientError(err)})
		return
	}
	if req.Role == "" {
		req.Role = "viewer"
	}
	if !validUserRole(req.Role) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role"})
		return
	}
	var expiresAt *time.Time
	if req.ExpiresDays > 0 {
		t := time.Now().Add(time.Duration(req.ExpiresDays) * 24 * time.Hour)
		expiresAt = &t
	}
	row, fullKey, err := store.CreateAPIKey(c.Request.Context(), claims.TenantID, claims.UserID, req.Name, req.Role, req.Scopes, expiresAt)
	if err != nil {
		respondStoreError(c, err)
		return
	}

	// Minting a key is issuing a second, longer-lived credential — an admin-role
	// key is equivalent to an admin account. The diff records the name and the
	// privileges granted, never the key itself (which is returned to the caller
	// once and stored only as a hash).
	actorID := claims.UserID
	keyID := row.ID
	diff, _ := json.Marshal(map[string]any{"name": row.Name, "role": row.Role, "scopes": req.Scopes})
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &actorID,
		Action:      "apikey.create",
		TargetKind:  "apikey",
		TargetID:    &keyID,
		Diff:        diff,
	})

	c.JSON(http.StatusCreated, gin.H{
		"api_key": row,
		"key":     fullKey, // shown exactly once
		"warning": "Copy this key now — it is stored hashed and will never be shown again.",
	})
}

func handleRevokeAPIKey(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceAPIKey, rbac.ActionDelete) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	if err := store.RevokeAPIKey(c.Request.Context(), claims.TenantID, claims.UserID, c.Param("id")); err != nil {
		respondStoreError(c, err)
		return
	}

	actorID := claims.UserID
	keyID := c.Param("id")
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &actorID,
		Action:      "apikey.delete",
		TargetKind:  "apikey",
		TargetID:    &keyID,
	})

	c.JSON(http.StatusOK, gin.H{"ok": true, "message": "API key revoked"})
}
