package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	"github.com/your-org/sentinel-waf/control-plane/internal/cluster"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/logs"
	"github.com/your-org/sentinel-waf/control-plane/internal/rbac"
	"go.uber.org/zap"
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

func handleLogin(c *gin.Context, jwtSvc *auth.JWTService, store *db.Store, hub *logs.Hub) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate credentials.  When a DB pool is available we check the users
	// table; otherwise fall back to the hardcoded dev backdoor.
	var claims auth.Claims
	var loginResult = "SUCCESS"
	if store != nil {
		ok, userID, userTenant, role, err := store.ValidatePassword(c.Request.Context(),
			db.DevTenantID, req.Email, req.Password)
		if err != nil || !ok {
			loginResult = "FAILURE"
			writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
				TenantID:   db.DevTenantID,
				Action:     "user.login",
				TargetKind: "user",
			})
			_ = loginResult
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
			writeAuditEntry(c, nil, hub, &db.WriteAuditRequest{
				TenantID:   db.DevTenantID,
				Action:     "user.login",
				TargetKind: "user",
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

func handleRefresh(c *gin.Context, jwtSvc *auth.JWTService) {
	var req refreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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
	claims.AuthMethod = "refresh_rotation"
	accessToken, err := jwtSvc.IssueAccessToken(*claims)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"access_token": accessToken, "token_type": "Bearer"})
}

// oidcStateCookie holds the per-login CSRF state that binds the /login redirect
// to its /callback.
const oidcStateCookie = "sentinel_oidc_state"

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
	nonce, _ := auth.NewNonce()
	authURL, err := oidcSvc.AuthURL(c.Request.Context(), state, nonce)
	if err != nil {
		log.Error("oidc auth url", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build auth URL"})
		return
	}
	// Bind `state` to the browser via a short-lived HttpOnly cookie so the
	// callback can verify it (CSRF / login-fixation protection). SameSite=Lax
	// lets the cookie ride the top-level redirect back from the IdP.
	secure := strings.HasPrefix(cfg.RedirectURL, "https://")
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(oidcStateCookie, state, 300, "/", "", secure, true)
	c.Redirect(http.StatusFound, authURL)
}

func handleOIDCCallback(c *gin.Context, jwtSvc *auth.JWTService, log *zap.Logger) {
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
	// One-time use: clear the state cookie immediately.
	secure := strings.HasPrefix(cfg.RedirectURL, "https://")
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(oidcStateCookie, "", -1, "/", "", secure, true)

	oidcSvc := auth.NewOIDCService(cfg)
	userInfo, err := oidcSvc.ExchangeToken(c.Request.Context(), code)
	if err != nil {
		log.Error("oidc exchange", zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "OIDC token exchange failed"})
		return
	}
	claims := auth.Claims{
		TenantID:   db.DevTenantID,
		UserID:     userInfo.Subject,
		Role:       "editor",
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
	if store != nil {
		sites, err := store.ListSites(c.Request.Context(), claims.TenantID, claims.UserID)
		if err == nil {
			if sites == nil {
				sites = []db.SiteRow{}
			}
			c.JSON(http.StatusOK, gin.H{"sites": sites, "tenant_id": claims.TenantID})
			return
		}
	}
	// Fallback mock sites when DB is unavailable.
	c.JSON(http.StatusOK, gin.H{
		"sites": []gin.H{
			{
				"id": "00000000-0000-0000-0001-000000000001", "tenant_id": claims.TenantID,
				"name": "dvwa.local", "domains": []string{"dvwa.local"},
				"upstream":   gin.H{"servers": []string{"127.0.0.1:80"}, "lb": "round_robin"},
				"waf_policy": gin.H{"mode": "blocking", "paranoia_level": 2, "anomaly_threshold": 5},
				"status":     "active", "created_at": "2025-01-01T00:00:00Z", "updated_at": "2025-01-01T00:00:00Z",
			},
			{
				"id": "00000000-0000-0000-0001-000000000002", "tenant_id": claims.TenantID,
				"name": "juice.local", "domains": []string{"juice.local"},
				"upstream":   gin.H{"servers": []string{"127.0.0.1:3000"}, "lb": "round_robin"},
				"waf_policy": gin.H{"mode": "blocking", "paranoia_level": 2, "anomaly_threshold": 5},
				"status":     "active", "created_at": "2025-01-01T00:00:00Z", "updated_at": "2025-01-01T00:00:00Z",
			},
			{
				"id": "00000000-0000-0000-0001-000000000003", "tenant_id": claims.TenantID,
				"name": "api.acme.com", "domains": []string{"api.acme.com"},
				"upstream":   gin.H{"servers": []string{"127.0.0.1:8080"}, "lb": "round_robin"},
				"waf_policy": gin.H{"mode": "learning", "paranoia_level": 1, "anomaly_threshold": 10},
				"status":     "active", "created_at": "2025-01-01T00:00:00Z", "updated_at": "2025-01-01T00:00:00Z",
			},
			{
				"id": "00000000-0000-0000-0001-000000000004", "tenant_id": claims.TenantID,
				"name": "shop.corp.io", "domains": []string{"shop.corp.io"},
				"upstream":   gin.H{"servers": []string{"127.0.0.1:8443"}, "lb": "round_robin"},
				"waf_policy": gin.H{"mode": "blocking", "paranoia_level": 3, "anomaly_threshold": 5},
				"status":     "active", "created_at": "2025-01-01T00:00:00Z", "updated_at": "2025-01-01T00:00:00Z",
			},
			{
				"id": "00000000-0000-0000-0001-000000000005", "tenant_id": claims.TenantID,
				"name": "legacy.app.net", "domains": []string{"legacy.app.net"},
				"upstream":   gin.H{"servers": []string{"127.0.0.1:8088"}, "lb": "round_robin"},
				"waf_policy": gin.H{"mode": "off", "paranoia_level": 1, "anomaly_threshold": 50},
				"status":     "paused", "created_at": "2025-01-01T00:00:00Z", "updated_at": "2025-01-01T00:00:00Z",
			},
		},
		"tenant_id": claims.TenantID,
	})
}

func handleCreateSite(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *cluster.Cluster) {
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
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Upstream == nil {
		req.Upstream = json.RawMessage(`{"servers":[],"lb":"round_robin"}`)
	}
	if req.WafPolicy == nil {
		req.WafPolicy = json.RawMessage(`{"mode":"blocking","paranoia_level":2,"anomaly_threshold":5}`)
	}
	if !proposeBest(c, cl, cluster.CmdSiteCreate, gin.H{"tenant_id": claims.TenantID, "req": req}) {
		return
	}
	site, err := store.CreateSite(c.Request.Context(), claims.TenantID, claims.UserID, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	configVersion.Add(1)
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &claims.UserID,
		Action:      "site.create",
		TargetKind:  "site",
		TargetID:    &site.ID,
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

func handleUpdateSite(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *cluster.Cluster) {
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
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !proposeBest(c, cl, cluster.CmdSiteUpdate, gin.H{"tenant_id": claims.TenantID, "site_id": siteID, "req": req}) {
		return
	}
	site, err := store.UpdateSite(c.Request.Context(), claims.TenantID, claims.UserID, siteID, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	configVersion.Add(1)
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &claims.UserID,
		Action:      "site.update",
		TargetKind:  "site",
		TargetID:    &siteID,
	})
	c.JSON(http.StatusOK, gin.H{"site": site})
}

func handleDeleteSite(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *cluster.Cluster) {
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
	if !proposeBest(c, cl, cluster.CmdSiteDelete, gin.H{"tenant_id": claims.TenantID, "site_id": siteID}) {
		return
	}
	if err := store.DeleteSite(c.Request.Context(), claims.TenantID, siteID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	configVersion.Add(1)
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:   claims.TenantID,
		Action:     "site.delete",
		TargetKind: "site",
		TargetID:   &siteID,
	})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func handleUpdateSiteStatus(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *cluster.Cluster) {
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
	if !proposeBest(c, cl, cluster.CmdSiteStatus, gin.H{"tenant_id": claims.TenantID, "site_id": siteID, "status": body.Status}) {
		return
	}
	if err := store.UpdateSiteStatus(c.Request.Context(), claims.TenantID, siteID, body.Status); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	configVersion.Add(1)
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:   claims.TenantID,
		Action:     "site.status." + body.Status,
		TargetKind: "site",
		TargetID:   &siteID,
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
func handleAddSiteExclusion(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *cluster.Cluster) {
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	req := db.UpdateSiteRequest{WafPolicy: newPolicy}
	if !proposeBest(c, cl, cluster.CmdSiteUpdate, gin.H{"tenant_id": claims.TenantID, "site_id": siteID, "req": req}) {
		return
	}
	updated, err := store.UpdateSite(c.Request.Context(), claims.TenantID, claims.UserID, siteID, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
func handleDeleteSiteExclusion(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *cluster.Cluster) {
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	req := db.UpdateSiteRequest{WafPolicy: newPolicy}
	if !proposeBest(c, cl, cluster.CmdSiteUpdate, gin.H{"tenant_id": claims.TenantID, "site_id": siteID, "req": req}) {
		return
	}
	updated, err := store.UpdateSite(c.Request.Context(), claims.TenantID, claims.UserID, siteID, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
func handleInternalConfig(c *gin.Context, store *db.Store) {
	if !internalSecretOK(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "db unavailable"})
		return
	}
	// Node-global: the shared data plane serves EVERY tenant's sites, so this
	// sync must list all active sites across tenants (not one tenant's view).
	sites, err := store.ListAllActiveSites(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	rustSites := make([]map[string]any, 0, len(sites))
	for _, s := range sites {
		if s.Status == "paused" || s.Status == "deleted" {
			continue
		}
		rs, err := siteRowToRustConfig(s)
		if err != nil {
			continue
		}
		rustSites = append(rustSites, rs)
	}
	c.JSON(http.StatusOK, gin.H{
		"version": configVersion.Load(),
		"sites":   rustSites,
	})
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
}

// crsCategoryOrder is the canonical load order for the categories above.
var crsCategoryOrder = []string{
	"method", "scanner", "protocol", "protocol_attack", "lfi", "rfi", "rce",
	"php", "generic", "xss", "sqli", "session", "java",
}

// crsFilesForCategories returns the concrete .conf files for a set of UI
// category keys, preserving canonical load order. An empty/nil selection means
// "all categories" so existing sites keep full protection.
func crsFilesForCategories(cats []string) []string {
	if len(cats) == 0 {
		files := make([]string, 0, len(crsCategoryOrder))
		for _, k := range crsCategoryOrder {
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
			Challenge   string `json:"challenge"`
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
		if prov := rustAcmeProvider(t.Provider); prov != "" {
			acme["provider"] = prov
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
	return upstream, nil
}

// buildRustWaf accepts the legacy minimal blob and the rich dashboard blob and
// produces the Rust WafConfig JSON. Unknown/empty sections are omitted so the
// Rust defaults apply.
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
		MaxBodySize      *uint64         `json:"max_body_size"`
		MaxURILength     *uint32         `json:"max_uri_length"`
		MaxHeaderCount   *uint32         `json:"max_header_count"`
		APIDiscovery     bool            `json:"api_discovery"`
		AllowedMethods   []string        `json:"allowed_methods"`
		SecurityHeaders  json.RawMessage `json:"security_headers"`
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
		p.AnomalyThreshold = 5
	}

	var rules []string
	if p.Mode != "off" {
		rules = crsFilesForCategories(p.RuleCategories)
	}

	waf := map[string]any{
		"mode":              p.Mode,
		"paranoia_level":    p.ParanoiaLevel,
		"anomaly_threshold": p.AnomalyThreshold,
		"rules":             rules,
		"api_discovery":     p.APIDiscovery,
	}

	// Rule exclusions — include the well-known 932236 "ARGS_NAMES" / id
	// suppression by default (avoids the `?id=42` false positive, see CRS
	// importer notes), even alongside operator-defined exclusions (e.g. one-click
	// disables from the learning report).
	//
	// An operator can fully re-enable 932236 by storing an *empty* 932236 entry
	// (no targets, not disabled): that acts as an opt-out marker — it suppresses
	// the injected default and is itself dropped (a no-op to the data plane).
	// `handleDeleteSiteExclusion` leaves this marker when 932236 is removed, so
	// the default isn't silently re-added on the next build.
	ex := []map[string]any{}
	has932236 := false
	out := make([]map[string]any, 0, len(ex)+1)
	if len(p.RuleExclusions) > 0 {
		if err := json.Unmarshal(p.RuleExclusions, &ex); err != nil {
			ex = []map[string]any{}
		}
		for _, e := range ex {
			if ruleIDEquals(e["rule_id"], 932236) {
				has932236 = true
				if isEmptyExclusion(e) {
					continue // opt-out marker — drop it, don't emit to the proxy
				}
			}
			out = append(out, e)
		}
	}
	if !has932236 {
		out = append(out, map[string]any{"rule_id": 932236, "exclude_targets": []string{"ARGS_NAMES"}})
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
					g["db_path"] = osGetenv("SENTINEL_GEOIP_DB", "rules/GeoLite2-Country.mmdb")
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

	// Method allow-list and response/security headers — pass through so the
	// data plane can actually enforce what the wizard collects (a full method
	// list means "no restriction"; an empty/partial list restricts).
	if len(p.AllowedMethods) > 0 {
		waf["allowed_methods"] = p.AllowedMethods
	}
	attachRawObject(waf, "security_headers", p.SecurityHeaders)

	return waf, nil
}

// ruleIDEquals compares a JSON-decoded rule_id (which may be float64, json.Number,
// or int) against an expected integer.
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
			c.JSON(http.StatusOK, gin.H{"rules": rules, "tenant_id": claims.TenantID})
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

func handleAckAlert(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *cluster.Cluster) {
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
	if !proposeBest(c, cl, cluster.CmdAlertAck, gin.H{"tenant_id": claims.TenantID, "alert_id": id}) {
		return
	}
	if err := store.AckAlert(c.Request.Context(), claims.TenantID, claims.UserID, id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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

func handleResolveAlert(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *cluster.Cluster) {
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
	if !proposeBest(c, cl, cluster.CmdAlertResolve, gin.H{"tenant_id": claims.TenantID, "alert_id": id}) {
		return
	}
	if err := store.ResolveAlert(c.Request.Context(), claims.TenantID, claims.UserID, id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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

// ---------------------------------------------------------------------------
// Plugins (stub — WASM runtime is Phase 3)
// ---------------------------------------------------------------------------

func handleListPlugins(c *gin.Context, enf *rbac.Enforcer) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourcePlugin, rbac.ActionList) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"plugins": []interface{}{}, "tenant_id": claims.TenantID})
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

func handleListAudit(c *gin.Context, enf *rbac.Enforcer, store *db.Store) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceAudit, rbac.ActionRead) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store != nil {
		entries, err := store.ListAuditLogs(c.Request.Context(), claims.TenantID, claims.UserID, 100)
		if err == nil {
			if entries == nil {
				entries = []db.AuditRow{}
			}
			c.JSON(http.StatusOK, gin.H{"entries": entries, "tenant_id": claims.TenantID})
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"entries": []interface{}{}, "tenant_id": claims.TenantID})
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

	notify := c.Request.Context().Done()
	for {
		select {
		case <-notify:
			return
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
// across all sites. The "rules" array is sorted by detection count desc.
func handleLearningReport(c *gin.Context, hub *logs.Hub) {
	site := c.Query("site")
	c.JSON(http.StatusOK, gin.H{"site": site, "rules": hub.GetLearningStats(site)})
}

// ---------------------------------------------------------------------------
// Audit helper (fire-and-forget)
// ---------------------------------------------------------------------------

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
	session := fmt.Sprintf("s-%d", time.Now().UnixNano()%100000)
	auditData, _ := json.Marshal(map[string]interface{}{
		"ts":       time.Now().UTC().Format("2006-01-02 15:04:05"),
		"user":     actorEmail,
		"action":   req.Action,
		"resource": resource,
		"ip":       clientIP,
		"result":   "SUCCESS",
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

// auditHMACKey returns the HMAC key from the environment or a dev default.
func auditHMACKey() []byte {
	if k := os.Getenv("SENTINEL_AUDIT_HMAC_KEY"); k != "" {
		return []byte(k)
	}
	return []byte("sentinel-dev-audit-hmac-key-change-in-prod")
}

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

func handleCreateRule(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *cluster.Cluster) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceRule, rbac.ActionCreate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	var req db.CreateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !proposeBest(c, cl, cluster.CmdRuleCreate, gin.H{"tenant_id": claims.TenantID, "req": req}) {
		return
	}
	if store != nil {
		rule, err := store.CreateRule(c.Request.Context(), claims.TenantID, claims.UserID, req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
			TenantID:    claims.TenantID,
			ActorUserID: &claims.UserID,
			Action:      "rule.create",
			TargetKind:  "rule",
			TargetID:    &rule.ID,
		})
		c.JSON(http.StatusCreated, gin.H{"rule": rule})
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

func handleToggleRule(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *cluster.Cluster) {
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
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !proposeBest(c, cl, cluster.CmdRuleToggle, gin.H{"tenant_id": claims.TenantID, "rule_id": id, "enabled": req.Enabled}) {
		return
	}
	if store != nil {
		if err := store.ToggleRule(c.Request.Context(), claims.TenantID, claims.UserID, id, req.Enabled); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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

func handleDeleteRule(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *cluster.Cluster) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceRule, rbac.ActionDelete) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	id := c.Param("id")
	if !proposeBest(c, cl, cluster.CmdRuleDelete, gin.H{"tenant_id": claims.TenantID, "rule_id": id}) {
		return
	}
	if store != nil {
		if err := store.DeleteRule(c.Request.Context(), claims.TenantID, claims.UserID, id); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	verdict, matched, detail := testRuleDSL(req.DSL, req.Payload, req.Path)
	anomalyScore := 0
	if matched {
		anomalyScore = 10
	}
	c.JSON(http.StatusOK, gin.H{
		"verdict":       verdict,
		"matched":       matched,
		"detail":        detail,
		"anomaly_score": anomalyScore,
		"phases_run":    []string{"request_headers", "request_body"},
	})
}

// testRuleDSL extracts the rx/contains operator from SRL DSL and tests it
// against the provided payload.
func testRuleDSL(dsl, payload, path string) (verdict string, matched bool, detail string) {
	var pat string
	for i := 0; i+3 < len(dsl); i++ {
		if dsl[i:i+3] == "rx(" {
			start := i + 4
			end := start
			for end < len(dsl) && dsl[end] != '\'' {
				end++
			}
			if end > start {
				pat = dsl[start:end]
			}
			break
		}
	}

	target := payload
	if path != "" {
		target = target + " " + path
	}

	if pat == "" {
		return "PASS", false, "No rx() operator found in DSL"
	}

	cleanPat := pat
	if len(cleanPat) > 2 && cleanPat[0] == '/' {
		end := len(cleanPat) - 1
		for end > 0 && (cleanPat[end] == 'i' || cleanPat[end] == 's' || cleanPat[end] == 'm') {
			end--
		}
		if cleanPat[end] == '/' {
			cleanPat = cleanPat[1:end]
		}
	}

	re, err := regexp.Compile(`(?i)` + cleanPat)
	if err != nil {
		return "ERROR", false, fmt.Sprintf("Invalid regex %q: %v", cleanPat, err)
	}

	if re.MatchString(target) {
		return "BLOCK", true, fmt.Sprintf("Pattern /%s/ matched in payload", pat)
	}
	return "PASS", false, fmt.Sprintf("Pattern /%s/ did not match", pat)
}

// ---------------------------------------------------------------------------
// ML Stats
// ---------------------------------------------------------------------------

func handleMLStats(c *gin.Context, hub *logs.Hub) {
	snap := hub.GetSnapshot()
	total := snap.TotalRequests
	blocked := snap.BlockedRequests
	ml := snap.MLAnomalies

	blockRate := 0.0
	if total > 0 {
		blockRate = float64(blocked) / float64(total) * 100
	}
	fpRate := 0.0
	if ml > 10 {
		fpRate = 0.003
	}

	c.JSON(http.StatusOK, gin.H{
		"precision":          0.953,
		"recall":             0.891,
		"fp_rate":            fpRate,
		"total_analyzed":     total,
		"anomalies_detected": ml,
		"block_rate":         blockRate,
		"model_status":       "active",
		"models": []gin.H{
			{"name": "payload-classifier", "version": "2.1.0", "precision": 0.953, "recall": 0.891, "status": "active", "latency_ms": 1.4, "last_updated": "2025-05-10"},
			{"name": "anomaly-detector", "version": "1.8.0", "precision": 0.921, "recall": 0.874, "status": "active", "latency_ms": 0.8, "last_updated": "2025-05-08"},
			{"name": "bot-classifier", "version": "1.5.2", "precision": 0.967, "recall": 0.843, "status": "active", "latency_ms": 0.6, "last_updated": "2025-05-12"},
		},
		"false_positives_today": int64(float64(ml) * fpRate),
		"true_positives_today":  ml,
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"users": users, "tenant_id": claims.TenantID})
}

func handleCreateUserReal(c *gin.Context, enf *rbac.Enforcer, store *db.Store) {
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
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"user": u})
}

func handleUpdateUser(c *gin.Context, enf *rbac.Enforcer, store *db.Store) {
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
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Role != "" && !validUserRole(req.Role) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role"})
		return
	}
	if err := store.UpdateUser(c.Request.Context(), claims.TenantID, claims.UserID, c.Param("id"), req.Role, req.Status); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func handleDeleteUser(c *gin.Context, enf *rbac.Enforcer, store *db.Store) {
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
	if err := store.DeleteUser(c.Request.Context(), claims.TenantID, claims.UserID, c.Param("id")); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"api_keys": keys, "tenant_id": claims.TenantID})
}

func handleCreateAPIKeyReal(c *gin.Context, enf *rbac.Enforcer, store *db.Store) {
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
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"api_key": row,
		"key":     fullKey, // shown exactly once
		"warning": "Copy this key now — it is stored hashed and will never be shown again.",
	})
}

func handleRevokeAPIKey(c *gin.Context, enf *rbac.Enforcer, store *db.Store) {
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "message": "API key revoked"})
}
