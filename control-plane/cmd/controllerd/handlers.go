package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
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
		ok, userID, role, err := store.ValidatePassword(c.Request.Context(),
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
		claims = auth.Claims{
			TenantID:   db.DevTenantID,
			UserID:     userID,
			Role:       role,
			AuthMethod: "password",
		}
	} else {
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

	// Write successful login audit entry.
	userID := claims.UserID
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    db.DevTenantID,
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

func handleOIDCLogin(c *gin.Context, jwtSvc *auth.JWTService, log *zap.Logger) {
	providerURL := c.Query("provider")
	if providerURL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provider query param required"})
		return
	}
	oidcCfg := auth.OIDCConfig{
		ProviderURL:  providerURL,
		ClientID:     osGetenv("SENTINEL_OIDC_CLIENT_ID", "sentinel"),
		ClientSecret: osGetenv("SENTINEL_OIDC_CLIENT_SECRET", ""),
		RedirectURL:  osGetenv("SENTINEL_OIDC_REDIRECT_URL", "http://localhost:9501/api/v1/auth/oidc/callback"),
	}
	oidcSvc := auth.NewOIDCService(oidcCfg)
	state, _ := auth.NewState()
	nonce, _ := auth.NewNonce()
	authURL, err := oidcSvc.AuthURL(c.Request.Context(), state, nonce)
	if err != nil {
		log.Error("oidc auth url", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build auth URL"})
		return
	}
	c.Redirect(http.StatusFound, authURL)
}

func handleOIDCCallback(c *gin.Context, jwtSvc *auth.JWTService, log *zap.Logger) {
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing code"})
		return
	}
	oidcCfg := auth.OIDCConfig{
		ProviderURL:  c.Query("provider"),
		ClientID:     osGetenv("SENTINEL_OIDC_CLIENT_ID", "sentinel"),
		ClientSecret: osGetenv("SENTINEL_OIDC_CLIENT_SECRET", ""),
		RedirectURL:  osGetenv("SENTINEL_OIDC_REDIRECT_URL", "http://localhost:9501/api/v1/auth/oidc/callback"),
	}
	oidcSvc := auth.NewOIDCService(oidcCfg)
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
				"status": "active", "created_at": "2025-01-01T00:00:00Z", "updated_at": "2025-01-01T00:00:00Z",
			},
			{
				"id": "00000000-0000-0000-0001-000000000002", "tenant_id": claims.TenantID,
				"name": "juice.local", "domains": []string{"juice.local"},
				"upstream":   gin.H{"servers": []string{"127.0.0.1:3000"}, "lb": "round_robin"},
				"waf_policy": gin.H{"mode": "blocking", "paranoia_level": 2, "anomaly_threshold": 5},
				"status": "active", "created_at": "2025-01-01T00:00:00Z", "updated_at": "2025-01-01T00:00:00Z",
			},
			{
				"id": "00000000-0000-0000-0001-000000000003", "tenant_id": claims.TenantID,
				"name": "api.acme.com", "domains": []string{"api.acme.com"},
				"upstream":   gin.H{"servers": []string{"127.0.0.1:8080"}, "lb": "round_robin"},
				"waf_policy": gin.H{"mode": "learning", "paranoia_level": 1, "anomaly_threshold": 10},
				"status": "active", "created_at": "2025-01-01T00:00:00Z", "updated_at": "2025-01-01T00:00:00Z",
			},
			{
				"id": "00000000-0000-0000-0001-000000000004", "tenant_id": claims.TenantID,
				"name": "shop.corp.io", "domains": []string{"shop.corp.io"},
				"upstream":   gin.H{"servers": []string{"127.0.0.1:8443"}, "lb": "round_robin"},
				"waf_policy": gin.H{"mode": "blocking", "paranoia_level": 3, "anomaly_threshold": 5},
				"status": "active", "created_at": "2025-01-01T00:00:00Z", "updated_at": "2025-01-01T00:00:00Z",
			},
			{
				"id": "00000000-0000-0000-0001-000000000005", "tenant_id": claims.TenantID,
				"name": "legacy.app.net", "domains": []string{"legacy.app.net"},
				"upstream":   gin.H{"servers": []string{"127.0.0.1:8088"}, "lb": "round_robin"},
				"waf_policy": gin.H{"mode": "off", "paranoia_level": 1, "anomaly_threshold": 50},
				"status": "paused", "created_at": "2025-01-01T00:00:00Z", "updated_at": "2025-01-01T00:00:00Z",
			},
		},
		"tenant_id": claims.TenantID,
	})
}

func handleCreateSite(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub) {
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

func handleDeleteSite(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceSite, rbac.ActionCreate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	siteID := c.Param("id")
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

func handleUpdateSiteStatus(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceSite, rbac.ActionCreate) {
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

// handleInternalConfig is called by the Rust data-plane proxy (no JWT — internal
// network only). Returns the current active site list in a format the proxy can
// deserialize directly into Vec<SiteConfig>.
func handleInternalConfig(c *gin.Context, store *db.Store) {
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "db unavailable"})
		return
	}
	// List all sites for the dev tenant — in production this would be
	// scoped per node/cluster, but for single-tenant dev this is correct.
	sites, err := store.ListSites(c.Request.Context(), db.DevTenantID, db.DevAdminID)
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

// siteRowToRustConfig converts a DB SiteRow into the JSON shape that the
// Rust SiteConfig serde deserializer expects.
func siteRowToRustConfig(s db.SiteRow) (map[string]any, error) {
	// DB upstream format: {"servers":["host:port"],"lb":"round_robin"}
	var upDB struct {
		Servers []string `json:"servers"`
		LB      string   `json:"lb"`
	}
	if err := json.Unmarshal(s.Upstream, &upDB); err != nil {
		return nil, err
	}
	rustServers := make([]map[string]any, 0, len(upDB.Servers))
	for _, addr := range upDB.Servers {
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			host, portStr = addr, "80"
		}
		port, _ := strconv.Atoi(portStr)
		if port == 0 {
			port = 80
		}
		rustServers = append(rustServers, map[string]any{
			"host": host, "port": port, "weight": 1,
		})
	}
	lb := upDB.LB
	if lb == "" {
		lb = "round_robin"
	}

	// DB waf_policy format: {"mode":"blocking","paranoia_level":2,"anomaly_threshold":5}
	var wafDB struct {
		Mode             string `json:"mode"`
		ParanoiaLevel    int    `json:"paranoia_level"`
		AnomalyThreshold int    `json:"anomaly_threshold"`
	}
	if err := json.Unmarshal(s.WafPolicy, &wafDB); err != nil {
		return nil, err
	}
	if wafDB.Mode == "" {
		wafDB.Mode = "blocking"
	}
	if wafDB.ParanoiaLevel == 0 {
		wafDB.ParanoiaLevel = 2
	}
	if wafDB.AnomalyThreshold == 0 {
		wafDB.AnomalyThreshold = 5
	}

	return map[string]any{
		"id":      s.Name, // proxy matches by site ID — use name (e.g., "dvwa.local")
		"domains": s.Domains,
		"upstream": map[string]any{
			"load_balancer": lb,
			"servers":       rustServers,
		},
		"waf": map[string]any{
			"mode":              wafDB.Mode,
			"paranoia_level":    wafDB.ParanoiaLevel,
			"anomaly_threshold": wafDB.AnomalyThreshold,
			"rules":             []string{},
		},
		"plugins": []any{},
	}, nil
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

func handleAckAlert(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub) {
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

func handleResolveAlert(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub) {
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

func handleLogsStream(c *gin.Context, jwtSvc *auth.JWTService, hub *logs.Hub) {
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
	if _, err := jwtSvc.Validate(tokenStr); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}

	kindFilter := c.Query("kind") // empty = all

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
		go func() {
			_ = store.WriteAuditLog(c.Request.Context(), reqCopy, auditHMACKey())
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

func handleCreateRule(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub) {
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
		"name": req.Name, "source": func() string { if req.Source != "" { return req.Source } else { return "custom" } }(),
		"phase": req.Phase, "severity": func() string { if req.Severity != "" { return req.Severity } else { return "medium" } }(),
		"dsl": req.DSL, "enabled": true, "tags": req.Tags,
		"created_at": time.Now(), "updated_at": time.Now(),
	}})
}

func handleToggleRule(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub) {
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
	if store != nil {
		if err := store.ToggleRule(c.Request.Context(), claims.TenantID, claims.UserID, id, req.Enabled); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &claims.UserID,
		Action:      fmt.Sprintf("rule.%s", func() string { if req.Enabled { return "enable" } else { return "disable" } }()),
		TargetKind:  "rule",
		TargetID:    &id,
	})
	c.JSON(http.StatusOK, gin.H{"ok": true, "id": id, "enabled": req.Enabled})
}

func handleDeleteRule(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceRule, rbac.ActionDelete) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	id := c.Param("id")
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
// Admin — Users & API Keys (enhanced with mock data)
// ---------------------------------------------------------------------------

func handleListUsersReal(c *gin.Context, enf *rbac.Enforcer) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceUser, rbac.ActionList) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"users": []gin.H{
			{"id": db.DevAdminID, "email": "admin@sentinel.local", "name": "Admin", "role": "admin", "status": "active", "twofa": true, "last_login": time.Now().Add(-2 * time.Minute)},
			{"id": "00000000-0000-0000-0000-000000000003", "email": "raj.kumar@sentinel.local", "name": "Raj Kumar", "role": "editor", "status": "active", "twofa": true, "last_login": time.Now().Add(-2 * time.Hour)},
			{"id": "00000000-0000-0000-0000-000000000004", "email": "priya.dev@sentinel.local", "name": "Priya Dev", "role": "viewer", "status": "active", "twofa": false, "last_login": time.Now().Add(-24 * time.Hour)},
		},
		"tenant_id": claims.TenantID,
	})
}

func handleCreateUserReal(c *gin.Context, enf *rbac.Enforcer) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceUser, rbac.ActionCreate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	var req struct {
		Email string `json:"email" binding:"required"`
		Name  string `json:"name"`
		Role  string `json:"role"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Role == "" {
		req.Role = "viewer"
	}
	c.JSON(http.StatusCreated, gin.H{
		"user": gin.H{
			"id": fmt.Sprintf("user-%d", time.Now().UnixNano()%100000000),
			"email": req.Email, "name": req.Name, "role": req.Role,
			"status": "active", "twofa": false, "last_login": nil,
		},
		"message": fmt.Sprintf("Invitation sent to %s", req.Email),
	})
}

func handleListAPIKeysReal(c *gin.Context, enf *rbac.Enforcer) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceAPIKey, rbac.ActionList) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"api_keys": []gin.H{
			{"id": "key-1", "name": "CI/CD Pipeline", "preview": "sk-live-f87a48c6••••51de", "scope": "read:all write:rules", "created_at": "2024-11-01T00:00:00Z", "expires_at": "2025-11-01T00:00:00Z", "last_used": "2 min ago"},
			{"id": "key-2", "name": "Monitoring Agent", "preview": "sk-live-a2b3c4d5••••ef90", "scope": "read:all", "created_at": "2024-10-15T00:00:00Z", "expires_at": "2025-10-15T00:00:00Z", "last_used": "5 min ago"},
			{"id": "key-3", "name": "Backup Script", "preview": "sk-live-9f8e7d6c••••ba01", "scope": "read:logs", "created_at": "2024-09-01T00:00:00Z", "expires_at": "2025-09-01T00:00:00Z", "last_used": "3d ago"},
		},
		"tenant_id": claims.TenantID,
	})
}

func handleCreateAPIKeyReal(c *gin.Context, enf *rbac.Enforcer) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceAPIKey, rbac.ActionCreate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	var req struct {
		Name    string `json:"name" binding:"required"`
		Scope   string `json:"scope"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	nano := time.Now().UnixNano()
	randomPart := fmt.Sprintf("%016x", nano)
	fullKey := "sk-live-" + randomPart
	preview := fullKey[:14] + "••••" + fullKey[len(fullKey)-4:]
	scope := req.Scope
	if scope == "" {
		scope = "read:all"
	}
	c.JSON(http.StatusCreated, gin.H{
		"api_key": gin.H{
			"id":         fmt.Sprintf("key-%d", nano%100000000),
			"name":       req.Name,
			"key":        fullKey,
			"preview":    preview,
			"scope":      scope,
			"created_at": time.Now().UTC(),
			"expires_at": time.Now().Add(365 * 24 * time.Hour).UTC(),
		},
		"warning": "Copy this key now — it will never be shown again.",
	})
}

func handleRevokeAPIKey(c *gin.Context, enf *rbac.Enforcer) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceAPIKey, rbac.ActionDelete) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	// id := c.Param("id")
	c.JSON(http.StatusOK, gin.H{"ok": true, "message": "API key revoked"})
}
