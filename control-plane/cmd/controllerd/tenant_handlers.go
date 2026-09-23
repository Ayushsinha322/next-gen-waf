package main

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"

	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
)

// platformTenantID is the "root" tenant whose owner/admin may provision other
// tenants. Defaults to the seeded dev tenant; override with
// SENTINEL_PLATFORM_TENANT_ID once a dedicated platform tenant exists.
func platformTenantID() string {
	if v := os.Getenv("SENTINEL_PLATFORM_TENANT_ID"); v != "" {
		return v
	}
	return db.DevTenantID
}

// isPlatformAdmin reports whether the caller may manage tenants: an owner/admin
// of the platform tenant. (There is no cross-tenant "superadmin" role yet, so
// membership in the platform tenant IS the platform-admin boundary.)
func isPlatformAdmin(claims *auth.Claims) bool {
	return claims != nil &&
		claims.TenantID == platformTenantID() &&
		(claims.Role == "owner" || claims.Role == "admin")
}

func validPlan(p string) bool {
	switch p {
	case "", "free", "pro", "enterprise":
		return true
	}
	return false
}

func handleCreateTenant(c *gin.Context, store *db.Store) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !isPlatformAdmin(claims) {
		c.JSON(http.StatusForbidden, gin.H{"error": "platform admin required"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	var req struct {
		Slug          string `json:"slug" binding:"required"`
		Name          string `json:"name" binding:"required"`
		Plan          string `json:"plan"`
		OwnerEmail    string `json:"owner_email" binding:"required,email"`
		OwnerName     string `json:"owner_name"`
		OwnerPassword string `json:"owner_password" binding:"required,min=12"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": clientError(err)})
		return
	}
	if !validPlan(req.Plan) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid plan"})
		return
	}
	tenantID, userID, err := store.CreateTenant(c.Request.Context(),
		req.Slug, req.Name, req.Plan, req.OwnerEmail, req.OwnerName, req.OwnerPassword)
	if err != nil {
		// Most likely a duplicate slug/owner email (unique violation).
		c.JSON(http.StatusConflict, gin.H{"error": "could not create tenant (slug or owner email may already exist)"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"tenant_id":     tenantID,
		"owner_user_id": userID,
		"slug":          req.Slug,
	})
}

func handleListTenants(c *gin.Context, store *db.Store) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !isPlatformAdmin(claims) {
		c.JSON(http.StatusForbidden, gin.H{"error": "platform admin required"})
		return
	}
	if store == nil {
		c.JSON(http.StatusOK, gin.H{"tenants": []db.TenantRow{}})
		return
	}
	tenants, err := store.ListTenants(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"tenants": tenants})
}

func handleSetTenantStatus(c *gin.Context, store *db.Store) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !isPlatformAdmin(claims) {
		c.JSON(http.StatusForbidden, gin.H{"error": "platform admin required"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	var req struct {
		Status string `json:"status" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": clientError(err)})
		return
	}
	switch req.Status {
	case "active", "suspended", "deleted":
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "status must be active, suspended, or deleted"})
		return
	}
	tid := c.Param("id")
	if tid == platformTenantID() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot change the platform tenant's status"})
		return
	}
	if err := store.SetTenantStatus(c.Request.Context(), tid, req.Status); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "tenant_id": tid, "status": req.Status})
}
