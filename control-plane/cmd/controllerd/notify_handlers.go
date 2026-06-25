package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/logs"
	"github.com/your-org/sentinel-waf/control-plane/internal/notify"
	"github.com/your-org/sentinel-waf/control-plane/internal/rbac"
)

// sharedDispatcher backs the "test channel" endpoint. Stateless, safe to share.
var sharedDispatcher = &notify.Dispatcher{}

func handleListChannels(c *gin.Context, enf *rbac.Enforcer, store *db.Store) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceNotification, rbac.ActionList) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusOK, gin.H{"channels": []any{}})
		return
	}
	channels, err := store.ListChannels(c.Request.Context(), claims.TenantID, claims.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if channels == nil {
		channels = []db.ChannelRow{}
	}
	c.JSON(http.StatusOK, gin.H{"channels": channels})
}

func handleCreateChannel(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceNotification, rbac.ActionCreate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	var req db.CreateChannelRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.Name == "" || req.Type == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name and type are required"})
		return
	}
	if !validChannelType(req.Type) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "type must be one of webhook, slack, syslog, cef"})
		return
	}
	ch, err := store.CreateChannel(c.Request.Context(), claims.TenantID, claims.UserID, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	auditChannel(c, store, hub, claims, "notification.channel.create", ch.ID)
	c.JSON(http.StatusOK, gin.H{"channel": ch})
}

func handleUpdateChannel(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceNotification, rbac.ActionUpdate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	id := c.Param("id")
	var req db.UpdateChannelRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ch, err := store.UpdateChannel(c.Request.Context(), claims.TenantID, claims.UserID, id, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	auditChannel(c, store, hub, claims, "notification.channel.update", id)
	c.JSON(http.StatusOK, gin.H{"channel": ch})
}

func handleDeleteChannel(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceNotification, rbac.ActionDelete) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	id := c.Param("id")
	if err := store.DeleteChannel(c.Request.Context(), claims.TenantID, claims.UserID, id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	auditChannel(c, store, hub, claims, "notification.channel.delete", id)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// handleTestChannel sends a synthetic alert to a single channel and reports the
// delivery outcome (the "Test" button in the UI).
func handleTestChannel(c *gin.Context, enf *rbac.Enforcer, store *db.Store) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceNotification, rbac.ActionUpdate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	id := c.Param("id")
	row, err := store.GetChannel(c.Request.Context(), claims.TenantID, claims.UserID, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "channel not found"})
		return
	}
	test := notify.Alert{
		ID:        "test",
		Severity:  "high",
		Kind:      "test",
		Summary:   "Sentinel WAF test alert — your channel is wired correctly.",
		Site:      "example.com",
		SourceIP:  "203.0.113.10",
		Rule:      "TEST-0001",
		CreatedAt: time.Now(),
	}
	res := sharedDispatcher.Test(c.Request.Context(), notifyChannelFromRow(*row), test)
	_ = store.RecordChannelDelivery(c.Request.Context(), claims.TenantID, claims.UserID, id, res.Status())
	if !res.OK {
		c.JSON(http.StatusBadGateway, gin.H{"ok": false, "error": res.Err})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "message": "test alert delivered"})
}

func validChannelType(t string) bool {
	switch t {
	case "webhook", "slack", "syslog", "cef":
		return true
	}
	return false
}

// notifyChannelFromRow converts a stored channel row to a notify.Channel.
func notifyChannelFromRow(r db.ChannelRow) notify.Channel {
	var cfg notify.Config
	_ = json.Unmarshal(r.Config, &cfg)
	return notify.Channel{
		ID: r.ID, Name: r.Name, Type: r.Type, MinSeverity: r.MinSeverity, Config: cfg,
	}
}

func auditChannel(c *gin.Context, store *db.Store, hub *logs.Hub, claims *auth.Claims, action, id string) {
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &claims.UserID,
		Action:      action,
		TargetKind:  "notification_channel",
		TargetID:    &id,
	})
}
