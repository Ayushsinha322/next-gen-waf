package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/logs"
	"github.com/your-org/sentinel-waf/control-plane/internal/mailer"
	"github.com/your-org/sentinel-waf/control-plane/internal/notify"
	"github.com/your-org/sentinel-waf/control-plane/internal/rbac"

	"github.com/your-org/sentinel-waf/control-plane/internal/version"
)

// sharedDispatcher backs the "test channel" endpoint. Stateless, safe to share.
var sharedDispatcher = &notify.Dispatcher{}

// Email channels send through the relay password recovery uses, read from the
// environment on each send like currentMailer.
func init() {
	notify.MailSender = func(to, subject, text string) error {
		err := currentMailer().Send(mailer.Message{To: to, Subject: subject, Text: text})
		if errors.Is(err, mailer.ErrNotConfigured) {
			return fmt.Errorf("SMTP is not configured: fill in the SENTINEL_SMTP_* block in .env and restart the control plane")
		}
		return err
	}
}

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
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "type must be one of webhook, slack, syslog, cef, email"})
		return
	}
	if err := validateChannelConfig(req.Type, req.Config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ch, err := store.CreateChannel(c.Request.Context(), claims.TenantID, claims.UserID, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": clientError(err)})
		return
	}
	if len(req.Config) > 0 {
		cur, err := store.GetChannel(c.Request.Context(), claims.TenantID, claims.UserID, id)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "channel not found"})
			return
		}
		if err := validateChannelConfig(cur.Type, req.Config); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}
	ch, err := store.UpdateChannel(c.Request.Context(), claims.TenantID, claims.UserID, id, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
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
		Summary:   version.Name + " test alert — your channel is wired correctly.",
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
	case "webhook", "slack", "syslog", "cef", "email":
		return true
	}
	return false
}

// validateChannelConfig checks what a channel cannot work without, where the
// mistake is the operator's and should be refused at save rather than found
// out by an alert that never arrives. Only email is checked here for now: its
// recipients must all be addresses, and a list with one typo in it would
// otherwise deliver to the others and fail for that one only on the night.
func validateChannelConfig(typ string, raw json.RawMessage) error {
	if typ != "email" {
		return nil
	}
	var cfg notify.Config
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return fmt.Errorf("config: %v", err)
		}
	}
	_, err := notify.Recipients(cfg.To)
	return err
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
