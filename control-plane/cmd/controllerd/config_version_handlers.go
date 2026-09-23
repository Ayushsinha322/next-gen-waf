package main

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/leader"
	"github.com/your-org/sentinel-waf/control-plane/internal/logs"
	"github.com/your-org/sentinel-waf/control-plane/internal/rbac"
	"go.uber.org/zap"
)

// snapshotBeforeMutation records an undo point before a config change is applied.
//
// Best-effort by design: a snapshot failure must never block a legitimate config
// change. Losing an undo point is a far smaller problem than refusing an operator's
// write, so this logs and returns rather than surfacing an error.
func snapshotBeforeMutation(c *gin.Context, store *db.Store, log *zap.Logger, reason string) {
	if store == nil {
		return
	}
	claims, _ := auth.GetClaims(c.Request.Context())
	if claims == nil || claims.TenantID == "" {
		return
	}
	if _, err := store.SnapshotConfig(c.Request.Context(), claims.TenantID, claims.UserID, reason); err != nil {
		log.Warn("could not snapshot config before mutation — rollback point missing",
			zap.String("reason", reason),
			zap.String("tenant_id", claims.TenantID),
			zap.Error(err))
	}
}

// handleListConfigVersions lists the tenant's rollback points, newest first.
func handleListConfigVersions(c *gin.Context, enf *rbac.Enforcer, store *db.Store) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceSite, rbac.ActionRead) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	limit, _ := strconv.Atoi(c.Query("limit"))
	versions, err := store.ListConfigVersions(c.Request.Context(), claims.TenantID, claims.UserID, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"versions": versions})
}

// handleRollbackConfig restores a previous site-configuration snapshot.
//
// The response reports exactly what was and was not applied. A rollback is
// deliberately NOT a full revert — sites created since the snapshot are left alone
// and sites deleted since are not resurrected — and saying so plainly is better
// than implying a completeness the operation does not have.
func handleRollbackConfig(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *leader.Elector, log *zap.Logger) {
	claims, _ := auth.GetClaims(c.Request.Context())
	// Rollback rewrites live protection settings, so it needs update rights.
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceSite, rbac.ActionUpdate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	versionID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || versionID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid version id"})
		return
	}
	if !requireLeader(c, cl) {
		return
	}

	// Snapshot the pre-rollback state too, so a rollback is itself undoable —
	// otherwise recovering from a mistaken rollback would mean no way back.
	snapshotBeforeMutation(c, store, log, "config.rollback")

	restored, skipped, err := store.RestoreConfigVersion(c.Request.Context(),
		claims.TenantID, claims.UserID, versionID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
		return
	}

	configVersion.Add(1)
	target := strconv.FormatInt(versionID, 10)
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &claims.UserID,
		Action:      "config.rollback",
		TargetKind:  "config_version",
		TargetID:    &target,
	})

	c.JSON(http.StatusOK, gin.H{
		"restored_sites": restored,
		"skipped":        skipped,
		"version_id":     versionID,
		"note": "Sites created after this snapshot were left unchanged, and sites deleted " +
			"since were not re-created. See `skipped` for the specifics.",
	})
}
