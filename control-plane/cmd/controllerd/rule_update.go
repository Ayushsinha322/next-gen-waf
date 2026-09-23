package main

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/leader"
	"github.com/your-org/sentinel-waf/control-plane/internal/logs"
	"github.com/your-org/sentinel-waf/control-plane/internal/rbac"
)

// handleUpdateRule is a partial update, including the rule's DSL.
//
// Before this the only mutation was flipping `enabled`, so fixing a typo meant
// DELETE followed by POST — which changes the rule's id and orphans every audit
// entry that referenced it.
//
// A DSL edit is validated with the REAL engine before it is stored. An invalid
// edit is refused rather than saved-and-reported-broken, because unlike creation
// this REPLACES something that may currently be working: accepting a broken edit
// would silently disarm a live rule.
func handleUpdateRule(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *leader.Elector) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceRule, rbac.ActionUpdate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	ruleID := c.Param("id")

	var req db.UpdateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": clientError(err)})
		return
	}
	if req.DSL == nil && req.Severity == nil && req.Phase == nil &&
		req.Tags == nil && req.Enabled == nil && req.SiteID == nil && !req.ClearSiteID {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "no updatable field supplied (dsl, severity, phase, tags, enabled, site_id)",
		})
		return
	}

	// Validate a DSL change before it can replace a working rule.
	var validationSkipped bool
	if req.DSL != nil {
		res, err := validateSRL(c.Request.Context(), srlRequest{DSL: *req.DSL})
		switch {
		case err != nil:
			// Cannot verify. Refuse — an unverified REPLACEMENT can disarm a rule
			// that is currently protecting the site, which is worse than making
			// the operator retry. (Creation is allowed to proceed unverified
			// because there is nothing to disarm.)
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "cannot validate the new rule on this node, so the existing " +
					"rule was left unchanged rather than replaced unverified",
				"detail": err.Error(),
			})
			return
		case !res.Valid:
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "the rule is not valid SRL and was not saved",
				"detail":  res.Error,
				"invalid": true,
			})
			return
		}
	}

	// Rescoping to a site the caller cannot see would deliver the rule nowhere.
	if req.SiteID != nil && strings.TrimSpace(*req.SiteID) != "" {
		if _, err := store.GetSite(c.Request.Context(), claims.TenantID, *req.SiteID); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "site_id does not refer to a site in this tenant; send " +
					"clear_site_id to make the rule deployment-wide",
			})
			return
		}
	}

	if !requireLeader(c, cl) {
		return
	}

	rule, err := store.UpdateRule(c.Request.Context(), claims.TenantID, claims.UserID, ruleID, req)
	if err != nil {
		if errors.Is(err, db.ErrRuleNotUpdatable) {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "rule not found, or its source makes it read-only " +
					"(crs and community rules are shipped, not editable)",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
		return
	}

	// The config-generation trigger on `rules` (migration 0012) fires on this
	// UPDATE, so the fleet re-fetches without a roll.
	configVersion.Add(1)
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &claims.UserID,
		Action:      "rule.update",
		TargetKind:  "rule",
		TargetID:    &rule.ID,
	})

	resp := gin.H{"rule": rule}
	if validationSkipped {
		resp["warning"] = "the new rule was stored without validation"
	}
	c.JSON(http.StatusOK, resp)
}
