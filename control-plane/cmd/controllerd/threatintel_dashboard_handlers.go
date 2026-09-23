package main

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	"github.com/your-org/sentinel-waf/control-plane/internal/clickhouse"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/logs"
	"github.com/your-org/sentinel-waf/control-plane/internal/rbac"
)

// Dashboard-facing threat-intelligence API (JWT + RBAC via ResourceThreatIntel).
// Distinct from the secret-gated data-plane sync endpoint in
// threatintel_handlers.go. IOCs are node-global (no tenant scoping): the RBAC
// role check is the access gate.

// handleThreatIntelStats returns the summary counters driving the KPI row + facets.
func handleThreatIntelStats(c *gin.Context, enf *rbac.Enforcer, store *db.Store) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceThreatIntel, rbac.ActionRead) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusOK, db.ThreatIntelSummary{
			ByType: map[string]int{}, BySource: map[string]int{}, ByCategory: map[string]int{},
			Threshold: db.DefaultBlockThreshold,
		})
		return
	}
	sum, err := store.ThreatIntelSummary(c.Request.Context(), atoiQuery(c, "threshold", 0))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
		return
	}
	c.JSON(http.StatusOK, sum)
}

// handleListIOCs returns a filtered, paginated slice of active IOCs.
func handleListIOCs(c *gin.Context, enf *rbac.Enforcer, store *db.Store) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceThreatIntel, rbac.ActionList) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusOK, db.IOCPage{Items: []db.IOCListItem{}})
		return
	}
	// Validate enum filters up front so bad input is a 400; a ListIOCs error
	// after this point is a genuine server/DB fault (500).
	iocType := c.Query("type")
	if iocType != "" && !db.ValidIOCType(iocType) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid type (ip|cidr|user_agent|domain|url_substring)"})
		return
	}
	tier := c.Query("tier")
	if tier != "" && tier != "block" && tier != "watch" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tier (block|watch)"})
		return
	}
	page, err := store.ListIOCs(c.Request.Context(), db.IOCListFilter{
		Type:      iocType,
		Source:    c.Query("source"),
		Tier:      tier,
		Search:    c.Query("q"),
		Threshold: atoiQuery(c, "threshold", 0),
		Limit:     atoiQuery(c, "limit", 0),
		Offset:    atoiQuery(c, "offset", 0),
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
		return
	}
	c.JSON(http.StatusOK, page)
}

type createIOCRequest struct {
	Type       string  `json:"type"`
	Value      string  `json:"value"`
	Source     string  `json:"source"`
	Category   string  `json:"category"`
	Confidence int     `json:"confidence"`
	Tier       string  `json:"tier"`       // optional "block"|"watch"; sets confidence if confidence==0
	ExpiresAt  *string `json:"expires_at"` // RFC3339 or null/omitted = never
}

// handleCreateIOC adds a manual operator-entered indicator to the corpus.
func handleCreateIOC(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceThreatIntel, rbac.ActionCreate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	var req createIOCRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.Value == "" || !db.ValidIOCType(req.Type) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "type (ip|cidr|user_agent|domain|url_substring) and value are required"})
		return
	}

	conf := req.Confidence
	if conf == 0 {
		switch req.Tier {
		case "block":
			conf = 95
		case "watch":
			conf = 60
		default:
			conf = 90 // a manual indicator defaults to block-tier
		}
	}

	var expires *time.Time
	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "expires_at must be RFC3339 or null"})
			return
		}
		expires = &t
	}

	ioc, err := store.CreateIOC(c.Request.Context(), db.IOC{
		Type:       req.Type,
		Value:      req.Value,
		Source:     req.Source, // "" -> "manual" in the store
		Category:   req.Category,
		Confidence: conf,
		ExpiresAt:  expires,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
		return
	}

	tid := strconv.FormatInt(ioc.ID, 10)
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &claims.UserID,
		Action:      "threat_intel.ioc.create",
		TargetKind:  "threat_intel_ioc",
		TargetID:    &tid,
	})
	c.JSON(http.StatusOK, gin.H{"ioc": ioc})
}

// handleDeleteIOC removes an indicator by its DB id (re-allows matching traffic).
func handleDeleteIOC(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceThreatIntel, rbac.ActionDelete) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid ioc id"})
		return
	}
	ok, err := store.DeleteIOCByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
		return
	}
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "indicator not found"})
		return
	}
	tid := c.Param("id")
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &claims.UserID,
		Action:      "threat_intel.ioc.delete",
		TargetKind:  "threat_intel_ioc",
		TargetID:    &tid,
	})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// tiBlock is the dashboard shape for a threat-intel-driven enforcement hit.
type tiBlock struct {
	TS      int64  `json:"ts"`
	IP      string `json:"ip"`
	Country string `json:"country"`
	Site    string `json:"site"`
	Path    string `json:"path"`
	Reason  string `json:"reason"` // e.g. "threat intel: malicious IP 1.2.3.4"
}

// handleRecentTIBlocks returns recent threat-intel-tagged blocks from ClickHouse.
// Degrades honestly (empty + clickhouse:false) when the reader is not configured.
func handleRecentTIBlocks(c *gin.Context, enf *rbac.Enforcer, ch *clickhouse.Client) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceThreatIntel, rbac.ActionRead) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if ch == nil || !ch.Enabled() {
		c.JSON(http.StatusOK, gin.H{"blocks": []tiBlock{}, "clickhouse": false})
		return
	}
	events, err := ch.RecentThreatIntelBlocks(c.Request.Context(), claims.TenantID,
		int64(atoiQuery(c, "from", 0)), int64(atoiQuery(c, "to", 0)), atoiQuery(c, "limit", 100))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error(), "clickhouse": true})
		return
	}
	blocks := make([]tiBlock, 0, len(events))
	for _, e := range events {
		blocks = append(blocks, tiBlock{
			TS: e.TS, IP: e.IP, Country: e.Country, Site: e.Site, Path: e.Path, Reason: e.Attack,
		})
	}
	c.JSON(http.StatusOK, gin.H{"blocks": blocks, "clickhouse": true})
}

// atoiQuery reads an int query param, returning def when absent/invalid.
func atoiQuery(c *gin.Context, key string, def int) int {
	if v := c.Query(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
