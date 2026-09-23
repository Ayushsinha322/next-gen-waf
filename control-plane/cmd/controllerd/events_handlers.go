package main

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	"github.com/your-org/sentinel-waf/control-plane/internal/clickhouse"
	"github.com/your-org/sentinel-waf/control-plane/internal/rbac"
)

// Searchable WAF history, backed by ClickHouse (the proxy writes; we read).

func handleEventsStatus(c *gin.Context, enf *rbac.Enforcer, ch *clickhouse.Client) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceAlert, rbac.ActionList) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	// Status never returns a non-nil error — reachability/errors are encoded in
	// the returned map itself.
	st, _ := ch.Status(c.Request.Context(), claims.TenantID)
	c.JSON(http.StatusOK, st)
}

func handleEventsSearch(c *gin.Context, enf *rbac.Enforcer, ch *clickhouse.Client) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceAlert, rbac.ActionList) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if !ch.Enabled() {
		c.JSON(http.StatusOK, gin.H{"events": []any{}, "clickhouse": false})
		return
	}
	f := clickhouse.SearchFilter{
		Tenant:   claims.TenantID, // isolation boundary — never from client input
		Site:     c.Query("site"),
		Country:  c.Query("country"),
		Rule:     c.Query("rule"),
		Action:   c.Query("action"),
		IP:       c.Query("ip"),
		Protocol: c.Query("protocol"),
		// The UI has always sent this; it was silently dropped here, so a
		// CRITICAL-only search returned unfiltered results — and a different
		// set than the export, which did honour it.
		Severity: c.Query("severity"),
		Query:    c.Query("q"),
		From:     atoi64(c.Query("from")),
		To:       atoi64(c.Query("to")),
		Limit:    int(atoi64(c.Query("limit"))),
	}
	events, err := ch.Search(c.Request.Context(), f)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": clientError(err)})
		return
	}
	if events == nil {
		events = []clickhouse.Event{}
	}
	c.JSON(http.StatusOK, gin.H{"events": events, "clickhouse": true})
}

// handleSupportIDLookup resolves a Support ID quoted by a customer back to the
// blocked request: GET /events/support/:id
//
// Separate from /events/search because it must ignore the UI's selected time
// range — see clickhouse.FindBySupportID.
func handleSupportIDLookup(c *gin.Context, enf *rbac.Enforcer, ch *clickhouse.Client) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceAlert, rbac.ActionList) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if !ch.Enabled() {
		c.JSON(http.StatusOK, gin.H{"events": []any{}, "clickhouse": false})
		return
	}
	events, err := ch.FindBySupportID(c.Request.Context(), claims.TenantID, c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": clientError(err)})
		return
	}
	if events == nil {
		events = []clickhouse.Event{}
	}
	c.JSON(http.StatusOK, gin.H{"events": events, "clickhouse": true})
}

func handleEventsTimeline(c *gin.Context, enf *rbac.Enforcer, ch *clickhouse.Client) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceAlert, rbac.ActionList) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if !ch.Enabled() {
		c.JSON(http.StatusOK, gin.H{"buckets": []any{}, "clickhouse": false})
		return
	}
	buckets, err := ch.Timeline(c.Request.Context(), claims.TenantID, atoi64(c.Query("from")), atoi64(c.Query("to")), int(atoi64(c.Query("bucket"))))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": clientError(err)})
		return
	}
	if buckets == nil {
		buckets = []clickhouse.TimelineBucket{}
	}
	c.JSON(http.StatusOK, gin.H{"buckets": buckets, "clickhouse": true})
}

func handleEventsFacets(c *gin.Context, enf *rbac.Enforcer, ch *clickhouse.Client) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceAlert, rbac.ActionList) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	col := c.Query("column")
	if col == "" {
		col = "rule"
	}
	if !ch.Enabled() {
		c.JSON(http.StatusOK, gin.H{"facets": []any{}, "column": col, "clickhouse": false})
		return
	}
	facets, err := ch.Facets(c.Request.Context(), col, claims.TenantID, atoi64(c.Query("from")), atoi64(c.Query("to")), int(atoi64(c.Query("limit"))))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": clientError(err)})
		return
	}
	if facets == nil {
		facets = []clickhouse.Facet{}
	}
	c.JSON(http.StatusOK, gin.H{"facets": facets, "column": col, "clickhouse": true})
}

// handleTopAttackers serves the "Top Attacker IPs" overview card: source IPs
// ranked by WAF-event volume with per-IP blocked count + resolved country.
// ClickHouse-gated — degrades to an honest empty list when the event store
// isn't configured (the hub keeps no per-IP/country data, so there is no
// fallback source and pretending otherwise would be dishonest).
func handleTopAttackers(c *gin.Context, enf *rbac.Enforcer, ch *clickhouse.Client) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceAlert, rbac.ActionList) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if !ch.Enabled() {
		c.JSON(http.StatusOK, gin.H{"attackers": []any{}, "clickhouse": false})
		return
	}
	attackers, err := ch.TopAttackers(c.Request.Context(), claims.TenantID,
		atoi64(c.Query("from")), atoi64(c.Query("to")), int(atoi64(c.Query("limit"))))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": clientError(err)})
		return
	}
	if attackers == nil {
		attackers = []clickhouse.Attacker{}
	}
	c.JSON(http.StatusOK, gin.H{"attackers": attackers, "clickhouse": true})
}

// handleSeverityTimeline serves the "Threat Detection Trend" chart: waf_events
// bucketed by time and severity band (High folds CRITICAL+HIGH). ClickHouse-gated
// with an honest empty state when the event store isn't configured.
func handleSeverityTimeline(c *gin.Context, enf *rbac.Enforcer, ch *clickhouse.Client) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceAlert, rbac.ActionList) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if !ch.Enabled() {
		c.JSON(http.StatusOK, gin.H{"buckets": []any{}, "clickhouse": false})
		return
	}
	buckets, err := ch.SeverityTimeline(c.Request.Context(), claims.TenantID,
		atoi64(c.Query("from")), atoi64(c.Query("to")), int(atoi64(c.Query("bucket"))))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": clientError(err)})
		return
	}
	if buckets == nil {
		buckets = []clickhouse.SeverityBucket{}
	}
	c.JSON(http.StatusOK, gin.H{"buckets": buckets, "clickhouse": true})
}

func atoi64(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}
