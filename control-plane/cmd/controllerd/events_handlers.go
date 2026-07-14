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
		Query:    c.Query("q"),
		From:     atoi64(c.Query("from")),
		To:       atoi64(c.Query("to")),
		Limit:    int(atoi64(c.Query("limit"))),
	}
	events, err := ch.Search(c.Request.Context(), f)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
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
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if facets == nil {
		facets = []clickhouse.Facet{}
	}
	c.JSON(http.StatusOK, gin.H{"facets": facets, "column": col, "clickhouse": true})
}

func atoi64(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}
