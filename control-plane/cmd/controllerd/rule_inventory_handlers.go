package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	"github.com/your-org/sentinel-waf/control-plane/internal/clickhouse"
	"github.com/your-org/sentinel-waf/control-plane/internal/rbac"
)

// ---------------------------------------------------------------------------
// GET /api/v1/rules/inventory[?site=<id>][&summary=1]
//
// The compiled rule set the data plane is ENFORCING, per site, with 24-hour hit
// counts from ClickHouse. This is distinct from GET /rules, which lists the
// rules operators have authored in this control plane's store.
//
// Why it exists: the Rules page showed the authored store — six rows — under the
// heading "loaded rules", and the overview said "CRS 5/5 enabled", while the
// data plane was enforcing a few hundred compiled CRS rules it had no way to
// report. An evaluator read a five-rule WAF. The data plane now exposes its
// inventory on an internal endpoint; this handler proxies it and enriches it.
// ---------------------------------------------------------------------------

// ruleInventoryHTTPClient is short-lived: the inventory is a few hundred KB at
// most and comes from a co-located process. A slow answer means the data plane
// is unhealthy, and the page must say so rather than hang.
var ruleInventoryHTTPClient = &http.Client{Timeout: 8 * time.Second}

// ruleHitsWindow is how far back hit counts look.
const ruleHitsWindow = 24 * time.Hour

func handleRuleInventory(c *gin.Context, enf *rbac.Enforcer, ch *clickhouse.Client) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceRule, rbac.ActionList) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}

	q := "?"
	if s := c.Query("site"); s != "" {
		q += "site=" + urlQueryEscape(s) + "&"
	}
	summary := c.Query("summary") == "1" || c.Query("summary") == "true"
	if summary {
		q += "summary=1"
	}
	req, _ := http.NewRequestWithContext(c.Request.Context(), http.MethodGet,
		dataPlaneBaseURL()+"/api/v1/internal/rules"+q, nil)
	setInternalAuth(req)
	resp, err := ruleInventoryHTTPClient.Do(req)
	if err != nil {
		// Say so. An empty inventory presented as truth is the bug this replaces.
		c.JSON(http.StatusOK, gin.H{
			"dataplane_reachable": false,
			"error":               "data plane unreachable: " + err.Error(),
			"sites":               []any{},
			"totals":              gin.H{"compiled": 0, "enforced": 0, "dropped": 0, "disabled": 0},
		})
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode != http.StatusOK {
		c.JSON(http.StatusBadGateway, gin.H{
			"dataplane_reachable": false,
			"error":               "data plane returned " + strconv.Itoa(resp.StatusCode),
		})
		return
	}

	var inv map[string]any
	if err := json.Unmarshal(body, &inv); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"dataplane_reachable": false, "error": "bad inventory JSON: " + err.Error()})
		return
	}
	inv["dataplane_reachable"] = true
	inv["hits_window_secs"] = int64(ruleHitsWindow / time.Second)
	inv["clickhouse"] = false

	if !summary && ch != nil && ch.Enabled() {
		now := time.Now()
		hits, err := ch.RuleHits(c.Request.Context(), claims.TenantID, now.Add(-ruleHitsWindow).Unix(), now.Unix())
		if err == nil {
			inv["clickhouse"] = true
			mergeRuleHits(inv, hits)
		} else {
			inv["hits_error"] = err.Error()
		}
	}
	c.JSON(http.StatusOK, inv)
}

// mergeRuleHits stamps hits_24h / blocks_24h on every rule entry of every site,
// keyed by the rule id as a string, and adds total_hits_24h to the totals.
// Rules with no events get 0, not an absent field, so the table can sort.
func mergeRuleHits(inv map[string]any, hits []clickhouse.RuleHit) {
	byID := make(map[string]clickhouse.RuleHit, len(hits))
	var total int64
	for _, h := range hits {
		byID[h.RuleID] = h
		total += h.Count
	}
	sites, _ := inv["sites"].([]any)
	for _, s := range sites {
		site, ok := s.(map[string]any)
		if !ok {
			continue
		}
		rules, _ := site["rules"].([]any)
		for _, r := range rules {
			rule, ok := r.(map[string]any)
			if !ok {
				continue
			}
			id := ruleIDString(rule["id"])
			h := byID[id]
			rule["hits_24h"] = h.Count
			rule["blocks_24h"] = h.Blocked
		}
	}
	if totals, ok := inv["totals"].(map[string]any); ok {
		totals["hits_24h"] = total
	}
}

// ruleIDString renders the JSON number the data plane emits for a rule id the
// way ClickHouse stores it (a plain decimal string).
func ruleIDString(v any) string {
	switch n := v.(type) {
	case float64:
		return strconv.FormatInt(int64(n), 10)
	case json.Number:
		return n.String()
	case string:
		return n
	}
	return ""
}

// urlQueryEscape is the minimal escaping a site id needs; ids are UUIDs or
// slugs, but never trust that when building a URL.
func urlQueryEscape(s string) string {
	const hex = "0123456789ABCDEF"
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		b := s[i]
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '-' || b == '_' || b == '.' {
			out = append(out, b)
		} else {
			out = append(out, '%', hex[b>>4], hex[b&15])
		}
	}
	return string(out)
}

var _ = context.Background // keep context imported for future cancellation wiring
