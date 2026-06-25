package main

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/logs"
	"github.com/your-org/sentinel-waf/control-plane/internal/rbac"
)

// GeoIP country blocking. A country is "blocked" when its ISO-3166-1 alpha-2
// code appears in a site's waf_policy.geoip.block_countries. These endpoints
// treat blocking as a GLOBAL policy: the code is added to / removed from every
// active site, then configVersion is bumped so the data plane hot-applies.
//
// NOTE (honest): enforcement requires a GeoLite2-Country.mmdb in the proxy's
// rules/ dir. Without it the GeoIP module degrades to no-op — the block is
// persisted and will take effect the moment the database is present.

// handleListBlockedCountries returns the union of blocked country codes across
// all of the tenant's sites.
func handleListBlockedCountries(c *gin.Context, enf *rbac.Enforcer, store *db.Store) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceSite, rbac.ActionList) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusOK, gin.H{"countries": []string{}})
		return
	}
	sites, err := store.ListSites(c.Request.Context(), claims.TenantID, claims.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"countries": blockedUnion(sites)})
}

// handleBlockCountry adds a country code to every active site's geoip block list.
func handleBlockCountry(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub) {
	geoipMutate(c, enf, store, hub, true)
}

// handleUnblockCountry removes a country code from every site's geoip block list.
func handleUnblockCountry(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub) {
	geoipMutate(c, enf, store, hub, false)
}

func geoipMutate(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, block bool) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceSite, rbac.ActionUpdate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}

	var code string
	if block {
		var body struct {
			Country string `json:"country"`
			Code    string `json:"code"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		code = firstNonEmpty(body.Code, body.Country)
	} else {
		code = c.Param("code")
	}
	code = strings.ToUpper(strings.TrimSpace(code))
	if len(code) != 2 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "country must be a 2-letter ISO code"})
		return
	}

	sites, err := store.ListSites(c.Request.Context(), claims.TenantID, claims.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	changed := 0
	for _, s := range sites {
		newPolicy, did := setCountryBlock(s.WafPolicy, code, block)
		if !did {
			continue
		}
		if _, err := store.UpdateSite(c.Request.Context(), claims.TenantID, claims.UserID, s.ID,
			db.UpdateSiteRequest{WafPolicy: newPolicy}); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		changed++
	}
	if changed > 0 {
		configVersion.Add(1)
	}

	action := "geoip.unblock." + code
	if block {
		action = "geoip.block." + code
	}
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID: claims.TenantID, ActorUserID: &claims.UserID,
		Action: action, TargetKind: "geoip",
	})

	// Re-read the union so the UI reflects the new state.
	sites, _ = store.ListSites(c.Request.Context(), claims.TenantID, claims.UserID)
	c.JSON(http.StatusOK, gin.H{
		"ok": true, "country": code, "blocked": block,
		"sites_changed": changed, "countries": blockedUnion(sites),
	})
}

// blockedUnion returns the sorted union of block_countries across sites.
func blockedUnion(sites []db.SiteRow) []string {
	set := map[string]struct{}{}
	for _, s := range sites {
		for _, code := range siteBlockedCountries(s.WafPolicy) {
			set[code] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// siteBlockedCountries extracts waf_policy.geoip.block_countries as []string.
func siteBlockedCountries(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var p struct {
		GeoIP struct {
			BlockCountries []string `json:"block_countries"`
		} `json:"geoip"`
	}
	if json.Unmarshal(raw, &p) != nil {
		return nil
	}
	out := make([]string, 0, len(p.GeoIP.BlockCountries))
	for _, c := range p.GeoIP.BlockCountries {
		out = append(out, strings.ToUpper(strings.TrimSpace(c)))
	}
	return out
}

// setCountryBlock adds/removes a country code in waf_policy.geoip.block_countries.
// Returns the new policy and whether anything changed.
func setCountryBlock(raw json.RawMessage, code string, block bool) (json.RawMessage, bool) {
	waf := map[string]any{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &waf)
	}
	geoip, _ := waf["geoip"].(map[string]any)
	if geoip == nil {
		geoip = map[string]any{}
	}
	// Current list as []string.
	var list []string
	if existing, ok := geoip["block_countries"].([]any); ok {
		for _, v := range existing {
			if s, ok := v.(string); ok {
				list = append(list, strings.ToUpper(strings.TrimSpace(s)))
			}
		}
	}
	has := false
	for _, c := range list {
		if c == code {
			has = true
			break
		}
	}

	if block && has {
		return raw, false
	}
	if !block && !has {
		return raw, false
	}

	if block {
		list = append(list, code)
	} else {
		next := list[:0]
		for _, c := range list {
			if c != code {
				next = append(next, c)
			}
		}
		list = next
	}

	geoip["block_countries"] = list
	waf["geoip"] = geoip
	out, err := json.Marshal(waf)
	if err != nil {
		return raw, false
	}
	return out, true
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
