package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/rbac"
)

// ---------------------------------------------------------------------------
// GET /api/v1/sites/:id/effective
//
// What this control plane PUSHES for a site (the exact conversion the config
// sync runs) next to what the data plane HOLDS for it, with a field-level diff
// and the stored waf_policy keys that never reach the data plane at all.
//
// Every one of the "silently inert" defects — a toggle the console showed that
// the allowlist dropped, a TLS mode nested where the converter did not look, a
// deleted site still served — is visible in this view as a difference or an
// ignored key. It is the escape hatch for anything the wizard does not model.
// ---------------------------------------------------------------------------

var effectiveHTTPClient = &http.Client{Timeout: 6 * time.Second}

func handleSiteEffectiveConfig(c *gin.Context, enf *rbac.Enforcer, store *db.Store) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceSite, rbac.ActionRead) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	site, err := store.GetSite(c.Request.Context(), claims.TenantID, c.Param("id"))
	if err != nil || site == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "site not found"})
		return
	}

	resp := gin.H{
		"site_id":             site.ID,
		"site":                site.Name,
		"status":              site.Status,
		"ignored_policy_keys": unknownWafPolicyKeys(site.WafPolicy),
	}

	// 1. What we push: the same conversion the sync runs, inline rules included.
	pushed, convErr := siteRowToRustConfig(*site)
	if convErr != nil {
		resp["pushed_error"] = convErr.Error()
	} else {
		if rulesByTenant, err := store.ListDeployableRules(c.Request.Context()); err == nil {
			attachInlineRules(pushed, site.ID, rulesByTenant[site.TenantID])
		}
		resp["pushed"] = redactJSON(toJSON(pushed))
	}

	// 2. What the data plane holds, keyed by the Rust site id (the name).
	req, _ := http.NewRequestWithContext(c.Request.Context(), http.MethodGet,
		dataPlaneBaseURL()+"/api/v1/internal/sites/"+url.PathEscape(site.Name)+"/config", nil)
	setInternalAuth(req)
	r, err := effectiveHTTPClient.Do(req)
	if err != nil {
		resp["dataplane"] = gin.H{"reachable": false, "error": err.Error()}
		c.JSON(http.StatusOK, resp)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	r.Body.Close()
	switch r.StatusCode {
	case http.StatusOK:
		var dp struct {
			Applied json.RawMessage `json:"applied"`
			Engine  json.RawMessage `json:"engine"`
			Version string          `json:"version"`
		}
		if json.Unmarshal(body, &dp) != nil {
			resp["dataplane"] = gin.H{"reachable": true, "error": "bad JSON from data plane"}
			break
		}
		var applied any
		_ = json.Unmarshal(dp.Applied, &applied)
		resp["applied"] = applied
		resp["dataplane"] = gin.H{"reachable": true, "version": dp.Version, "engine": dp.Engine}
		if p, ok := resp["pushed"]; ok {
			resp["diff"] = diffJSON(p, applied)
		}
	case http.StatusNotFound:
		// The data plane does not have this site at all. For an active site that
		// is the fail-open shape: stored, listed, unprotected.
		resp["dataplane"] = gin.H{"reachable": true, "error": "site is not present on the data plane"}
		resp["applied"] = nil
	default:
		resp["dataplane"] = gin.H{"reachable": true, "error": "data plane returned " + r.Status}
	}
	c.JSON(http.StatusOK, resp)
}

// toJSON round-trips a map through encoding/json so numeric types match what
// the data plane returns (float64 everywhere) and the diff compares like with like.
func toJSON(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}

// redactJSON blanks credential-bearing values before the pushed config leaves
// the control plane: the same rule the data plane applies to its side, so the
// two panes stay comparable.
func redactJSON(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			kl := strings.ToLower(k)
			if strings.Contains(kl, "password") || strings.Contains(kl, "secret") || strings.Contains(kl, "token") || kl == "api_key" {
				if val != nil {
					t[k] = "***"
				}
				continue
			}
			t[k] = redactJSON(val)
		}
		return t
	case []any:
		for i := range t {
			t[i] = redactJSON(t[i])
		}
		return t
	}
	return v
}

// DiffEntry is one field that differs between the pushed and applied config.
type DiffEntry struct {
	Path    string `json:"path"`
	Pushed  any    `json:"pushed"`
	Applied any    `json:"applied"`
}

// diffJSON compares two JSON trees leaf by leaf and reports every dotted path
// whose value differs, is missing on one side, or is present only on the other.
// A key the data plane fills with a default (present on the applied side only)
// is reported too — that is information, not noise: it tells the operator the
// control plane never sent it.
func diffJSON(pushed, applied any) []DiffEntry {
	pf, af := map[string]any{}, map[string]any{}
	flatten("", pushed, pf)
	flatten("", applied, af)
	keys := map[string]bool{}
	for k := range pf {
		keys[k] = true
	}
	for k := range af {
		keys[k] = true
	}
	var out []DiffEntry
	for k := range keys {
		pv, pok := pf[k]
		av, aok := af[k]
		if pok && aok && jsonEqual(pv, av) {
			continue
		}
		if !pok {
			pv = "(not sent)"
		}
		if !aok {
			av = "(not held)"
		}
		out = append(out, DiffEntry{Path: k, Pushed: pv, Applied: av})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func flatten(prefix string, v any, out map[string]any) {
	switch t := v.(type) {
	case map[string]any:
		if len(t) == 0 {
			out[prefix] = t
			return
		}
		for k, val := range t {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			flatten(p, val, out)
		}
	case []any:
		if len(t) == 0 {
			out[prefix] = t
			return
		}
		for i, val := range t {
			flatten(fmt.Sprintf("%s[%d]", prefix, i), val, out)
		}
	default:
		out[prefix] = v
	}
}

func jsonEqual(a, b any) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(ab) == string(bb)
}
