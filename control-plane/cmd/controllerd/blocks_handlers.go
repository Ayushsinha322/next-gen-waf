package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/leader"
	"github.com/your-org/sentinel-waf/control-plane/internal/logs"
	"github.com/your-org/sentinel-waf/control-plane/internal/rbac"
)

// ---------------------------------------------------------------------------
// Blocked sources — one view of everything currently being blocked, and unblock.
//
//   GET    /api/v1/blocks            data-plane bans (XDP auto-ban, eBPF list,
//                                    repeat offenders) + block-tier IP/CIDR
//                                    indicators + blocked countries
//   DELETE /api/v1/blocks/ip/:ip     lift the data plane's own block on an IP
//
// Indicators are removed through DELETE /threat-intel/iocs/:id and countries
// through DELETE /geoip/block/:code — both existed; this page is the place that
// shows them together. Before it, an auto-banned IP appeared nowhere in the
// console and could only be released by restarting the data plane.
// ---------------------------------------------------------------------------

var blocksHTTPClient = &http.Client{Timeout: 6 * time.Second}

func handleListBlocks(c *gin.Context, enf *rbac.Enforcer, store *db.Store) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceIPList, rbac.ActionList) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	resp := gin.H{}

	// 1. Data plane: what this node is dropping on its own initiative.
	req, _ := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, dataPlaneBaseURL()+"/api/v1/internal/blocks", nil)
	setInternalAuth(req)
	if r, err := blocksHTTPClient.Do(req); err == nil {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		r.Body.Close()
		var dp map[string]any
		if r.StatusCode == http.StatusOK && json.Unmarshal(body, &dp) == nil {
			dp["reachable"] = true
			resp["dataplane"] = dp
		} else {
			resp["dataplane"] = gin.H{"reachable": false, "error": "data plane returned " + r.Status}
		}
	} else {
		resp["dataplane"] = gin.H{"reachable": false, "error": err.Error()}
	}

	// 2. Block-tier IP and CIDR indicators (feeds + manual).
	//
	// The page is capped at 500 per type, and the console used to count the rows
	// it received — so a feed holding 18,013 block-tier indicators displayed as
	// "THREAT INTEL 500", a page size presented as a fleet total. ListIOCs
	// already returns the true match count; it was simply discarded here. Both
	// are returned now so the console can say "500 of 18,013" instead of
	// implying the cap is the answer.
	indicators := []db.IOCListItem{}
	indicatorsTotal := 0
	if store != nil {
		for _, t := range []string{"ip", "cidr"} {
			page, err := store.ListIOCs(c.Request.Context(), db.IOCListFilter{Type: t, Tier: "block", Limit: 500})
			if err != nil {
				resp["indicators_error"] = err.Error()
				break
			}
			indicators = append(indicators, page.Items...)
			indicatorsTotal += page.Total
		}
	}
	resp["indicators"] = indicators
	resp["indicators_total"] = indicatorsTotal

	// 3. Countries blocked by any site's policy.
	countries := []string{}
	if store != nil {
		if sites, err := store.ListSites(c.Request.Context(), claims.TenantID, claims.UserID); err == nil {
			countries = blockedUnion(sites)
		}
	}
	resp["countries"] = countries
	c.JSON(http.StatusOK, resp)
}

func handleUnblockIP(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *leader.Elector) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceIPList, rbac.ActionDelete) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if !requireLeader(c, cl) {
		return
	}
	raw := c.Param("ip")
	ip := net.ParseIP(raw)
	if ip == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "not an IP address"})
		return
	}
	// Every data-plane node holds its own bans. Sent to one URL, an unblock
	// lifted the ban on whichever node answered and left it on the rest.
	targets := unblockTargets(c.Request.Context(), store)
	type nodeResult struct {
		Target string         `json:"target"`
		OK     bool           `json:"ok"`
		Error  string         `json:"error,omitempty"`
		Result map[string]any `json:"result,omitempty"`
	}
	results := make([]nodeResult, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t string) {
			defer wg.Done()
			results[i] = nodeResult{Target: t}
			req, _ := http.NewRequestWithContext(c.Request.Context(), http.MethodDelete, t+"/api/v1/internal/blocks/"+ip.String(), nil)
			setInternalAuth(req)
			r, err := blocksHTTPClient.Do(req)
			if err != nil {
				results[i].Error = "unreachable: " + err.Error()
				return
			}
			defer r.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if r.StatusCode != http.StatusOK {
				results[i].Error = "returned " + r.Status
				return
			}
			_ = json.Unmarshal(body, &results[i].Result)
			results[i].OK = true
		}(i, t)
	}
	wg.Wait()
	var result map[string]any
	failed := 0
	for _, r := range results {
		if !r.OK {
			failed++
		} else if result == nil {
			result = r.Result
		}
	}
	if failed == len(results) {
		c.JSON(http.StatusBadGateway, gin.H{"error": "no data-plane node accepted the unblock", "nodes": results})
		return
	}
	if store != nil {
		actor := claims.UserID
		diff, _ := json.Marshal(gin.H{"ip": ip.String(), "result": result, "nodes": results})
		writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
			TenantID:    claims.TenantID,
			ActorUserID: &actor,
			Action:      "block.ip.remove",
			TargetKind:  "ip_block",
			Diff:        diff,
		})
	}
	c.JSON(http.StatusOK, gin.H{"ok": failed == 0, "partial": failed > 0, "result": result, "nodes": results})
}

// unblockTargets is the configured data-plane URL plus every data-plane node
// heard from in the last ten minutes, by its hostname on the same scheme and
// port. A hostname is used only if it is a plain host name: the request carries
// the internal secret.
func unblockTargets(ctx context.Context, store *db.Store) []string {
	base := strings.TrimRight(dataPlaneBaseURL(), "/")
	out := []string{base}
	u, err := url.Parse(base)
	if err != nil || store == nil {
		return out
	}
	nodes, err := store.ListNodes(ctx)
	if err != nil {
		return out
	}
	seen := map[string]bool{base: true}
	for _, n := range nodes {
		if n.Role != "data-plane" || time.Since(n.LastSeen) > 10*time.Minute || !plainHostname(n.Hostname) {
			continue
		}
		host := n.Hostname
		if p := u.Port(); p != "" {
			host = net.JoinHostPort(host, p)
		}
		if t := u.Scheme + "://" + host; !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

func plainHostname(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, r := range h {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-') {
			return false
		}
	}
	return true
}
