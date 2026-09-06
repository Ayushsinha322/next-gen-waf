package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
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
	indicators := []db.IOCListItem{}
	if store != nil {
		for _, t := range []string{"ip", "cidr"} {
			page, err := store.ListIOCs(c.Request.Context(), db.IOCListFilter{Type: t, Tier: "block", Limit: 500})
			if err != nil {
				resp["indicators_error"] = err.Error()
				break
			}
			indicators = append(indicators, page.Items...)
		}
	}
	resp["indicators"] = indicators

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
	req, _ := http.NewRequestWithContext(c.Request.Context(), http.MethodDelete, dataPlaneBaseURL()+"/api/v1/internal/blocks/"+ip.String(), nil)
	setInternalAuth(req)
	r, err := blocksHTTPClient.Do(req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "data plane unreachable: " + err.Error()})
		return
	}
	defer r.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if r.StatusCode != http.StatusOK {
		c.JSON(http.StatusBadGateway, gin.H{"error": "data plane returned " + r.Status, "detail": string(body)})
		return
	}
	var result map[string]any
	_ = json.Unmarshal(body, &result)
	if store != nil {
		actor := claims.UserID
		diff, _ := json.Marshal(gin.H{"ip": ip.String(), "result": result})
		writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
			TenantID:    claims.TenantID,
			ActorUserID: &actor,
			Action:      "block.ip.remove",
			TargetKind:  "ip_block",
			Diff:        diff,
		})
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "result": result})
}
