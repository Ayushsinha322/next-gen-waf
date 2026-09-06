package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/leader"
	"github.com/your-org/sentinel-waf/control-plane/internal/rbac"

	"github.com/your-org/sentinel-waf/control-plane/internal/version"
)

// nodeHeartbeatRequest is the body posted by a data-plane node to
// POST /api/v1/internal/nodes/heartbeat.
type nodeHeartbeatRequest struct {
	ID       string          `json:"id"`
	Hostname string          `json:"hostname"`
	Role     string          `json:"role"`
	Version  string          `json:"version"`
	Status   string          `json:"status"`
	Metadata json.RawMessage `json:"metadata"`
}

// handleNodeHeartbeat ingests a node's health heartbeat. Gated by the shared
// internal secret (like /internal/config and /internal/threat-intel), not JWT.
func handleNodeHeartbeat(c *gin.Context, store *db.Store) {
	if !internalSecretOK(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	var req nodeHeartbeatRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.ID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid heartbeat: id required"})
		return
	}
	if req.Role == "" {
		req.Role = "data-plane"
	}
	if req.Status == "" {
		req.Status = "healthy"
	}
	if err := store.UpsertNode(c.Request.Context(), db.Node{
		ID:       req.ID,
		Hostname: req.Hostname,
		Role:     req.Role,
		Version:  req.Version,
		Status:   req.Status,
		Metadata: req.Metadata,
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "persist heartbeat: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// nodeMetadata is the subset of a node's heartbeat metadata surfaced in the
// cluster-health read.
type nodeMetadata struct {
	UptimeSecs       int64 `json:"uptime_secs"`
	Sites            int   `json:"sites"`
	UpstreamsHealthy int   `json:"upstreams_healthy"`
	UpstreamsTotal   int   `json:"upstreams_total"`
	// Per-node drill-down (newer data planes; zero/absent on older ones).
	Listeners            []string        `json:"listeners"`
	HTTP3Enabled         bool            `json:"http3_enabled"`
	ConfigVersionApplied int64           `json:"config_version_applied"`
	RulesCompiled        int             `json:"rules_compiled"`
	RulesEnforced        int             `json:"rules_enforced"`
	EbpfMode             string          `json:"ebpf_mode"`
	EbpfDrops            int64           `json:"ebpf_drops"`
	ThreatIntelEntries   int             `json:"threat_intel_entries"`
	ThreatIntelVersion   int64           `json:"threat_intel_version"`
	InlineRules          json.RawMessage `json:"inline_rules"`
}

// nodeDownAfter reads the staleness window (default 30s) shared with the
// node-health monitor.
func nodeDownAfter() time.Duration {
	if v := os.Getenv("SENTINEL_NODE_DOWN_SECS"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return 30 * time.Second
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// handleClusterHealth returns a unified data-plane + control-plane health view.
// JWT-protected; requires site:list (same gate as handleClusterStatus).
func handleClusterHealth(c *gin.Context, enf *rbac.Enforcer, store *db.Store, cl *leader.Elector) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if claims == nil || !enf.Allow(rbac.Role(claims.Role), rbac.ResourceSite, rbac.ActionList) {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}

	downAfter := nodeDownAfter()

	// ── Data plane ──────────────────────────────────────────────────────────
	dpNodes := []gin.H{}
	dpHealthy, dpDegraded, dpDown := 0, 0, 0
	if store != nil {
		nodes, err := store.ListNodes(c.Request.Context())
		if err == nil {
			for _, n := range nodes {
				secondsSince := int(time.Since(n.LastSeen).Seconds())
				status := n.Status
				if time.Since(n.LastSeen) > downAfter {
					status = "down"
				}
				switch status {
				case "healthy":
					dpHealthy++
				case "degraded":
					dpDegraded++
				default:
					status = "down"
					dpDown++
				}
				var md nodeMetadata
				if len(n.Metadata) > 0 {
					_ = json.Unmarshal(n.Metadata, &md)
				}
				dpNodes = append(dpNodes, gin.H{
					"id":                 n.ID,
					"hostname":           n.Hostname,
					"role":               n.Role,
					"version":            n.Version,
					"status":             status,
					"last_seen":          n.LastSeen.Unix(),
					"seconds_since_seen": secondsSince,
					"uptime_secs":        md.UptimeSecs,
					"sites":              md.Sites,
					"upstreams_healthy":  md.UpstreamsHealthy,
					"upstreams_total":    md.UpstreamsTotal,
					// drill-down
					"listeners":              md.Listeners,
					"http3_enabled":          md.HTTP3Enabled,
					"config_version_applied": md.ConfigVersionApplied,
					"rules_compiled":         md.RulesCompiled,
					"rules_enforced":         md.RulesEnforced,
					"ebpf_mode":              md.EbpfMode,
					"ebpf_drops":             md.EbpfDrops,
					"threat_intel_entries":   md.ThreatIntelEntries,
					"threat_intel_version":   md.ThreatIntelVersion,
					"inline_rules":           md.InlineRules,
				})
			}
		}
	}
	// The version the control plane currently serves, so the page can flag a
	// node whose config_version_applied lags it (stale, not just "healthy").
	var currentCfgVersion int64
	if store != nil {
		if v, err := store.ConfigVersion(c.Request.Context()); err == nil {
			currentCfgVersion = v
		}
	}
	dpTotal := len(dpNodes)
	dataPlane := gin.H{
		"total":             dpTotal,
		"healthy":           dpHealthy,
		"degraded":          dpDegraded,
		"down":              dpDown,
		"resilience_budget": maxInt(0, dpHealthy-1),
		"nodes":             dpNodes,
	}

	// ── Control plane ───────────────────────────────────────────────────────
	//
	// Membership comes from the shared cluster_members table, which every node
	// heartbeats into. This is strictly more accurate than the Raft-era view: Raft
	// tracked peer liveness only leader->follower, so a follower could not observe
	// its peers and this endpoint had to fall back to "a leader exists, so assume
	// the rest are up". Now any node reports real per-node liveness.
	//
	// There is deliberately no quorum here. Control-plane availability no longer
	// depends on a control-plane majority — leadership is a Postgres advisory lock,
	// so a single surviving node still serves writes as long as the database is
	// reachable. `write_available` reports the thing that actually matters.
	cpAnyUnreachable := false
	var controlPlane gin.H
	if cl == nil {
		controlPlane = gin.H{
			"enabled":           false,
			"role":              "standalone",
			"total":             1,
			"healthy":           1,
			"write_available":   true,
			"leader_id":         nil,
			"resilience_budget": 0,
			"nodes":             []gin.H{},
		}
	} else {
		st := cl.Status()
		members, merr := cl.Members(c.Request.Context())
		if merr != nil {
			// Membership is observability, not the authority on leadership; a query
			// failure must not fail the health endpoint.
			members = nil
		}

		cpNodes := make([]gin.H, 0, len(members))
		healthy := 0
		for _, m := range members {
			if m.Reachable {
				healthy++
			} else {
				cpAnyUnreachable = true
			}
			role := "follower"
			if m.IsLeader {
				role = "leader"
			}
			cpNodes = append(cpNodes, gin.H{
				"node_id":       m.NodeID,
				"role":          role,
				"is_leader":     m.IsLeader,
				"is_self":       m.NodeID == st.NodeID,
				"reachable":     m.Reachable,
				"last_seen_sec": m.LastSeenSec,
				"addr":          m.Advertise,
			})
		}
		// Fall back to describing just this node if membership could not be read, so
		// the view degrades to "what I know" rather than "empty cluster".
		if len(cpNodes) == 0 {
			cpNodes = append(cpNodes, gin.H{
				"node_id":       st.NodeID,
				"role":          st.Role,
				"is_leader":     st.Role == "leader",
				"is_self":       true,
				"reachable":     true,
				"last_seen_sec": int64(0),
				"addr":          st.LeaderAddr,
			})
			healthy = 1
		}

		var leaderID interface{}
		if st.LeaderID != "" {
			leaderID = st.LeaderID
		}
		controlPlane = gin.H{
			"enabled":         true,
			"role":            st.Role,
			"total":           len(cpNodes),
			"healthy":         healthy,
			"write_available": st.LeaderID != "",
			"leader_id":       leaderID,
			"leader_addr":     st.LeaderAddr,
			// Every healthy node beyond the one serving writes is spare capacity;
			// unlike Raft there is no majority to preserve, so the budget is simply
			// "how many more can I lose and still have a node".
			"resilience_budget": maxInt(0, healthy-1),
			"nodes":             cpNodes,
		}
	}

	// ── Overall verdict ─────────────────────────────────────────────────────
	cpEnabled, _ := controlPlane["enabled"].(bool)
	cpWritable, _ := controlPlane["write_available"].(bool)

	overall := "healthy"
	switch {
	case (dpTotal > 0 && dpHealthy == 0) || (cpEnabled && !cpWritable):
		overall = "critical"
	case dpDown > 0 || dpDegraded > 0 || cpAnyUnreachable:
		overall = "degraded"
	}
	protectionActive := dpHealthy >= 1 || dpTotal == 0

	c.JSON(http.StatusOK, gin.H{
		"config_version":    currentCfgVersion,
		"build":             version.Info(),
		"generated_at":      time.Now().Unix(),
		"overall":           overall,
		"protection_active": protectionActive,
		"data_plane":        dataPlane,
		"control_plane":     controlPlane,
	})
}
