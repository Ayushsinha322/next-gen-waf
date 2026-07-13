package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	"github.com/your-org/sentinel-waf/control-plane/internal/cluster"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/rbac"
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
func handleClusterHealth(c *gin.Context, enf *rbac.Enforcer, store *db.Store, cl *cluster.Cluster) {
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
				})
			}
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
	cpAnyUnreachable := false
	var controlPlane gin.H
	if cl == nil {
		controlPlane = gin.H{
			"enabled":           false,
			"role":              "standalone",
			"total":             0,
			"healthy":           0,
			"quorum_size":       0,
			"quorum_ok":         true,
			"leader_id":         nil,
			"term":              0,
			"resilience_budget": 0,
			"nodes":             []gin.H{},
		}
	} else {
		st := cl.Status()
		selfIsLeader := st.LeaderID != nil && *st.LeaderID == st.NodeID
		cpNodes := []gin.H{
			{
				"node_id":       uint64(st.NodeID),
				"role":          string(st.Role),
				"is_leader":     selfIsLeader,
				"is_self":       true,
				"reachable":     true,
				"last_seen_sec": int64(0),
				"addr":          "",
			},
		}
		healthy := 1
		for _, p := range st.Peers {
			if p.Reachable {
				healthy++
			} else {
				cpAnyUnreachable = true
			}
			isLeader := st.LeaderID != nil && *st.LeaderID == p.NodeID
			cpNodes = append(cpNodes, gin.H{
				"node_id":       uint64(p.NodeID),
				"role":          "unknown",
				"is_leader":     isLeader,
				"is_self":       false,
				"reachable":     p.Reachable,
				"last_seen_sec": p.LastSeenSec,
				"addr":          p.Addr,
			})
		}
		total := len(st.Peers) + 1
		quorumSize := total/2 + 1
		var leaderID interface{}
		if st.LeaderID != nil {
			leaderID = uint64(*st.LeaderID)
		}
		controlPlane = gin.H{
			"enabled":           true,
			"role":              string(st.Role),
			"total":             total,
			"healthy":           healthy,
			"quorum_size":       quorumSize,
			"quorum_ok":         healthy >= quorumSize,
			"leader_id":         leaderID,
			"term":              st.Term,
			"resilience_budget": maxInt(0, healthy-quorumSize),
			"nodes":             cpNodes,
		}
	}

	// ── Overall verdict ─────────────────────────────────────────────────────
	cpEnabled, _ := controlPlane["enabled"].(bool)
	cpQuorumOK, _ := controlPlane["quorum_ok"].(bool)

	overall := "healthy"
	switch {
	case (dpTotal > 0 && dpHealthy == 0) || (cpEnabled && !cpQuorumOK):
		overall = "critical"
	case dpDown > 0 || dpDegraded > 0 || cpAnyUnreachable:
		overall = "degraded"
	}
	protectionActive := dpHealthy >= 1 || dpTotal == 0

	c.JSON(http.StatusOK, gin.H{
		"generated_at":      time.Now().Unix(),
		"overall":           overall,
		"protection_active": protectionActive,
		"data_plane":        dataPlane,
		"control_plane":     controlPlane,
	})
}
