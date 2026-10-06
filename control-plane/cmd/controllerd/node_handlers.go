package main

import (
	"encoding/json"
	"fmt"
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
	ConfigSync           *nodeConfigSync `json:"config_sync"`
	RulesCompiled        int             `json:"rules_compiled"`
	RulesEnforced        int             `json:"rules_enforced"`
	EbpfMode             string          `json:"ebpf_mode"`
	EbpfDrops            int64           `json:"ebpf_drops"`
	ThreatIntelEntries   int             `json:"threat_intel_entries"`
	ThreatIntelVersion   int64           `json:"threat_intel_version"`
	ThreatIntelSync      *nodeTISync     `json:"threat_intel_sync"`
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

// fleetVerdict turns the counted node states into the two things the console
// puts in front of every operator: the fleet's overall status, and whether
// traffic is being inspected at all.
//
// The distinction this used to get wrong. A DEGRADED node is alive, heartbeating,
// its rules compiled, and it inspects every request — it simply cannot reach any
// origin behind it. That is the application being unreachable, not the WAF. The
// old rule counted only `healthy` nodes, so a single node with a broken origin
// produced protection_active=false, and the top bar showed a red "Protection
// inactive" badge on EVERY page while the WAF was doing its job exactly as
// configured (seen on the UAT node, whose origin served a certificate without
// its intermediate chain). An operator reading that badge goes looking for a
// broken WAF, which is the one thing that is not broken.
//
// So:
//   - protection is active while at least one node is UP — healthy OR degraded —
//     and trivially so when no node is deployed yet;
//   - critical means nothing can inspect traffic (no node up), or writes are
//     unavailable, because those are the states where the product is not doing
//     its job;
//   - anything short of fully healthy is degraded, which is still visible and
//     still worth investigating — the per-node upstream counts say why.
//
// Pure, so the semantics can be tested without a database.
// nodeConfigSync is a data plane's own account of whether it is taking config
// (crates/sentinel-proxy ConfigSyncStatus).
type nodeConfigSync struct {
	LastError     *string `json:"last_error"`
	FailingSince  *int64  `json:"failing_since"`
	RejectedSites []struct {
		ID           string `json:"id"`
		Error        string `json:"error"`
		KeptPrevious bool   `json:"kept_previous"`
	} `json:"rejected_sites"`
}

// nodeTISync is a data plane's account of its threat-intel poller
// (crates/sentinel-proxy ti_sync_heartbeat). Without it the entry count above
// read the same for a node refreshing its IOC set every minute and one whose
// polls had been failing for a day.
type nodeTISync struct {
	Poller         string  `json:"poller"`
	LastSyncStatus int     `json:"last_sync_status"`
	LastError      *string `json:"last_error"`
	FailingSince   *int64  `json:"failing_since"`
}

// threatIntelSyncProblem says why a node's IOC set is not being refreshed, or
// "" when it is (or the node predates the field). Shown on the node, not folded
// into the fleet verdict: a stale feed still enforces what it holds.
func threatIntelSyncProblem(ts *nodeTISync) string {
	if ts == nil {
		return ""
	}
	if ts.LastError != nil {
		if ts.FailingSince != nil {
			return fmt.Sprintf("threat-intel sync failing since %s: %s",
				time.Unix(*ts.FailingSince, 0).UTC().Format(time.RFC3339), *ts.LastError)
		}
		return "threat-intel sync failing: " + *ts.LastError
	}
	if ts.Poller == "rejected" {
		return fmt.Sprintf("threat-intel sync refused by the control plane with HTTP %d (403 = SENTINEL_INTERNAL_SECRET mismatch)",
			ts.LastSyncStatus)
	}
	return ""
}

// configSyncGrace is how long polls may fail before a node counts as not taking
// config: one missed 5s poll during a control-plane restart is not an incident.
const configSyncGrace = 30 * time.Second

// rejectingConfig reports whether a node is not applying what the control plane
// serves, and why, in the operator's terms.
func rejectingConfig(cs *nodeConfigSync, now time.Time) (bool, string) {
	if cs == nil {
		return false, ""
	}
	if n := len(cs.RejectedSites); n > 0 {
		r := cs.RejectedSites[0]
		what := "keeps its previous config"
		if !r.KeptPrevious {
			what = "is not served"
		}
		msg := fmt.Sprintf("rejected site %s (%s): %s", r.ID, what, r.Error)
		if n > 1 {
			msg += fmt.Sprintf(" — and %d more", n-1)
		}
		return true, msg
	}
	if cs.LastError != nil && cs.FailingSince != nil &&
		now.Sub(time.Unix(*cs.FailingSince, 0)) >= configSyncGrace {
		return true, fmt.Sprintf("config sync failing since %s: %s",
			time.Unix(*cs.FailingSince, 0).UTC().Format(time.RFC3339), *cs.LastError)
	}
	return false, ""
}

// withConfigSync degrades a healthy verdict when any node is not taking config.
// Before it existed the cluster headline read HEALTHY while every node served a
// frozen configuration and each change "saved" in the console reached none.
func withConfigSync(overall string, nodesRejecting int) string {
	if overall == "healthy" && nodesRejecting > 0 {
		return "degraded"
	}
	return overall
}

func fleetVerdict(dpTotal, dpHealthy, dpDegraded, dpDown int, cpEnabled, cpWritable, cpAnyUnreachable bool) (string, bool) {
	up := dpHealthy + dpDegraded
	protectionActive := up >= 1 || dpTotal == 0
	switch {
	case (dpTotal > 0 && up == 0) || (cpEnabled && !cpWritable):
		return "critical", protectionActive
	case dpDown > 0 || dpDegraded > 0 || cpAnyUnreachable:
		return "degraded", protectionActive
	}
	return "healthy", protectionActive
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
	staleAfter := nodeStaleAfter()

	// ── Data plane ──────────────────────────────────────────────────────────
	dpNodes := []gin.H{}
	dpHealthy, dpDegraded, dpDown, dpStale := 0, 0, 0, 0
	dpUpstreamsHealthy, dpUpstreamsTotal := 0, 0
	dpRejectingConfig := 0
	if store != nil {
		nodes, err := store.ListNodes(c.Request.Context())
		if err == nil {
			for _, n := range nodes {
				sinceSeen := time.Since(n.LastSeen)
				secondsSince := int(sinceSeen.Seconds())
				status := classifyNode(n.Status, sinceSeen, downAfter, staleAfter)
				switch status {
				case "healthy":
					dpHealthy++
				case "degraded":
					dpDegraded++
				case "stale":
					// Silent for longer than the stale window: a former container
					// identity, not an outage. Listed so the page can say "last seen
					// 4 days ago"; never counted as down.
					dpStale++
				default:
					dpDown++
				}
				var md nodeMetadata
				if len(n.Metadata) > 0 {
					_ = json.Unmarshal(n.Metadata, &md)
				}
				// Only nodes that are up have meaningful upstream counts; a node
				// that stopped reporting last week would otherwise contribute its
				// final reading to a total describing the fleet right now.
				rejecting, syncProblem := false, ""
				if status == "healthy" || status == "degraded" {
					dpUpstreamsHealthy += md.UpstreamsHealthy
					dpUpstreamsTotal += md.UpstreamsTotal
					rejecting, syncProblem = rejectingConfig(md.ConfigSync, time.Now())
					if rejecting {
						dpRejectingConfig++
					}
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
					"config_rejecting":       rejecting,
					"config_sync_problem":    syncProblem,
					"rules_compiled":         md.RulesCompiled,
					"rules_enforced":         md.RulesEnforced,
					"ebpf_mode":              md.EbpfMode,
					"ebpf_drops":             md.EbpfDrops,
					"threat_intel_entries":   md.ThreatIntelEntries,
					"threat_intel_version":   md.ThreatIntelVersion,
					"threat_intel_problem":   threatIntelSyncProblem(md.ThreatIntelSync),
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
	// total = nodes that exist. Stale rows are listed for the operator's benefit
	// but are not part of the fleet, so they are excluded from total and from
	// every verdict below.
	dpTotal := dpHealthy + dpDegraded + dpDown
	dataPlane := gin.H{
		"total":             dpTotal,
		"healthy":           dpHealthy,
		"degraded":          dpDegraded,
		"down":              dpDown,
		"stale":             dpStale,
		"rejecting_config":  dpRejectingConfig,
		"resilience_budget": maxInt(0, dpHealthy-1),
		// Summed across the nodes that are up, so the page can say WHY the fleet
		// is degraded — "protection active, 0 of 1 origins reachable" rather than
		// leaving the operator to open a node to find out.
		"upstreams_healthy": dpUpstreamsHealthy,
		"upstreams_total":   dpUpstreamsTotal,
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

	overall, protectionActive := fleetVerdict(dpTotal, dpHealthy, dpDegraded, dpDown, cpEnabled, cpWritable, cpAnyUnreachable)
	overall = withConfigSync(overall, dpRejectingConfig)

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
