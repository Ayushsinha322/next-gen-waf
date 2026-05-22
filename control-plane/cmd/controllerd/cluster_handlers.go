package main

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/your-org/sentinel-waf/control-plane/internal/cluster"
)

// requireLeader returns true if this node is the leader and the request may
// proceed.  Otherwise it writes a 503 with a Location header pointing at the
// known leader (if any) so clients/proxies can retry there, and returns false.
//
// When cluster is nil (single-node bootstrap without --enable-cluster), all
// writes proceed unconditionally — the same behaviour we had pre-Raft.
func requireLeader(c *gin.Context, cl *cluster.Cluster) bool {
	if cl == nil {
		return true
	}
	if cl.IsLeader() {
		return true
	}
	id, addr := cl.LeaderHint()
	resp := gin.H{"error": "not the leader"}
	if id != nil {
		resp["leader_id"] = *id
		resp["leader_addr"] = addr
		if addr != "" {
			c.Header("X-Sentinel-Leader", addr)
		}
	}
	c.JSON(http.StatusServiceUnavailable, resp)
	return false
}

// proposeBest tries to replicate a command through Raft.  When the cluster is
// nil (Raft disabled) it's a no-op success.  On *NotLeaderError it writes the
// 503 redirect and returns false so the caller can short-circuit.
func proposeBest(c *gin.Context, cl *cluster.Cluster, kind cluster.CommandKind, payload interface{}) bool {
	if cl == nil {
		return true
	}
	if !cl.IsLeader() {
		id, addr := cl.LeaderHint()
		resp := gin.H{"error": "not the leader"}
		if id != nil {
			resp["leader_id"] = *id
			resp["leader_addr"] = addr
			if addr != "" {
				c.Header("X-Sentinel-Leader", addr)
			}
		}
		c.JSON(http.StatusServiceUnavailable, resp)
		return false
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "marshal command: " + err.Error()})
		return false
	}
	if err := cl.Propose(c.Request.Context(), cluster.Command{Kind: kind, Payload: raw}); err != nil {
		var nle *cluster.NotLeaderError
		if errors.As(err, &nle) {
			resp := gin.H{"error": "not the leader"}
			if nle.LeaderID != nil {
				resp["leader_id"] = *nle.LeaderID
				resp["leader_addr"] = nle.LeaderAddr
			}
			c.JSON(http.StatusServiceUnavailable, resp)
			return false
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "raft propose: " + err.Error()})
		return false
	}
	return true
}

// handleClusterStatus exposes the Raft state for monitoring.
func handleClusterStatus(c *gin.Context, cl *cluster.Cluster) {
	if cl == nil {
		c.JSON(http.StatusOK, gin.H{
			"enabled": false,
			"role":    "standalone",
		})
		return
	}
	st := cl.Status()
	c.JSON(http.StatusOK, gin.H{
		"enabled": true,
		"status":  st,
	})
}
