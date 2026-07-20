package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/your-org/sentinel-waf/control-plane/internal/cluster"
)

// hopByHopHeaders are connection-scoped and must NOT be copied from the leader's
// response to the client (RFC 7230 §6.1). Also skip headers the follower's own
// middleware already set on the response (CORS, Date) so forwarding doesn't emit
// a duplicate (a doubled Access-Control-Allow-Origin makes browsers reject the
// otherwise-successful cross-origin write).
var skipForwardRespHeaders = map[string]bool{
	"connection":                       true,
	"keep-alive":                       true,
	"proxy-authenticate":               true,
	"proxy-authorization":              true,
	"te":                               true,
	"trailer":                          true,
	"transfer-encoding":                true,
	"upgrade":                          true,
	"date":                             true,
	"access-control-allow-origin":      true,
	"access-control-allow-methods":     true,
	"access-control-allow-headers":     true,
	"access-control-allow-credentials": true,
	"access-control-expose-headers":    true,
}

// leaderForwardClient proxies mutating requests to the Raft leader. The timeout
// comfortably exceeds the leader's Propose commit timeout so a slow (but not
// dead) leader isn't cut off mid-replication.
var leaderForwardClient = &http.Client{Timeout: 20 * time.Second}

// clusterRESTPort is the port every control-plane node serves its REST API on;
// leader-forwarding rewrites the leader's Raft address (host:9600) to its REST
// address (host:<this>). All nodes share the same REST port, so one value works
// for the whole cluster. Override with SENTINEL_CLUSTER_REST_PORT if needed.
func clusterRESTPort() string {
	if p := os.Getenv("SENTINEL_CLUSTER_REST_PORT"); p != "" {
		return p
	}
	if a := os.Getenv("SENTINEL_REST_ADDR"); a != "" {
		if _, port, err := net.SplitHostPort(a); err == nil && port != "" {
			return port
		}
	}
	return "9501"
}

// leaderForward transparently proxies mutating requests (POST/PUT/PATCH/DELETE)
// to the current Raft leader, so a client can talk to ANY control-plane node and
// still have its writes committed by the leader. Reads (GET/HEAD/OPTIONS) are
// served locally — every node shares the same Postgres, so reads are consistent
// anywhere and don't need the extra hop. When clustering is disabled (cl == nil)
// this is a no-op. The X-Sentinel-Forwarded header is a loop-guard: a request
// that has already been forwarded once is processed locally even on a follower
// (covers the rare window where leadership moves mid-forward), so a request can
// bounce at most once.
//
// This is the standard "any node accepts writes; the cluster routes to the
// leader" model (etcd/Consul-style). It must run BEFORE the auth middleware on
// each group: on a follower we forward the raw request (Authorization header and
// all) and let the leader authenticate, avoiding double work.
func leaderForward(cl *cluster.Cluster) gin.HandlerFunc {
	restPort := clusterRESTPort()
	return func(c *gin.Context) {
		if cl == nil {
			c.Next()
			return
		}
		switch c.Request.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			c.Next()
			return
		}
		if c.GetHeader("X-Sentinel-Forwarded") != "" {
			c.Next() // already routed here once — process locally, don't bounce again
			return
		}
		if cl.IsLeader() {
			c.Next()
			return
		}

		id, raftAddr := cl.LeaderHint()
		if id == nil || raftAddr == "" {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable,
				gin.H{"error": "no leader elected yet — retry shortly"})
			return
		}
		host, _, err := net.SplitHostPort(raftAddr)
		if err != nil {
			host = raftAddr
		}
		target := (&url.URL{
			Scheme:   "http",
			Host:     net.JoinHostPort(host, restPort),
			Path:     c.Request.URL.Path,
			RawQuery: c.Request.URL.RawQuery,
		}).String()

		req, err := http.NewRequestWithContext(c.Request.Context(),
			c.Request.Method, target, c.Request.Body)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadGateway,
				gin.H{"error": "leader forward: " + err.Error()})
			return
		}
		req.Header = c.Request.Header.Clone()
		req.Header.Set("X-Sentinel-Forwarded", "1")
		req.Header.Set("X-Forwarded-For", c.ClientIP())
		req.ContentLength = c.Request.ContentLength

		resp, err := leaderForwardClient.Do(req)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadGateway,
				gin.H{"error": "leader unreachable: " + err.Error(), "leader_id": *id})
			return
		}
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			if skipForwardRespHeaders[strings.ToLower(k)] {
				continue
			}
			for _, v := range vs {
				c.Writer.Header().Add(k, v)
			}
		}
		c.Writer.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(c.Writer, resp.Body)
		c.Abort()
	}
}

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
	// Bound the commit: if quorum is lost (e.g. 2 of 3 nodes down) Propose would
	// otherwise block until the client disconnects. Fast-fail with a retryable
	// 503 instead so callers/proxies back off and retry cleanly.
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	if err := cl.Propose(ctx, cluster.Command{Kind: kind, Payload: raw}); err != nil {
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
		if errors.Is(err, context.DeadlineExceeded) {
			c.Header("Retry-After", "2")
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "raft commit timed out (quorum unavailable?) — retry shortly"})
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
