package main

import (
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/your-org/sentinel-waf/control-plane/internal/leader"

	"github.com/your-org/sentinel-waf/control-plane/internal/version"
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
func leaderForward(cl *leader.Elector) gin.HandlerFunc {
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

		id, advertise, ok := cl.Leader()
		if !ok || advertise == "" {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable,
				gin.H{"error": "no leader elected yet — retry shortly"})
			return
		}
		// The leader advertises its REST address directly, so there is no longer a
		// Raft port to rewrite. Fall back to the shared REST port if it advertised
		// a bare host.
		host, port, err := net.SplitHostPort(advertise)
		if err != nil {
			host, port = advertise, restPort
		}
		target := (&url.URL{
			Scheme:   "http",
			Host:     net.JoinHostPort(host, port),
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
				gin.H{"error": "leader unreachable: " + err.Error(), "leader_id": id})
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

// requireLeader returns true if this node holds write leadership and the request
// may proceed. Otherwise it writes a retryable 503 naming the current leader (if
// known) so clients and proxies can retry there, and returns false.
//
// When cl is nil no database is configured, so the node is a standalone writer and
// all writes proceed.
//
// This replaced proposeBest(), which additionally round-tripped a Raft log entry
// before the handler wrote to Postgres. That entry was pure overhead: the state
// machine's Apply hook was a no-op, so nothing ever consumed the log, and the real
// state change went to Postgres immediately afterwards either way. Worse, its
// commit required control-plane quorum, so losing 2 of 3 nodes refused every write
// even while Postgres — itself HA with its own synchronous quorum — was healthy
// and writable. Leadership now comes from a Postgres advisory lock, so write
// availability depends only on the database the write was going to anyway.
func requireLeader(c *gin.Context, cl *leader.Elector) bool {
	if cl == nil || cl.IsLeader() {
		return true
	}
	resp := gin.H{"error": "not the write leader"}
	if id, addr, ok := cl.Leader(); ok {
		resp["leader_id"] = id
		resp["leader_addr"] = addr
		if addr != "" {
			c.Header("X-Sentinel-Leader", addr)
		}
	} else {
		resp["error"] = "no leader elected yet — retry shortly"
	}
	// Retryable: leadership changes are brief and clients should back off, not fail.
	c.Header("Retry-After", "2")
	c.JSON(http.StatusServiceUnavailable, resp)
	return false
}

// handleClusterStatus exposes the Raft state for monitoring.
func handleClusterStatus(c *gin.Context, cl *leader.Elector) {
	if cl == nil {
		c.JSON(http.StatusOK, gin.H{
			"enabled": false,
			"role":    "standalone",
			"build":   version.Info(),
		})
		return
	}
	st := cl.Status()
	c.JSON(http.StatusOK, gin.H{
		"enabled": true,
		"status":  st,
		"build":   version.Info(),
	})
}
