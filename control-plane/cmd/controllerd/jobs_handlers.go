package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/jobs"
	"github.com/your-org/sentinel-waf/control-plane/internal/leader"
	"github.com/your-org/sentinel-waf/control-plane/internal/logs"
	"github.com/your-org/sentinel-waf/control-plane/internal/rbac"
)

// ---------------------------------------------------------------------------
// GET  /api/v1/jobs            every background job on THIS control-plane node
//                              (they run on the leader) + the data plane's own
//                              poller state from /healthz
// POST /api/v1/jobs/:name/run  run one now, synchronously, and report the outcome
// ---------------------------------------------------------------------------

func handleListJobs(c *gin.Context, enf *rbac.Enforcer, cl *leader.Elector) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceSettings, rbac.ActionRead) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	role := "standalone"
	isLeader := true
	if cl != nil {
		isLeader = cl.IsLeader()
		if isLeader {
			role = "leader"
		} else {
			role = "follower"
		}
	}
	resp := gin.H{
		"node":  gin.H{"role": role, "runs_jobs": isLeader},
		"jobs":  jobs.Snapshot(),
		"note":  "Control-plane jobs run on the Raft leader only; a follower shows the jobs it would run if it became leader.",
		"since": time.Now().UTC().Format(time.RFC3339),
	}
	// Data-plane background work, from its health endpoint.
	req, _ := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, dataPlaneBaseURL()+"/healthz", nil)
	if r, err := (&http.Client{Timeout: 4 * time.Second}).Do(req); err == nil {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		r.Body.Close()
		var h map[string]any
		if json.Unmarshal(body, &h) == nil {
			resp["dataplane"] = gin.H{
				"reachable":    true,
				"threat_intel": h["threat_intel"],
				"uptime_secs":  h["uptime_secs"],
				"version":      h["version"],
			}
		}
	} else {
		resp["dataplane"] = gin.H{"reachable": false, "error": err.Error()}
	}
	c.JSON(http.StatusOK, resp)
}

func handleRunJob(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *leader.Elector) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceSettings, rbac.ActionUpdate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	// Jobs live on the leader; requireLeader answers a follower with the
	// leader's address so the console can retry there.
	if !requireLeader(c, cl) {
		return
	}
	name := c.Param("name")
	ctx, cancel := context.WithTimeout(c.Request.Context(), 90*time.Second)
	defer cancel()
	st, err := jobs.RunNow(ctx, name)
	if store != nil {
		actor := claims.UserID
		diff, _ := json.Marshal(gin.H{"job": name, "ok": err == nil, "note": st.LastNote, "error": st.LastError, "duration_ms": st.LastMs})
		writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
			TenantID: claims.TenantID, ActorUserID: &actor, Action: "job.run", TargetKind: "job", Diff: diff,
		})
	}
	switch {
	case errors.Is(err, jobs.ErrUnknown):
		c.JSON(http.StatusNotFound, gin.H{"error": "unknown job: " + name})
	case errors.Is(err, jobs.ErrNotRunnable):
		c.JSON(http.StatusConflict, gin.H{"error": "this job cannot be run on demand", "job": st})
	case errors.Is(err, jobs.ErrBusy):
		c.JSON(http.StatusConflict, gin.H{"error": "job is already running", "job": st})
	case err != nil:
		c.JSON(http.StatusOK, gin.H{"ok": false, "job": st})
	default:
		c.JSON(http.StatusOK, gin.H{"ok": true, "job": st})
	}
}
