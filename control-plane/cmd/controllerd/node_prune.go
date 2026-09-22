package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"go.uber.org/zap"

	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/jobs"
	"github.com/your-org/sentinel-waf/control-plane/internal/leader"
)

// Stale nodes.
//
// A node reports itself under its hostname every 10 s (see handleNodeHeartbeat).
// Before compose.prod.yml pinned hostnames, an unpinned container's hostname
// was its container id, so every recreate — upgrade, rollback, `docker rm -f` —
// minted a NEW node and left the old one behind. Nothing removed it, and the
// health view counted it as "down" for the life of the installation. The first
// customer install showed exactly that: one live data plane, one ghost from the
// container removed on day one, and a banner saying the fleet was unhealthy.
//
// Two things fix it. classifyNode stops counting a node that has been silent
// for longer than the stale window — a day of silence at a 10-second heartbeat
// is history, not an incident — and the nodes.prune job deletes those rows, and
// the matching cluster_members rows, once an hour.

// nodeStaleAfter reads SENTINEL_NODE_STALE_HOURS (default 24). Anything at or
// below zero, or unparsable, falls back to the default: a zero window would make
// every node stale the moment its heartbeat was a second late.
func nodeStaleAfter() time.Duration {
	const def = 24 * time.Hour
	if v := os.Getenv("SENTINEL_NODE_STALE_HOURS"); v != "" {
		if h, err := strconv.Atoi(v); err == nil && h > 0 {
			return time.Duration(h) * time.Hour
		}
	}
	return def
}

// classifyNode turns a heartbeat's self-reported status and its age into the
// status the health view shows: healthy / degraded / down / stale.
//
//   - not seen for longer than staleAfter  -> "stale"  (excluded from counts)
//   - not seen for longer than downAfter   -> "down"
//   - otherwise the reported status, with anything unrecognised read as "down"
//     (a node that cannot say it is healthy is not assumed to be).
//
// Pure, so the health handler's counting can be tested without a database.
func classifyNode(reported string, sinceSeen, downAfter, staleAfter time.Duration) string {
	if staleAfter > 0 && sinceSeen > staleAfter {
		return "stale"
	}
	if sinceSeen > downAfter {
		return "down"
	}
	switch reported {
	case "healthy", "degraded":
		return reported
	default:
		return "down"
	}
}

// startNodePrune registers the nodes.prune job and runs it hourly. Returns the
// stop function. Safe with a nil elector (standalone control plane): only the
// nodes table is pruned then.
func startNodePrune(store *db.Store, cl *leader.Elector, log *zap.Logger) func() {
	done := make(chan struct{})
	run := func(ctx context.Context) (string, error) {
		window := nodeStaleAfter()
		nodesGone, err := store.PruneNodes(ctx, window)
		if err != nil {
			return "", err
		}
		var membersGone int64
		if cl != nil {
			membersGone, err = cl.PruneMembers(ctx, window)
			if err != nil {
				return fmt.Sprintf("pruned %d node(s); members: error", nodesGone), err
			}
		}
		return fmt.Sprintf("pruned %d node(s), %d cluster member(s) silent for over %s", nodesGone, membersGone, window), nil
	}
	job := jobs.Register("nodes.prune",
		"Forget data-plane nodes and control-plane members not heard from for SENTINEL_NODE_STALE_HOURS (default 24 h) — former container identities, not outages",
		time.Hour, run)
	tick := func() {
		job.Track(func() (string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			note, err := run(ctx)
			if err != nil {
				log.Warn("nodes.prune failed", zap.Error(err))
			} else if note != "" && note != "pruned 0 node(s), 0 cluster member(s) silent for over 24h0m0s" {
				log.Info("nodes.prune", zap.String("result", note))
			}
			return note, err
		})
	}
	go func() {
		// First pass shortly after boot, so an upgrade's own ghost rows (the
		// identities this very restart replaced) are gone within minutes, not
		// after the first hourly tick.
		select {
		case <-done:
			return
		case <-time.After(2 * time.Minute):
			tick()
		}
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				tick()
			}
		}
	}()
	return func() { close(done); jobs.Unregister("nodes.prune") }
}
