// Package nodehealth watches the node registry and the Raft cluster, flips
// stale data-plane nodes to "down", and raises alerts on node/quorum
// transitions. It is node-global infrastructure (like the threat-intel
// aggregator): a single monitor per control-plane process, not tenant-scoped.
package nodehealth

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/your-org/sentinel-waf/control-plane/internal/jobs"
	"os"
	"strconv"
	"time"

	"go.uber.org/zap"

	"github.com/your-org/sentinel-waf/control-plane/internal/alerting"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/notify"
)

const (
	// tickInterval is how often we re-evaluate node/cluster health.
	tickInterval = 10 * time.Second
	// defaultDownAfter is the staleness window before a data-plane node whose
	// heartbeats stopped is considered DOWN. Override via SENTINEL_NODE_DOWN_SECS.
	defaultDownAfter = 30 * time.Second
)

// Monitor tracks DATA-PLANE node health.
//
// It used to also track control-plane peer reachability and Raft quorum. Both
// concepts disappeared with the Raft implementation: leadership is now a Postgres
// advisory lock, so control-plane nodes hold no opinion about each other and there
// is no second quorum to be at risk. Control-plane liveness is observed by the
// orchestrator's readiness probes against /readyz, which is the layer that can
// actually act on it by removing the node from Service endpoints.
//
// The monitor no longer needs a leader handle either: main.go's supervisor starts
// this set only on the node holding leadership and stops it when leadership moves,
// so by construction exactly one instance runs.
type Monitor struct {
	store     *db.Store
	engine    *alerting.Engine
	log       *zap.Logger
	downAfter time.Duration
	done      chan struct{}
	job       *jobs.Job

	// In-memory transition state (single monitor goroutine — no locking needed).
	dpPrev map[string]string // data-plane node id -> last effective status
}

// New builds a Monitor. downAfter comes from SENTINEL_NODE_DOWN_SECS (seconds;
// default 30s). The Monitor should only be started when store != nil.
func New(store *db.Store, engine *alerting.Engine, log *zap.Logger) *Monitor {
	downAfter := defaultDownAfter
	if v := os.Getenv("SENTINEL_NODE_DOWN_SECS"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			downAfter = time.Duration(secs) * time.Second
		}
	}
	if log == nil {
		log = zap.NewNop()
	}
	return &Monitor{
		store:     store,
		engine:    engine,
		log:       log,
		downAfter: downAfter,
		done:      make(chan struct{}),
		dpPrev:    make(map[string]string),
	}
}

// Start launches the health-check loop in its own goroutine.
func (m *Monitor) Start() {
	m.job = jobs.Register("nodes.health-sweep",
		"Mark data-plane nodes that stopped heart-beating as down and alert on transitions.",
		tickInterval, func(ctx context.Context) (string, error) { return m.tickTracked(ctx) })
	m.log.Info("node-health monitor started",
		zap.Duration("down_after", m.downAfter))
	go m.loop()
}

// Stop halts the monitor.
func (m *Monitor) Stop() { close(m.done) }

func (m *Monitor) loop() {
	t := time.NewTicker(tickInterval)
	defer t.Stop()
	for {
		select {
		case <-m.done:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			m.job.Track(func() (string, error) { return m.tickTracked(ctx) })
			cancel()
		}
	}
}

func (m *Monitor) tick(ctx context.Context) {
	m.checkDataPlane(ctx)
}

// tickTracked runs one sweep and reports the node count, for the jobs registry.
func (m *Monitor) tickTracked(ctx context.Context) (string, error) {
	nodes, err := m.store.ListNodes(ctx)
	if err != nil {
		return "", err
	}
	m.tick(ctx)
	return fmt.Sprintf("%d nodes checked", len(nodes)), nil
}

// checkDataPlane flips stale nodes to "down" and raises down/recovered alerts on
// transitions.
func (m *Monitor) checkDataPlane(ctx context.Context) {
	nodes, err := m.store.ListNodes(ctx)
	if err != nil {
		m.log.Warn("node-health: list nodes failed", zap.Error(err))
		return
	}
	for _, node := range nodes {
		effective := node.Status
		if time.Since(node.LastSeen) > m.downAfter {
			effective = "down"
		}

		// Persist the derived down state so reads without the monitor still see it.
		if effective == "down" && node.Status != "down" {
			if err := m.store.UpdateNodeStatus(ctx, node.ID, "down"); err != nil {
				m.log.Warn("node-health: mark down failed", zap.String("node", node.ID), zap.Error(err))
			}
		}

		prev, seen := m.dpPrev[node.ID]
		switch {
		case effective == "down" && seen && prev != "down":
			// healthy/degraded -> down
			m.raiseDataPlaneDown(node)
		case effective != "down" && seen && prev == "down":
			// down -> healthy/degraded
			m.raiseDataPlaneRecovered(node)
		}
		m.dpPrev[node.ID] = effective
	}
}

func (m *Monitor) raiseDataPlaneDown(node db.Node) {
	if m.store == nil {
		return
	}
	summary := fmt.Sprintf("Data-plane node %s is DOWN", node.ID)
	m.engine.Raise("node_down:"+node.ID, db.CreateAlertRequest{
		Severity: "critical",
		Kind:     "node_down",
		Summary:  summary,
		Details:  jsonRaw(map[string]any{"node": node.ID, "hostname": node.Hostname, "role": node.Role}),
	}, notify.Alert{
		Severity: "critical",
		Kind:     "node_down",
		Summary:  summary,
		Details:  map[string]interface{}{"node": node.ID, "hostname": node.Hostname},
	})
	m.log.Warn("data-plane node down", zap.String("node", node.ID), zap.String("hostname", node.Hostname))
}

func (m *Monitor) raiseDataPlaneRecovered(node db.Node) {
	if m.store == nil {
		return
	}
	summary := "Data-plane node " + node.ID + " recovered"
	m.engine.Raise("node_recovered:"+node.ID, db.CreateAlertRequest{
		Severity: "info",
		Kind:     "node_recovered",
		Summary:  summary,
		Details:  jsonRaw(map[string]any{"node": node.ID, "hostname": node.Hostname, "role": node.Role}),
	}, notify.Alert{
		Severity: "info",
		Kind:     "node_recovered",
		Summary:  summary,
		Details:  map[string]interface{}{"node": node.ID, "hostname": node.Hostname},
	})
	m.log.Info("data-plane node recovered", zap.String("node", node.ID))
}

func jsonRaw(m map[string]any) json.RawMessage {
	b, _ := json.Marshal(m)
	return b
}
