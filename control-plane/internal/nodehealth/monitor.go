// Package nodehealth watches the node registry and the Raft cluster, flips
// stale data-plane nodes to "down", and raises alerts on node/quorum
// transitions. It is node-global infrastructure (like the threat-intel
// aggregator): a single monitor per control-plane process, not tenant-scoped.
package nodehealth

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"go.uber.org/zap"

	"github.com/your-org/sentinel-waf/control-plane/internal/alerting"
	"github.com/your-org/sentinel-waf/control-plane/internal/cluster"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/notify"
)

const (
	// tickInterval is how often we re-evaluate node/cluster health.
	tickInterval = 10 * time.Second
	// defaultDownAfter is the staleness window before a data-plane node whose
	// heartbeats stopped is considered DOWN. Override via SENTINEL_NODE_DOWN_SECS.
	defaultDownAfter = 30 * time.Second
	// cpMissThreshold debounces control-plane peer flapping: the Raft peer
	// reachability window is ~200ms, so require this many consecutive misses
	// (~30s at tickInterval) before declaring a control-plane node down.
	cpMissThreshold = 3
)

// Monitor tracks node health. It is safe to construct with a nil cluster (Raft
// disabled / standalone) — the control-plane section is simply skipped.
type Monitor struct {
	store     *db.Store
	engine    *alerting.Engine
	cl        *cluster.Cluster
	log       *zap.Logger
	downAfter time.Duration
	done      chan struct{}

	// In-memory transition state (single monitor goroutine — no locking needed).
	dpPrev map[string]string // data-plane node id -> last effective status
	cpMiss map[uint64]int    // control-plane node id -> consecutive unreachable ticks
	cpPrev map[uint64]bool   // control-plane node id -> last-known reachable

	quorumAtRisk bool // last-known quorum state (for recovery edge)
}

// New builds a Monitor. downAfter comes from SENTINEL_NODE_DOWN_SECS (seconds;
// default 30s). The Monitor should only be started when store != nil.
func New(store *db.Store, engine *alerting.Engine, cl *cluster.Cluster, log *zap.Logger) *Monitor {
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
		cl:        cl,
		log:       log,
		downAfter: downAfter,
		done:      make(chan struct{}),
		dpPrev:    make(map[string]string),
		cpMiss:    make(map[uint64]int),
		cpPrev:    make(map[uint64]bool),
	}
}

// Start launches the health-check loop in its own goroutine.
func (m *Monitor) Start() {
	m.log.Info("node-health monitor started",
		zap.Duration("down_after", m.downAfter),
		zap.Bool("cluster", m.cl != nil))
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
			m.tick(ctx)
			cancel()
		}
	}
}

func (m *Monitor) tick(ctx context.Context) {
	m.checkDataPlane(ctx)
	m.checkControlPlane()
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

// checkControlPlane debounces Raft peer reachability and raises node/quorum
// alerts. No-op when Raft is disabled.
func (m *Monitor) checkControlPlane() {
	if m.cl == nil {
		return
	}
	st := m.cl.Status()

	for _, peer := range st.Peers {
		id := uint64(peer.NodeID)
		if peer.Reachable {
			// Recovery edge: raise only if we had previously declared it down.
			if m.cpMiss[id] >= cpMissThreshold {
				m.raiseCPRecovered(id)
			}
			m.cpMiss[id] = 0
			m.cpPrev[id] = true
			continue
		}
		m.cpMiss[id]++
		// Fire exactly once when we cross the debounce threshold.
		if m.cpMiss[id] == cpMissThreshold {
			m.raiseCPDown(id, peer.Addr)
		}
		m.cpPrev[id] = false
	}

	// Quorum: self + reachable peers vs the majority needed.
	total := len(st.Peers) + 1
	healthy := 1
	for _, peer := range st.Peers {
		if peer.Reachable {
			healthy++
		}
	}
	quorumSize := total/2 + 1
	if healthy < quorumSize {
		if !m.quorumAtRisk {
			m.raiseQuorumAtRisk(healthy, quorumSize, total)
		}
		m.quorumAtRisk = true
	} else {
		if m.quorumAtRisk {
			m.raiseQuorumRecovered(healthy, quorumSize, total)
		}
		m.quorumAtRisk = false
	}
}

func (m *Monitor) raiseCPDown(id uint64, addr string) {
	if m.store == nil {
		return
	}
	summary := fmt.Sprintf("Control-plane node %d is unreachable", id)
	m.engine.Raise(fmt.Sprintf("cp_node_down:%d", id), db.CreateAlertRequest{
		Severity: "critical",
		Kind:     "cp_node_down",
		Summary:  summary,
		Details:  jsonRaw(map[string]any{"node_id": id, "addr": addr}),
	}, notify.Alert{
		Severity: "critical",
		Kind:     "cp_node_down",
		Summary:  summary,
		Details:  map[string]interface{}{"node_id": id, "addr": addr},
	})
	m.log.Warn("control-plane node unreachable", zap.Uint64("node_id", id))
}

func (m *Monitor) raiseCPRecovered(id uint64) {
	if m.store == nil {
		return
	}
	summary := fmt.Sprintf("Control-plane node %d recovered", id)
	m.engine.Raise(fmt.Sprintf("cp_node_recovered:%d", id), db.CreateAlertRequest{
		Severity: "info",
		Kind:     "cp_node_recovered",
		Summary:  summary,
		Details:  jsonRaw(map[string]any{"node_id": id}),
	}, notify.Alert{
		Severity: "info",
		Kind:     "cp_node_recovered",
		Summary:  summary,
		Details:  map[string]interface{}{"node_id": id},
	})
	m.log.Info("control-plane node recovered", zap.Uint64("node_id", id))
}

func (m *Monitor) raiseQuorumAtRisk(healthy, quorumSize, total int) {
	if m.store == nil {
		return
	}
	summary := fmt.Sprintf("Control-plane quorum at risk: %d/%d healthy (need %d)", healthy, total, quorumSize)
	m.engine.Raise("quorum_at_risk", db.CreateAlertRequest{
		Severity: "critical",
		Kind:     "quorum_at_risk",
		Summary:  summary,
		Details:  jsonRaw(map[string]any{"healthy": healthy, "quorum_size": quorumSize, "total": total}),
	}, notify.Alert{
		Severity: "critical",
		Kind:     "quorum_at_risk",
		Summary:  summary,
		Details:  map[string]interface{}{"healthy": healthy, "quorum_size": quorumSize, "total": total},
	})
	m.log.Warn("control-plane quorum at risk", zap.Int("healthy", healthy), zap.Int("quorum_size", quorumSize))
}

func (m *Monitor) raiseQuorumRecovered(healthy, quorumSize, total int) {
	if m.store == nil {
		return
	}
	summary := fmt.Sprintf("Control-plane quorum restored: %d/%d healthy (need %d)", healthy, total, quorumSize)
	m.engine.Raise("quorum_recovered", db.CreateAlertRequest{
		Severity: "info",
		Kind:     "quorum_recovered",
		Summary:  summary,
		Details:  jsonRaw(map[string]any{"healthy": healthy, "quorum_size": quorumSize, "total": total}),
	}, notify.Alert{
		Severity: "info",
		Kind:     "quorum_recovered",
		Summary:  summary,
		Details:  map[string]interface{}{"healthy": healthy, "quorum_size": quorumSize, "total": total},
	})
	m.log.Info("control-plane quorum restored")
}

func jsonRaw(m map[string]any) json.RawMessage {
	b, _ := json.Marshal(m)
	return b
}
