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

	// Tenant identity the alerting engine writes as. Held so reconcileAlerts can
	// resolve the same rows the engine raised.
	tenantID string
	userID   string

	// In-memory transition state (single monitor goroutine — no locking needed).
	// NOTE: this is why reconcileAlerts exists — a restart empties this map, so
	// transitions alone cannot be trusted to close anything.
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
	tenantID, userID := engine.Identity()
	return &Monitor{
		store:     store,
		engine:    engine,
		log:       log,
		downAfter: downAfter,
		done:      make(chan struct{}),
		dpPrev:    make(map[string]string),
		tenantID:  tenantID,
		userID:    userID,
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

// orphanedInfraKinds are alert kinds that NOTHING in this build raises. They were
// emitted by an earlier control plane during the July HA work; the code that
// produced them is gone, so no transition can ever close them and every open row
// is by definition stale. The 13 July deployment still showed five
// "control-plane node N is unreachable" and three "quorum at risk" criticals on a
// cluster that had been 3/3 for weeks.
//
// If a future version reintroduces either kind, it MUST also reconcile it — add
// the recovery path there and drop the kind from this list, rather than leaving
// the sweep to close alerts that are once again real.
var orphanedInfraKinds = []string{"cp_node_down", "quorum_at_risk"}

// healthyNodeIDs returns the nodes considered up at `now`, by the same rule
// checkDataPlane applies. Split out from the sweep so the boundary is testable
// without a database: an off-by-one here would either resolve alerts for nodes
// that are still down, or never resolve them at all.
func healthyNodeIDs(nodes []db.Node, downAfter time.Duration, now time.Time) []string {
	healthy := make([]string, 0, len(nodes))
	for _, n := range nodes {
		if now.Sub(n.LastSeen) <= downAfter {
			healthy = append(healthy, n.ID)
		}
	}
	return healthy
}

// reconcileAlerts closes infrastructure alerts whose condition no longer holds.
//
// This is deliberately state-based, not transition-based. checkDataPlane compares
// against m.dpPrev, which lives in this process, so a control-plane restart wipes
// it: a node that was down before the restart and healthy after produces no
// transition at all and its node_down alert stays open forever. Reconciling on
// every sweep is idempotent and fixes rows already stranded.
func (m *Monitor) reconcileAlerts(ctx context.Context, healthy []string) (int64, error) {
	if m.store == nil || m.tenantID == "" {
		return 0, nil
	}
	var total int64

	if len(healthy) > 0 {
		n, err := m.store.ResolveAlertsByKind(ctx, m.tenantID, m.userID,
			[]string{"node_down"}, "node", healthy,
			"node is heart-beating again")
		if err != nil {
			return total, err
		}
		if n > 0 {
			m.log.Info("resolved stale node_down alerts",
				zap.Int64("count", n), zap.Strings("nodes", healthy))
		}
		total += n
	}

	n, err := m.store.ResolveAlertsByKind(ctx, m.tenantID, m.userID,
		orphanedInfraKinds, "", nil,
		"no monitor in this build raises this kind; row is stale")
	if err != nil {
		return total, err
	}
	if n > 0 {
		m.log.Info("resolved orphaned infrastructure alerts",
			zap.Int64("count", n), zap.Strings("kinds", orphanedInfraKinds))
	}
	return total + n, nil
}

// tickTracked runs one sweep and reports the node count, for the jobs registry.
func (m *Monitor) tickTracked(ctx context.Context) (string, error) {
	nodes, err := m.store.ListNodes(ctx)
	if err != nil {
		return "", err
	}
	m.tick(ctx)

	resolved, err := m.reconcileAlerts(ctx, healthyNodeIDs(nodes, m.downAfter, time.Now()))
	if err != nil {
		// Reconciliation is housekeeping: report it, but a failure here must not
		// mask the fact that the sweep itself ran.
		m.log.Warn("node-health: alert reconciliation failed", zap.Error(err))
		return fmt.Sprintf("%d nodes checked; reconcile failed", len(nodes)), nil
	}
	if resolved > 0 {
		return fmt.Sprintf("%d nodes checked, %d stale alerts resolved", len(nodes), resolved), nil
	}
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
	m.engine.RaiseOngoing("node", node.ID, "node_down:"+node.ID, db.CreateAlertRequest{
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
	// The recovery notice above is informational. Closing the node_down row is
	// what actually clears the console, and reconcileAlerts does it on this same
	// sweep, so a recovery seen as a transition and one only visible as current
	// state both converge on the same result.
	m.log.Info("data-plane node recovered", zap.String("node", node.ID))
}

func jsonRaw(m map[string]any) json.RawMessage {
	b, _ := json.Marshal(m)
	return b
}
