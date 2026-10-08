package nodehealth

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/notify"
)

// Conditions a data plane reports in its heartbeat that somebody has to hear
// about (2026-10-07 review #24). Each was visible only on that node's /healthz,
// which nothing polls, or in its log: a site refusing every request because its
// rules do not compile, blocked attacks that were never recorded, the event
// store gone (the console showed "awaiting events"), a certificate order
// failing every retry until the certificate lapsed, a node no longer taking
// config, a process or loop that keeps crashing.
//
// Ongoing conditions open one alert per node and close it themselves when the
// condition clears; counters (shed events, contained panics) raise one alert per
// increase and are closed by the engine's quiet-period auto-resolve.
const (
	KindSiteRefused    = "site_refused"
	KindClickHouseDown = "clickhouse_down"
	KindACMEFailing    = "acme_failing"
	KindConfigStale    = "config_stale"
	KindRestartLoop    = "restart_loop"
	KindEventsShed     = "events_shed"
	KindPanic          = "panic"
)

// ongoingKinds are the condition kinds this file opens and closes.
var ongoingKinds = []string{KindSiteRefused, KindClickHouseDown, KindACMEFailing, KindConfigStale, KindRestartLoop}

// How long a condition must hold before it alerts. A config reload refuses
// sites for the seconds its engines take to compile, ClickHouse connects in the
// background after a restart, and a node polls config on an interval: none of
// those is worth waking anyone for.
var holdFor = map[string]time.Duration{
	KindSiteRefused:    60 * time.Second,
	KindClickHouseDown: 2 * time.Minute,
	KindACMEFailing:    0, // the data plane only reports an order after it failed
	KindConfigStale:    0, // timed by its own evidence below: configStaleAfter
	KindRestartLoop:    0,
}

// configStaleAfter is how long config polls may fail, or a node trail the
// version the control plane serves, before it counts as not taking config.
const configStaleAfter = 5 * time.Minute

const (
	restartWindow    = 15 * time.Minute
	restartsForAlarm = 3
	// controlPlaneNode names the control plane's own ClickHouse reachability in
	// the alerts' "node" detail.
	controlPlaneNode = "control-plane"
)

// heartbeatMeta is the part of a data plane's heartbeat metadata read here.
type heartbeatMeta struct {
	UptimeSecs   int64    `json:"uptime_secs"`
	SitesRefused []string `json:"sites_refused"`
	HistoryShed  *uint64  `json:"history_shed"`
	ClickHouse   *struct {
		Configured    bool   `json:"configured"`
		Connected     bool   `json:"connected"`
		FailuresTotal uint64 `json:"failures_total"`
	} `json:"clickhouse"`
	ACMEFailing []struct {
		Domains  []string `json:"domains"`
		Failures int      `json:"failures"`
		Error    string   `json:"error"`
		Since    int64    `json:"since"`
	} `json:"acme_failing"`
	ConfigVersionApplied int64 `json:"config_version_applied"`
	ConfigSync           *struct {
		LastError     *string `json:"last_error"`
		FailingSince  *int64  `json:"failing_since"`
		RejectedSites []struct {
			ID    string `json:"id"`
			Error string `json:"error"`
		} `json:"rejected_sites"`
	} `json:"config_sync"`
	Panics *struct {
		Total      uint64  `json:"total"`
		Restarting *string `json:"restarting"`
	} `json:"panics"`
}

// finding is one condition as evaluated on one sweep.
type finding struct {
	Kind     string
	Severity string
	Summary  string
	Details  map[string]any
}

// nodeTrack is what one node's previous heartbeats leave behind: counters to
// diff against, process restarts seen, and since when each condition has held.
type nodeTrack struct {
	uptime      int64
	shed        uint64
	panics      uint64
	seen        bool
	restarts    []time.Time
	cfgLagSince time.Time
	holding     map[string]time.Time // kind → first sweep it was seen, continuously
	open        map[string]bool      // kinds this monitor has an alert open for
}

func newNodeTrack() *nodeTrack {
	return &nodeTrack{holding: map[string]time.Time{}, open: map[string]bool{}}
}

// evaluate reads one heartbeat. It returns the ongoing conditions that hold
// now (debounced), the one-off events since the previous heartbeat, and every
// condition present at all — one still inside its hold time is not cleared, or
// a leadership change would close and reopen an alert that never went away.
// Pure apart from the track it updates, so the rules are testable without a
// store.
func (t *nodeTrack) evaluate(node db.Node, md heartbeatMeta, currentCfg int64, now time.Time) (ongoing, events []finding, present map[string]bool) {
	label := node.ID
	if node.Hostname != "" && node.Hostname != node.ID {
		label = node.Hostname + " (" + node.ID + ")"
	}
	base := func(extra map[string]any) map[string]any {
		d := map[string]any{"node": node.ID, "hostname": node.Hostname}
		for k, v := range extra {
			d[k] = v
		}
		return d
	}
	var candidates []finding

	// Process restarts: uptime going backwards between two heartbeats.
	if t.seen && md.UptimeSecs < t.uptime {
		t.restarts = append(t.restarts, now)
	}
	kept := t.restarts[:0]
	for _, r := range t.restarts {
		if now.Sub(r) <= restartWindow {
			kept = append(kept, r)
		}
	}
	t.restarts = kept

	// Counters. A restart resets them, so a drop is a new baseline, not news.
	if md.HistoryShed != nil {
		if t.seen && *md.HistoryShed > t.shed {
			n := *md.HistoryShed - t.shed
			events = append(events, finding{
				Kind: KindEventsShed, Severity: "high",
				Summary: fmt.Sprintf("Node %s blocked %d requests it could not record: the event history is missing them", label, n),
				Details: base(map[string]any{"shed": n, "shed_total": *md.HistoryShed}),
			})
		}
		t.shed = *md.HistoryShed
	}
	if md.Panics != nil {
		if t.seen && md.Panics.Total > t.panics {
			n := md.Panics.Total - t.panics
			events = append(events, finding{
				Kind: KindPanic, Severity: "high",
				Summary: fmt.Sprintf("Node %s contained %d panic(s): a defect to report (its log has the location)", label, n),
				Details: base(map[string]any{"panics": n, "panics_total": md.Panics.Total}),
			})
		}
		t.panics = md.Panics.Total
	}
	t.uptime, t.seen = md.UptimeSecs, true

	if len(md.SitesRefused) > 0 {
		sites := append([]string(nil), md.SitesRefused...)
		sort.Strings(sites)
		candidates = append(candidates, finding{
			Kind: KindSiteRefused, Severity: "critical",
			Summary: fmt.Sprintf("Node %s is refusing every request to %s (503): the site's rules do not compile", label, strings.Join(sites, ", ")),
			Details: base(map[string]any{"sites": sites}),
		})
	}
	if ch := md.ClickHouse; ch != nil && ch.Configured && !ch.Connected {
		candidates = append(candidates, finding{
			Kind: KindClickHouseDown, Severity: "high",
			Summary: fmt.Sprintf("Node %s cannot reach the event store (ClickHouse): events are spooled to disk and Threat Search is behind", label),
			Details: base(map[string]any{"failures_total": ch.FailuresTotal}),
		})
	}
	var acme []string
	for _, f := range md.ACMEFailing {
		if f.Failures >= 2 {
			acme = append(acme, fmt.Sprintf("%s (%d attempts: %s)", strings.Join(f.Domains, ", "), f.Failures, f.Error))
		}
	}
	if len(acme) > 0 {
		sort.Strings(acme)
		candidates = append(candidates, finding{
			Kind: KindACMEFailing, Severity: "high",
			Summary: fmt.Sprintf("Node %s cannot obtain a certificate for %s", label, strings.Join(acme, "; ")),
			Details: base(map[string]any{"orders": acme}),
		})
	}
	var stale []string
	if cs := md.ConfigSync; cs != nil {
		if cs.FailingSince != nil && now.Sub(time.Unix(*cs.FailingSince, 0)) >= configStaleAfter {
			reason := "config polls are failing"
			if cs.LastError != nil && *cs.LastError != "" {
				reason += ": " + *cs.LastError
			}
			stale = append(stale, reason)
		}
		for _, r := range cs.RejectedSites {
			stale = append(stale, fmt.Sprintf("rejected the config of site %s (%s) and kept the previous one", r.ID, r.Error))
		}
	}
	// Behind the version the control plane serves, for longer than a poll or two.
	if currentCfg > 0 && md.ConfigVersionApplied < currentCfg {
		if t.cfgLagSince.IsZero() {
			t.cfgLagSince = now
		}
		if now.Sub(t.cfgLagSince) >= configStaleAfter {
			stale = append(stale, fmt.Sprintf("serving config version %d, the control plane is on %d", md.ConfigVersionApplied, currentCfg))
		}
	} else {
		t.cfgLagSince = time.Time{}
	}
	if len(stale) > 0 {
		candidates = append(candidates, finding{
			Kind: KindConfigStale, Severity: "high",
			Summary: fmt.Sprintf("Node %s is not taking configuration: %s", label, strings.Join(stale, "; ")),
			Details: base(map[string]any{"problems": stale, "applied": md.ConfigVersionApplied, "current": currentCfg}),
		})
	}
	var loops []string
	if len(t.restarts) >= restartsForAlarm {
		loops = append(loops, fmt.Sprintf("the process restarted %d times in %s", len(t.restarts), restartWindow))
	}
	if md.Panics != nil && md.Panics.Restarting != nil && *md.Panics.Restarting != "" {
		loops = append(loops, fmt.Sprintf("its %q loop keeps crashing and restarting", *md.Panics.Restarting))
	}
	if len(loops) > 0 {
		candidates = append(candidates, finding{
			Kind: KindRestartLoop, Severity: "critical",
			Summary: fmt.Sprintf("Node %s is in a restart loop: %s", label, strings.Join(loops, "; ")),
			Details: base(map[string]any{"restarts": len(t.restarts), "problems": loops}),
		})
	}

	// Debounce: a condition alerts once it has held for its hold time.
	present = map[string]bool{}
	for _, f := range candidates {
		present[f.Kind] = true
		since, ok := t.holding[f.Kind]
		if !ok {
			since = now
			t.holding[f.Kind] = now
		}
		if now.Sub(since) >= holdFor[f.Kind] {
			ongoing = append(ongoing, f)
		}
	}
	for k := range t.holding {
		if !present[k] {
			delete(t.holding, k)
		}
	}
	return ongoing, events, present
}

// checkConditions runs the rules over every node that is up, raises what
// holds, and closes what cleared. Called from tick.
func (m *Monitor) checkConditions(ctx context.Context, nodes []db.Node) {
	if m.engine == nil {
		return
	}
	var currentCfg int64
	if m.store != nil {
		if v, err := m.store.ConfigVersion(ctx); err == nil {
			currentCfg = v
		}
	}
	now := time.Now()
	clear := map[string][]string{} // kind → nodes whose condition cleared
	for _, node := range nodes {
		if node.Role != "" && node.Role != "data-plane" {
			continue
		}
		if now.Sub(node.LastSeen) > m.downAfter {
			continue // node_down covers it; its last report is not current
		}
		var md heartbeatMeta
		if len(node.Metadata) == 0 || json.Unmarshal(node.Metadata, &md) != nil {
			continue
		}
		t := m.tracks[node.ID]
		if t == nil {
			t = newNodeTrack()
			m.tracks[node.ID] = t
		}
		ongoing, events, present := t.evaluate(node, md, currentCfg, now)
		for _, f := range ongoing {
			t.open[f.Kind] = true
			m.raiseCondition(node.ID, f)
		}
		for _, k := range ongoingKinds {
			if !present[k] && (t.open[k] || m.reconcileDue) {
				clear[k] = append(clear[k], node.ID)
				delete(t.open, k)
			}
		}
		for _, f := range events {
			m.raiseEvent(node.ID, f)
		}
	}
	if m.chPing != nil {
		m.checkControlPlaneClickHouse(ctx, now, clear)
	}
	m.reconcileDue = false
	m.resolveCleared(ctx, clear)
}

// checkControlPlaneClickHouse is the same event-store condition seen from the
// control plane, which reads ClickHouse for every console search and report.
func (m *Monitor) checkControlPlaneClickHouse(ctx context.Context, now time.Time, clear map[string][]string) {
	pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	err := m.chPing(pctx)
	cancel()
	t := m.tracks[controlPlaneNode]
	if t == nil {
		t = newNodeTrack()
		m.tracks[controlPlaneNode] = t
	}
	if err == nil {
		delete(t.holding, KindClickHouseDown)
		// Cleared only on a successful ping: a failure still inside its hold
		// time leaves an alert from before a leadership change alone.
		if t.open[KindClickHouseDown] || m.reconcileDue {
			clear[KindClickHouseDown] = append(clear[KindClickHouseDown], controlPlaneNode)
			delete(t.open, KindClickHouseDown)
		}
		return
	}
	since, ok := t.holding[KindClickHouseDown]
	if !ok {
		t.holding[KindClickHouseDown] = now
		since = now
	}
	if now.Sub(since) < holdFor[KindClickHouseDown] {
		return
	}
	t.open[KindClickHouseDown] = true
	m.raiseCondition(controlPlaneNode, finding{
		Kind: KindClickHouseDown, Severity: "critical",
		Summary: "The control plane cannot reach the event store (ClickHouse): Threat Search, Logs and reports have no data, and disk-pressure checks are blind",
		Details: map[string]any{"node": controlPlaneNode, "error": err.Error()},
	})
}

func (m *Monitor) raiseCondition(nodeID string, f finding) {
	m.engine.RaiseOngoing("node", nodeID, f.Kind+":"+nodeID, db.CreateAlertRequest{
		Severity: f.Severity, Kind: f.Kind, Summary: f.Summary, Details: jsonRaw(f.Details),
	}, notify.Alert{
		Severity: f.Severity, Kind: f.Kind, Summary: f.Summary, Details: f.Details,
	})
}

func (m *Monitor) raiseEvent(nodeID string, f finding) {
	m.engine.Raise(f.Kind+":"+nodeID, db.CreateAlertRequest{
		Severity: f.Severity, Kind: f.Kind, Summary: f.Summary, Details: jsonRaw(f.Details),
	}, notify.Alert{
		Severity: f.Severity, Kind: f.Kind, Summary: f.Summary, Details: f.Details,
	})
	m.log.Warn("node condition", zap.String("kind", f.Kind), zap.String("node", nodeID), zap.String("summary", f.Summary))
}

func (m *Monitor) resolveCleared(ctx context.Context, clear map[string][]string) {
	if m.store == nil || m.tenantID == "" {
		return
	}
	for kind, nodes := range clear {
		n, err := m.store.ResolveAlertsByKind(ctx, m.tenantID, m.userID, []string{kind}, "node", nodes, "the condition cleared")
		if err != nil {
			m.log.Warn("node-health: resolving cleared conditions failed", zap.String("kind", kind), zap.Error(err))
			continue
		}
		if n > 0 {
			m.log.Info("node condition cleared", zap.String("kind", kind), zap.Strings("nodes", nodes))
		}
	}
}
