// Package alerting turns the live WAF event stream into actionable alerts.
// It subscribes to the log hub, applies threshold/anomaly conditions with
// throttling, persists alerts to the store, republishes them to the hub for
// live SSE delivery, and fans them out to configured notification channels.
package alerting

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/your-org/sentinel-waf/control-plane/internal/jobs"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/logs"
	"github.com/your-org/sentinel-waf/control-plane/internal/notify"
)

// Config tunes the alert-generation thresholds. Zero values fall back to
// sensible defaults in New.
type Config struct {
	SpikeWindow       time.Duration // sliding window for spike/offender counting
	SpikeThreshold    int           // blocks per site in window → attack_spike
	OffenderThreshold int           // blocks per IP in window → repeat_offender
	Throttle          time.Duration // min interval between identical alerts
	// AutoResolveAfter closes an event-driven alert that has not recurred for
	// this long. An ongoing condition is re-raised every Throttle, so it keeps a
	// fresh open row; a finished one stops piling up. 0 = default (30 min);
	// negative disables.
	AutoResolveAfter time.Duration
}

// Engine consumes hub events and raises alerts. It owns one tenant context
// (the proxy NDJSON stream is not tenant-tagged, so single-tenant by design;
// documented honestly).
type Engine struct {
	store      *db.Store
	hub        *logs.Hub
	dispatcher *notify.Dispatcher
	tenantID   string
	userID     string
	log        *zap.Logger
	cfg        Config

	mu         sync.Mutex
	lastRaise  map[string]time.Time
	ipWindow   map[string][]time.Time
	siteWindow map[string][]time.Time

	// dispatchCh decouples the (slow, network-bound) channel fan-out from the
	// single hub-consumer goroutine. Without it an unreachable webhook/syslog
	// channel would block the consumer for the per-channel timeout and make the
	// engine drop WAF events during an attack spike.
	dispatchCh chan notify.Alert

	// configSource, when set, is consulted once a minute so thresholds edited
	// on the Global Settings page take effect without a restart.
	configSource func() Config

	done chan struct{}
}

// SetConfigSource installs a function that returns the current desired Config
// (from the settings store). Zero fields fall back to defaults exactly as in
// New. Safe to call before Start.
func (e *Engine) SetConfigSource(fn func() Config) { e.configSource = fn }

// applyConfig swaps thresholds under the lock. Windows keep their history; the
// new thresholds apply to the next event.
func (e *Engine) applyConfig(cfg Config) {
	cfg = withDefaults(cfg)
	e.mu.Lock()
	changed := cfg != e.cfg
	e.cfg = cfg
	e.mu.Unlock()
	if changed {
		e.log.Info("alert engine config applied",
			zap.Int("spike_threshold", cfg.SpikeThreshold), zap.Int("offender_threshold", cfg.OffenderThreshold),
			zap.Duration("window", cfg.SpikeWindow), zap.Duration("throttle", cfg.Throttle),
			zap.Duration("auto_resolve", cfg.AutoResolveAfter))
	}
}

// Config returns the thresholds currently in force.
func (e *Engine) Config() Config { e.mu.Lock(); defer e.mu.Unlock(); return e.cfg }

func withDefaults(cfg Config) Config {
	if cfg.SpikeWindow == 0 {
		cfg.SpikeWindow = 60 * time.Second
	}
	if cfg.SpikeThreshold == 0 {
		cfg.SpikeThreshold = 20
	}
	if cfg.OffenderThreshold == 0 {
		cfg.OffenderThreshold = 15
	}
	if cfg.Throttle == 0 {
		cfg.Throttle = 5 * time.Minute
	}
	if cfg.AutoResolveAfter == 0 {
		cfg.AutoResolveAfter = 30 * time.Minute
	}
	return cfg
}

// New constructs an Engine with defaults applied.
func New(store *db.Store, hub *logs.Hub, tenantID, userID string, cfg Config, log *zap.Logger) *Engine {
	cfg = withDefaults(cfg)
	return &Engine{
		store:      store,
		hub:        hub,
		dispatcher: &notify.Dispatcher{},
		tenantID:   tenantID,
		userID:     userID,
		log:        log,
		cfg:        cfg,
		lastRaise:  make(map[string]time.Time),
		ipWindow:   make(map[string][]time.Time),
		siteWindow: make(map[string][]time.Time),
		dispatchCh: make(chan notify.Alert, 256),
		done:       make(chan struct{}),
	}
}

// Start subscribes to the hub and processes events until Stop is called.
func (e *Engine) Start() {
	if e.store == nil {
		e.log.Warn("alerting disabled — no database (channels + alert persistence require DB)")
		return
	}
	ch := e.hub.Subscribe()
	go e.loop(ch)
	go e.dispatchWorker()
	go e.janitor()
	go e.autoResolver()
	e.log.Info("alert engine started",
		zap.Int("spike_threshold", e.cfg.SpikeThreshold),
		zap.Int("offender_threshold", e.cfg.OffenderThreshold),
		zap.Duration("window", e.cfg.SpikeWindow))
}

// Stop halts the engine.
func (e *Engine) Stop() { close(e.done) }

func (e *Engine) loop(ch chan logs.Entry) {
	for {
		select {
		case <-e.done:
			return
		case ent, ok := <-ch:
			if !ok {
				return
			}
			if ent.Kind == "waf" {
				e.onWaf(ent.Data)
			}
		}
	}
}

// wafEvent is the subset of waf.log we evaluate.
type wafEvent struct {
	Action string `json:"action"`
	Rule   string `json:"rule"`
	IP     string `json:"ip"`
	Site   string `json:"site"`
	Tenant string `json:"tenant"`
	Sev    string `json:"sev"`
	Attack string `json:"attack"`
	Path   string `json:"path"`
}

func (e *Engine) onWaf(data json.RawMessage) {
	var ev wafEvent
	if json.Unmarshal(data, &ev) != nil {
		return
	}
	// Only real blocks drive alerts (DETECT/learning and PASS do not).
	if ev.Action != "BLOCK" && ev.Action != "BLOCKED" {
		return
	}
	now := time.Now()
	cfg := e.Config()
	sev := strings.ToLower(ev.Sev)
	// Attribute the alert to the owning tenant (the proxy now tags every event
	// with it); fall back to the default tenant for untagged events.
	effTenant := ev.Tenant
	if effTenant == "" {
		effTenant = e.tenantID
	}

	// Condition 1 — repeat offender: one IP blocked many times in the window.
	if ev.IP != "" {
		if n := e.bumpWindow(e.ipWindow, ev.IP, now); n >= cfg.OffenderThreshold {
			e.raiseForTenant(effTenant, "offender:"+ev.IP, db.CreateAlertRequest{
				Severity: "high",
				Kind:     "repeat_offender",
				Summary:  fmt.Sprintf("IP %s blocked %d times in %s", ev.IP, n, cfg.SpikeWindow),
				Details:  jsonObj(map[string]any{"ip": ev.IP, "count": n, "window": cfg.SpikeWindow.String(), "last_rule": ev.Rule}),
			}, notify.Alert{Severity: "high", Kind: "repeat_offender", SourceIP: ev.IP, Rule: ev.Rule, Site: ev.Site, Count: n})
		}
	}

	// Condition 2 — attack spike: a site sees a burst of blocks in the window.
	if ev.Site != "" && ev.Site != "-" {
		if n := e.bumpWindow(e.siteWindow, ev.Site, now); n >= cfg.SpikeThreshold {
			e.raiseForTenant(effTenant, "spike:"+ev.Site, db.CreateAlertRequest{
				Severity: "critical",
				Kind:     "attack_spike",
				Summary:  fmt.Sprintf("Attack spike on %s — %d blocks in %s", ev.Site, n, cfg.SpikeWindow),
				Details:  jsonObj(map[string]any{"site": ev.Site, "count": n, "window": cfg.SpikeWindow.String()}),
			}, notify.Alert{Severity: "critical", Kind: "attack_spike", Site: ev.Site, Count: n})
		}
	}

	// Condition 3 — a single critical/high block is itself notable.
	if sev == "critical" || sev == "high" {
		// Throttle by a full identity (severity + attack kind + site + IP), not
		// just rule+IP — otherwise blocks with no rule/IP collapse to one bucket
		// ("sev::") and distinct critical events coalesce into a single alert.
		throttleKey := fmt.Sprintf("sev:%s:%s:%s:%s", sev, attackKind(ev.Attack, ev.Rule), ev.Site, ev.IP)
		e.raiseForTenant(effTenant, throttleKey, db.CreateAlertRequest{
			Severity: sev,
			Kind:     attackKind(ev.Attack, ev.Rule),
			Summary:  fmt.Sprintf("%s blocked on %s (rule %s) from %s", capitalize(attackKind(ev.Attack, ev.Rule)), siteOr(ev.Site), ev.Rule, ev.IP),
			Details:  jsonObj(map[string]any{"rule": ev.Rule, "ip": ev.IP, "site": ev.Site, "path": ev.Path, "attack": ev.Attack}),
		}, notify.Alert{Severity: sev, Kind: attackKind(ev.Attack, ev.Rule), SourceIP: ev.IP, Rule: ev.Rule, Site: ev.Site})
	}
}

// bumpWindow appends now to the named sliding window, trims expired entries,
// and returns the current count.
func (e *Engine) bumpWindow(m map[string][]time.Time, key string, now time.Time) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	cutoff := now.Add(-e.cfg.SpikeWindow)
	w := append(m[key], now)
	i := sort.Search(len(w), func(i int) bool { return w[i].After(cutoff) })
	w = w[i:]
	m[key] = w
	return len(w)
}

// Raise is an exported wrapper over raise so out-of-package monitors (e.g. the
// node-health monitor) can surface alerts through the same persistence +
// throttling + channel fan-out path. Callers MUST set na.Severity and na.Kind.
// Identity returns the tenant and user the engine writes alerts as. The
// node-health monitor needs it to resolve rows the engine raised, and duplicating
// the values at both call sites is how they drift apart.
func (e *Engine) Identity() (tenantID, userID string) {
	if e == nil {
		return "", ""
	}
	return e.tenantID, e.userID
}

func (e *Engine) Raise(throttleKey string, req db.CreateAlertRequest, na notify.Alert) {
	e.raise(throttleKey, req, na)
}

// RaiseOngoing raises an alert for a CONDITION that persists — a full disk, a
// down node, an expiring certificate — identified by kind plus one details key
// (conditionKey=conditionValue, which must also be in req.Details).
//
// While an alert for that condition is open it is refreshed in place rather
// than duplicated: the monitor's periodic re-raise used to insert a new row
// each time, so a disk over its threshold for a day produced one alert per
// reading, and closing one brought a fresh one back at the next check — the
// bell count an operator had just cleared came straight back. Channels are
// notified again only when the refresh ESCALATES severity; a refresh at the same
// or lower severity updates the row and the live dashboard only.
func (e *Engine) RaiseOngoing(conditionKey, conditionValue, throttleKey string, req db.CreateAlertRequest, na notify.Alert) {
	tenantID := e.tenantID
	key := tenantID + "|" + throttleKey
	e.mu.Lock()
	if last, ok := e.lastRaise[key]; ok && time.Since(last) < e.cfg.Throttle {
		e.mu.Unlock()
		return
	}
	e.lastRaise[key] = time.Now()
	e.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	row, prev, err := e.store.RefreshOpenAlert(ctx, tenantID, e.userID, req.Kind,
		conditionKey, conditionValue, req.Severity, req.Summary, req.Details)
	if err != nil {
		e.log.Warn("alert refresh failed — raising a new one", zap.Error(err), zap.String("kind", req.Kind))
	}
	if row == nil {
		// Nothing open for this condition: a new alert, notified as usual. The
		// throttle slot is already taken, so go straight to the insert path.
		e.mu.Lock()
		delete(e.lastRaise, key)
		e.mu.Unlock()
		e.raiseForTenant(tenantID, throttleKey, req, na)
		return
	}
	e.publishToHub(row)
	if !escalates(prev, req.Severity) {
		return
	}
	na.ID, na.Summary, na.CreatedAt, na.Tenant = row.ID, req.Summary, row.CreatedAt, tenantID
	select {
	case e.dispatchCh <- na:
	default:
		e.log.Warn("alert dispatch queue full — dropping channel fan-out", zap.String("kind", req.Kind))
	}
	e.log.Info("ongoing alert escalated", zap.String("kind", req.Kind),
		zap.String("from", prev), zap.String("to", req.Severity))
}

// escalates reports whether next is strictly more severe than prev.
func escalates(prev, next string) bool {
	rank := map[string]int{"info": 0, "low": 1, "warning": 2, "medium": 2, "high": 3, "critical": 4}
	return rank[strings.ToLower(next)] > rank[strings.ToLower(prev)]
}

// raise persists+dispatches under the default tenant (used by the exported
// Raise wrapper and the node-health/cert monitors).
func (e *Engine) raise(throttleKey string, req db.CreateAlertRequest, na notify.Alert) {
	e.raiseForTenant(e.tenantID, throttleKey, req, na)
}

// raiseForTenant persists, republishes, and dispatches an alert attributed to a
// specific tenant, unless throttled. The throttle bucket is namespaced by
// tenant so one tenant's activity never suppresses another's.
func (e *Engine) raiseForTenant(tenantID, throttleKey string, req db.CreateAlertRequest, na notify.Alert) {
	if tenantID == "" {
		tenantID = e.tenantID
	}
	key := tenantID + "|" + throttleKey
	e.mu.Lock()
	if last, ok := e.lastRaise[key]; ok && time.Since(last) < e.cfg.Throttle {
		e.mu.Unlock()
		return
	}
	e.lastRaise[key] = time.Now()
	e.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	row, err := e.store.CreateAlert(ctx, tenantID, e.userID, req)
	if err != nil {
		e.log.Warn("alert persist failed", zap.Error(err), zap.String("kind", req.Kind))
		return
	}
	na.ID = row.ID
	na.Summary = req.Summary
	na.CreatedAt = row.CreatedAt
	na.Tenant = tenantID

	// Live SSE: surface the alert on the dashboard immediately.
	e.publishToHub(row)

	// Hand the channel fan-out to the dispatch worker so a slow/unreachable
	// channel can't stall this consumer goroutine. Non-blocking: if the queue is
	// saturated we drop the fan-out (the alert is already persisted + on the
	// dashboard) rather than block event processing.
	select {
	case e.dispatchCh <- na:
	default:
		e.log.Warn("alert dispatch queue full — dropping channel fan-out", zap.String("kind", req.Kind))
	}
	e.log.Info("alert raised", zap.String("kind", req.Kind), zap.String("severity", req.Severity), zap.String("summary", req.Summary))
}

// dispatchWorker drains the dispatch queue, fanning each alert out to the
// configured notification channels with its own timeout — off the hub-consumer
// goroutine so per-channel latency never backs up event processing.
func (e *Engine) dispatchWorker() {
	for {
		select {
		case <-e.done:
			return
		case na := <-e.dispatchCh:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			e.dispatch(ctx, na)
			cancel()
		}
	}
}

func (e *Engine) publishToHub(row *db.AlertRow) {
	payload, _ := json.Marshal(map[string]any{
		"id": row.ID, "severity": row.Severity, "kind": row.Kind,
		"summary": row.Summary, "state": row.State,
		"ts": row.CreatedAt.Format(time.RFC3339),
	})
	e.hub.PublishDirect(logs.Entry{Kind: "alert", Data: payload})
}

func (e *Engine) dispatch(ctx context.Context, na notify.Alert) {
	// Route to the owning tenant's channels (na.Tenant), not a fixed tenant.
	tenantID := na.Tenant
	if tenantID == "" {
		tenantID = e.tenantID
	}
	rows, err := e.store.ListChannels(ctx, tenantID, e.userID)
	if err != nil || len(rows) == 0 {
		return
	}
	var channels []notify.Channel
	for _, r := range rows {
		if !r.Enabled {
			continue
		}
		channels = append(channels, toNotifyChannel(r))
	}
	results := e.dispatcher.Dispatch(ctx, na, channels)
	for _, res := range results {
		if err := e.store.RecordChannelDelivery(ctx, tenantID, e.userID, res.ChannelID, res.Status()); err != nil {
			e.log.Debug("record delivery failed", zap.Error(err))
		}
		if !res.OK {
			e.log.Warn("alert delivery failed", zap.String("channel", res.Name), zap.String("err", res.Err))
		}
	}
}

// EventDrivenKinds are the alert kinds that describe a condition observed in a
// traffic window and are therefore safe to auto-resolve once it stops recurring.
// Operational kinds (node_down, cert_expiring, disk_pressure) are excluded: they
// are resolved by their own monitors when the underlying state recovers, and a
// quiet period does not mean the disk is no longer full.
var EventDrivenKinds = []string{
	"attack_spike", "repeat_offender",
	"sqli", "xss", "rce", "file_inclusion", "scanner", "attack",
	// Kinds an earlier engine version emitted; rows of these were still open
	// from June on the first deployment because nothing recognised them.
	"rate_limit", "path_traversal", "log4shell", "cmdinj",
	// Recovery notices are informational: once a node has been back for the
	// quiet window there is nothing left to act on.
	"node_recovered", "cp_node_recovered",
}

// autoResolver closes stale event-driven alerts once a minute. See
// db.Store.AutoResolveQuietAlerts for why this exists.
func (e *Engine) autoResolver() {
	job := jobs.Register("alerts.auto-resolve",
		"Close attack alerts that have not recurred within the quiet window; re-read Global Settings.",
		time.Minute, func(ctx context.Context) (string, error) { return e.autoResolveOnce(ctx) })
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-e.done:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			job.Track(func() (string, error) { return e.autoResolveOnce(ctx) })
			cancel()
		}
	}
}

// autoResolveOnce is one tick: apply console settings, then sweep.
func (e *Engine) autoResolveOnce(ctx context.Context) (string, error) {
	// Pick up console edits first, so a threshold change is live within a
	// minute of being saved.
	if e.configSource != nil {
		e.applyConfig(e.configSource())
	}
	quiet := e.Config().AutoResolveAfter
	if quiet < 0 {
		return "skipped — auto-resolve disabled", nil
	}
	n, err := e.store.AutoResolveQuietAlerts(ctx, e.tenantID, e.userID, EventDrivenKinds, quiet)
	if err != nil {
		e.log.Warn("alert auto-resolve failed", zap.Error(err))
		return "", err
	}
	if n > 0 {
		e.log.Info("auto-resolved quiet alerts", zap.Int64("count", n), zap.Duration("quiet", quiet))
	}
	return fmt.Sprintf("%d alerts resolved", n), nil
}

// janitor periodically drops stale throttle/window entries.
func (e *Engine) janitor() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-e.done:
			return
		case <-t.C:
			now := time.Now()
			e.mu.Lock()
			for k, v := range e.lastRaise {
				if now.Sub(v) > e.cfg.Throttle*2 {
					delete(e.lastRaise, k)
				}
			}
			cutoff := now.Add(-e.cfg.SpikeWindow)
			trim := func(m map[string][]time.Time) {
				for k, w := range m {
					i := sort.Search(len(w), func(i int) bool { return w[i].After(cutoff) })
					if i >= len(w) {
						delete(m, k)
					} else {
						m[k] = w[i:]
					}
				}
			}
			trim(e.ipWindow)
			trim(e.siteWindow)
			e.mu.Unlock()
		}
	}
}

// toNotifyChannel converts a stored channel row into a notify.Channel.
func toNotifyChannel(r db.ChannelRow) notify.Channel {
	var cfg notify.Config
	_ = json.Unmarshal(r.Config, &cfg)
	return notify.Channel{
		ID:          r.ID,
		Name:        r.Name,
		Type:        r.Type,
		MinSeverity: r.MinSeverity,
		Config:      cfg,
	}
}

func jsonObj(m map[string]any) json.RawMessage {
	b, _ := json.Marshal(m)
	return b
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func siteOr(s string) string {
	if s == "" || s == "-" {
		return "site"
	}
	return s
}

// attackKind derives a coarse alert kind from the attack message / rule ID.
func attackKind(attack, rule string) string {
	a := strings.ToLower(attack)
	switch {
	case strings.Contains(a, "sql"):
		return "sqli"
	case strings.Contains(a, "xss") || strings.Contains(a, "cross-site script"):
		return "xss"
	case strings.Contains(a, "rce") || strings.Contains(a, "command"):
		return "rce"
	case strings.Contains(a, "lfi") || strings.Contains(a, "rfi") || strings.Contains(a, "traversal") || strings.Contains(a, "file"):
		return "file_inclusion"
	case strings.Contains(a, "scanner") || strings.Contains(a, "bot"):
		return "scanner"
	}
	// Fall back to CRS rule-family prefix.
	switch {
	case strings.HasPrefix(rule, "942"):
		return "sqli"
	case strings.HasPrefix(rule, "941"):
		return "xss"
	case strings.HasPrefix(rule, "930"), strings.HasPrefix(rule, "931"):
		return "file_inclusion"
	case strings.HasPrefix(rule, "932"), strings.HasPrefix(rule, "933"), strings.HasPrefix(rule, "944"):
		return "rce"
	}
	return "attack"
}
