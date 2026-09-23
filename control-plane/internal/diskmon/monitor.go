// Package diskmon watches the ClickHouse data disk and raises escalating
// disk_pressure alerts through the shared alerting engine (webhook/Slack/
// syslog/CEF) BEFORE the event store fills up.
//
// Why it matters: ClickHouse holds the searchable attack history (waf_events).
// If its disk fills, Threat Search and event ingest degrade — the WAF keeps
// blocking (Postgres/rules are unaffected), but the SOC loses visibility. A
// full disk must never be a silent surprise, so we poll system.disks and page
// the operator at a configurable threshold. It is node-global infrastructure,
// mirroring certmon.Monitor / nodehealth.Monitor, and runs only on the primary
// control-plane node (like the other singleton monitors).
package diskmon

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
	chreader "github.com/your-org/sentinel-waf/control-plane/internal/clickhouse"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/notify"
)

const (
	// defaultInterval — disk fills slowly relative to request rate, so a 5-min
	// poll is plenty. Override with SENTINEL_DISK_CHECK_SECS.
	defaultInterval = 5 * time.Minute
	// defaultThreshold — used-percent at which we start warning. Override with
	// SENTINEL_DISK_ALERT_PCT.
	defaultThreshold = 80.0
)

// Monitor polls ClickHouse disk usage and raises disk_pressure alerts.
type Monitor struct {
	engine    *alerting.Engine
	ch        *chreader.Client
	log       *zap.Logger
	interval  time.Duration
	threshold float64 // percent (0..100) at which "warning" begins
	done      chan struct{}
	job       *jobs.Job

	// lastSev tracks the last severity bucket alerted so each escalation level
	// (warning -> high -> critical) fires once, not every tick. Single goroutine
	// — no locking needed.
	lastSev string
}

// New builds a disk-pressure Monitor. Start only when the alerting engine and a
// ClickHouse reader are present (i.e. on the primary node).
func New(engine *alerting.Engine, ch *chreader.Client, log *zap.Logger) *Monitor {
	interval := defaultInterval
	if v := os.Getenv("SENTINEL_DISK_CHECK_SECS"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			interval = time.Duration(secs) * time.Second
		}
	}
	threshold := defaultThreshold
	if v := os.Getenv("SENTINEL_DISK_ALERT_PCT"); v != "" {
		if pct, err := strconv.ParseFloat(v, 64); err == nil && pct > 0 && pct < 100 {
			threshold = pct
		}
	}
	if log == nil {
		log = zap.NewNop()
	}
	return &Monitor{
		engine:    engine,
		ch:        ch,
		log:       log,
		interval:  interval,
		threshold: threshold,
		done:      make(chan struct{}),
	}
}

// Start launches the check loop in its own goroutine.
func (m *Monitor) Start() {
	m.job = jobs.Register("clickhouse.disk-pressure",
		"Read the event store's disk usage and alert when it crosses the threshold.",
		m.interval, func(ctx context.Context) (string, error) { return m.tickTracked(ctx) })
	m.log.Info("disk-pressure monitor started",
		zap.Duration("interval", m.interval),
		zap.Float64("threshold_pct", m.threshold))
	go m.loop()
}

// Stop halts the monitor.
func (m *Monitor) Stop() { close(m.done) }

func (m *Monitor) loop() {
	m.tickOnce()
	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		select {
		case <-m.done:
			return
		case <-t.C:
			m.tickOnce()
		}
	}
}

func (m *Monitor) tickOnce() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	m.job.Track(func() (string, error) { return m.tickTracked(ctx) })
}

// tickTracked runs one check and reports usage, for the jobs registry.
func (m *Monitor) tickTracked(ctx context.Context) (string, error) {
	usedFrac, _, _, err := m.ch.DiskUsage(ctx)
	if err != nil {
		return "", err
	}
	m.tick(ctx)
	return fmt.Sprintf("%.1f%% used", usedFrac*100), nil
}

func (m *Monitor) tick(ctx context.Context) {
	usedFrac, free, total, err := m.ch.DiskUsage(ctx)
	if err != nil {
		// ClickHouse may be down/starting — transient, don't alert on it.
		m.log.Warn("disk-pressure: reading ClickHouse disk usage failed", zap.Error(err))
		return
	}
	pct := usedFrac * 100
	sev := m.severityFor(pct)
	if sev == "" {
		// Healthy (below threshold). Clear prior state so a re-fill alerts afresh.
		if m.lastSev != "" {
			m.log.Info("disk pressure cleared", zap.Float64("used_pct", pct))
		}
		m.lastSev = ""
		return
	}
	if m.lastSev == sev {
		return // already alerted at this level
	}
	m.raiseDiskPressure(pct, free, total, sev)
	m.lastSev = sev
}

// severityFor maps used-percent to an alert severity bucket, or "" when healthy.
func (m *Monitor) severityFor(pct float64) string {
	switch {
	case pct >= 95:
		return "critical"
	case pct >= 90:
		return "high"
	case pct >= m.threshold:
		return "warning"
	default:
		return ""
	}
}

func (m *Monitor) raiseDiskPressure(pct float64, free, total int64, sev string) {
	summary := fmt.Sprintf("ClickHouse disk %.1f%% full (%s free of %s) — event store nearing capacity",
		pct, humanBytes(free), humanBytes(total))
	details := map[string]any{
		"used_pct":      round1(pct),
		"free_bytes":    free,
		"total_bytes":   total,
		"threshold_pct": m.threshold,
		"component":     "clickhouse",
	}
	// Severity is part of the throttle key so each escalation level fires once
	// as the disk fills, rather than being swallowed by the lower level's throttle.
	m.engine.RaiseOngoing("component", "clickhouse",
		fmt.Sprintf("disk_pressure:clickhouse:%s", sev),
		db.CreateAlertRequest{
			Severity: sev,
			Kind:     "disk_pressure",
			Summary:  summary,
			Details:  jsonRaw(details),
		},
		notify.Alert{
			Severity: sev,
			Kind:     "disk_pressure",
			Summary:  summary,
			Details:  details,
		},
	)
	m.log.Warn("clickhouse disk pressure",
		zap.Float64("used_pct", pct),
		zap.String("severity", sev))
}

func round1(f float64) float64 { return float64(int64(f*10+0.5)) / 10 }

func humanBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

func jsonRaw(m map[string]any) json.RawMessage {
	b, _ := json.Marshal(m)
	return b
}
