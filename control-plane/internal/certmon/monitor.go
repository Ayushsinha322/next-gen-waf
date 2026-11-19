// Package certmon watches TLS certificate expiry and raises alerts before a
// cert lapses. Certificates are not persisted in the control plane — they live
// in the data-plane proxy's cert store — so the monitor polls the data plane's
// internal cert-enumeration endpoint on a slow ticker and raises escalating
// cert_expiring alerts through the shared alerting engine (webhook/slack/
// syslog/CEF). It is node-global infrastructure, mirroring nodehealth.Monitor.
//
// This closes a real gap: the data plane auto-renews ACME certs but never
// alerts, and does nothing at all for manually-uploaded certs — which today
// expire silently with no notification.
package certmon

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/your-org/sentinel-waf/control-plane/internal/jobs"
	"net/http"
	"os"
	"strconv"
	"time"

	"go.uber.org/zap"

	"github.com/your-org/sentinel-waf/control-plane/internal/alerting"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/notify"
	"github.com/your-org/sentinel-waf/control-plane/internal/safego"
)

const (
	// defaultInterval is how often the cert inventory is re-checked. Cert expiry
	// changes on the scale of days, so a slow poll is plenty; override with
	// SENTINEL_CERT_CHECK_SECS.
	defaultInterval = 6 * time.Hour
	// warnDays is the horizon at which we start alerting.
	warnDays = 30
)

// Monitor polls the data-plane cert inventory and raises cert_expiring alerts.
type Monitor struct {
	engine         *alerting.Engine
	log            *zap.Logger
	client         *http.Client
	baseURL        string // data-plane base URL (e.g. http://localhost:9080)
	internalSecret string // X-Sentinel-Internal shared secret ("" = co-located dev)
	interval       time.Duration
	done           chan struct{}
	job            *jobs.Job

	// lastSev tracks the last severity bucket alerted per domain so each
	// escalation level (medium -> high -> critical) fires once, not every tick.
	// Single monitor goroutine — no locking needed.
	lastSev map[string]string

	// internal reads the deployment's own certificates (see internal_certs.go).
	// nil = site certificates only.
	internal func(ctx context.Context) []certEntry
	// raise delivers one alert; a field so tests can observe it without an
	// alerting engine. Defaults to raiseCertExpiring.
	raise func(c certEntry, days int64, sev string)
}

// SetInternalCerts adds the deployment's own certificates — CA files and the
// certificates the datastores present — to what is checked on every tick. Call
// before Start.
func (m *Monitor) SetInternalCerts(read func(ctx context.Context) []certEntry) {
	m.internal = read
}

// New builds a cert-expiry Monitor. baseURL + internalSecret are passed in
// (rather than read here) because the data-plane URL/secret helpers live in
// package main. Only start when the alerting engine (and its store) is present.
func New(engine *alerting.Engine, baseURL, internalSecret string, log *zap.Logger) *Monitor {
	interval := defaultInterval
	if v := os.Getenv("SENTINEL_CERT_CHECK_SECS"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			interval = time.Duration(secs) * time.Second
		}
	}
	if log == nil {
		log = zap.NewNop()
	}
	return &Monitor{
		engine:         engine,
		log:            log,
		client:         &http.Client{Timeout: 15 * time.Second},
		baseURL:        baseURL,
		internalSecret: internalSecret,
		interval:       interval,
		done:           make(chan struct{}),
		lastSev:        make(map[string]string),
	}
}

// Start launches the check loop in its own goroutine.
func (m *Monitor) Start() {
	m.job = jobs.Register("certificates.expiry-check",
		"Read every certificate the data plane holds and alert on those expiring soon.",
		m.interval, func(ctx context.Context) (string, error) { return m.tickTracked(ctx) })
	m.log.Info("cert-expiry monitor started",
		zap.Duration("interval", m.interval),
		zap.String("data_plane", m.baseURL))
	safego.Loop(m.log, "certmon.monitor", m.loop)
}

// Stop halts the monitor.
func (m *Monitor) Stop() { close(m.done) }

func (m *Monitor) loop() {
	// Immediate first check at boot, then on the ticker (threat-intel style).
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
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	m.job.Track(func() (string, error) { return m.tickTracked(ctx) })
}

// tickTracked runs one check and reports what it saw, for the jobs registry.
func (m *Monitor) tickTracked(ctx context.Context) (string, error) {
	site, internal, err := m.tick(ctx)
	note := fmt.Sprintf("%d site and %d internal certificates checked", site, internal)
	if err != nil {
		// The internal ones were still checked; say so next to the failure.
		return note, fmt.Errorf("data plane inventory unavailable (%s): %w", note, err)
	}
	return note, nil
}

// certEntry is the subset of the data plane's CertMeta JSON we need.
type certEntry struct {
	Domain    string `json:"domain"`
	Name      string `json:"name"`
	ExpiresAt int64  `json:"expires_at"` // unix seconds; 0 = unknown
}

// tick checks the site certificates the data plane holds and the deployment's
// own. The two are independent: an unreachable data plane used to end the tick,
// which would now also skip the certificates that do not depend on it.
func (m *Monitor) tick(ctx context.Context) (site, internal int, err error) {
	certs, err := m.fetchCerts(ctx)
	if err != nil {
		// Data plane may be down/starting — transient, don't alert on it.
		m.log.Warn("cert-expiry: fetching cert inventory failed", zap.Error(err))
		certs = nil
	}
	site = len(certs)
	if m.internal != nil {
		own := m.internal(ctx)
		internal = len(own)
		certs = append(certs, own...)
	}
	m.evaluate(certs, time.Now())
	return site, internal, err
}

// evaluate raises an alert for each certificate that has entered a new
// severity bucket since the last tick.
func (m *Monitor) evaluate(certs []certEntry, at time.Time) {
	raise := m.raise
	if raise == nil {
		raise = m.raiseCertExpiring
	}
	now := at.Unix()
	for _, c := range certs {
		if c.ExpiresAt <= 0 {
			continue // unknown expiry (e.g. self-signed) — never alert
		}
		days := (c.ExpiresAt - now) / 86400
		sev := severityFor(days)
		if sev == "" {
			// Healthy (>warnDays). Clear prior state so a re-issued cert that
			// later approaches expiry alerts afresh.
			delete(m.lastSev, c.Domain)
			continue
		}
		if m.lastSev[c.Domain] == sev {
			continue // already alerted at this level
		}
		raise(c, days, sev)
		m.lastSev[c.Domain] = sev
	}
}

func (m *Monitor) fetchCerts(ctx context.Context) ([]certEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.baseURL+"/api/v1/internal/certs", nil)
	if err != nil {
		return nil, err
	}
	if m.internalSecret != "" {
		req.Header.Set("X-Sentinel-Internal", m.internalSecret)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("data plane returned HTTP %d", resp.StatusCode)
	}
	var certs []certEntry
	if err := json.NewDecoder(resp.Body).Decode(&certs); err != nil {
		return nil, fmt.Errorf("decoding cert inventory: %w", err)
	}
	return certs, nil
}

// severityFor maps days-until-expiry to an alert severity bucket, or "" when
// the cert is healthy (beyond the warn horizon). Already-expired (days <= 0)
// falls into critical.
func severityFor(days int64) string {
	switch {
	case days <= 7:
		return "critical"
	case days <= 14:
		return "high"
	case days <= warnDays:
		return "medium"
	default:
		return ""
	}
}

func (m *Monitor) raiseCertExpiring(c certEntry, days int64, sev string) {
	var summary string
	if days <= 0 {
		summary = fmt.Sprintf("Certificate for %s has EXPIRED", c.Domain)
	} else {
		summary = fmt.Sprintf("Certificate for %s expires in %d day(s)", c.Domain, days)
	}
	// Severity is part of the throttle key so each escalation level fires once
	// as days -> 0, rather than being swallowed by the down-level's throttle.
	m.engine.RaiseOngoing("domain", c.Domain,
		fmt.Sprintf("cert_expiring:%s:%s", c.Domain, sev),
		db.CreateAlertRequest{
			Severity: sev,
			Kind:     "cert_expiring",
			Summary:  summary,
			Details:  jsonRaw(map[string]any{"domain": c.Domain, "name": c.Name, "days_remaining": days, "expires_at": c.ExpiresAt}),
		},
		notify.Alert{
			Severity: sev,
			Kind:     "cert_expiring",
			Summary:  summary,
			Site:     c.Domain,
			Details:  map[string]interface{}{"domain": c.Domain, "days_remaining": days},
		},
	)
	m.log.Warn("certificate expiring",
		zap.String("domain", c.Domain),
		zap.Int64("days_remaining", days),
		zap.String("severity", sev))
}

func jsonRaw(m map[string]any) json.RawMessage {
	b, _ := json.Marshal(m)
	return b
}
