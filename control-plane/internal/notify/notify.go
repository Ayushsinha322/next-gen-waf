// Package notify delivers Sentinel WAF alerts to external SOC sinks:
// generic webhooks, Slack incoming webhooks, RFC 5424 syslog, and ArcSight CEF
// (over syslog transport). It is dependency-free (stdlib only) and decoupled
// from the database layer — callers translate their rows into notify.Channel
// and notify.Alert.
package notify

import (
	"context"
	"strings"
	"sync"
	"time"
)

// Severity rank for min-severity gating. Higher = more severe.
var severityRank = map[string]int{
	"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}

// SeverityAtLeast reports whether sev is at least as severe as min.
func SeverityAtLeast(sev, min string) bool {
	return severityRank[strings.ToLower(sev)] >= severityRank[strings.ToLower(min)]
}

// Alert is the payload delivered to a channel. It is a flat, sink-friendly
// view of an alert (no DB types).
type Alert struct {
	ID        string                 `json:"id"`
	Severity  string                 `json:"severity"`
	Kind      string                 `json:"kind"`
	Summary   string                 `json:"summary"`
	Site      string                 `json:"site,omitempty"`
	SourceIP  string                 `json:"source_ip,omitempty"`
	Rule      string                 `json:"rule,omitempty"`
	Count     int                    `json:"count,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
}

// Channel is a configured sink. Config is the type-specific settings blob.
type Channel struct {
	ID          string
	Name        string
	Type        string // webhook | slack | syslog | cef
	MinSeverity string
	Config      Config
}

// Config holds all possible per-channel settings (only the relevant subset is
// used per channel type). JSON-tagged so it can be unmarshaled straight from
// the stored channel config blob.
type Config struct {
	// webhook / slack
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Secret  string            `json:"secret"` // optional HMAC-SHA256 signing key (webhook)

	// syslog / cef
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // udp | tcp
	Facility int    `json:"facility"` // syslog facility (default 16 = local0)
	Tag      string `json:"tag"`      // app-name / syslog tag (default "sentinel-waf")
}

// Result is the outcome of one delivery attempt.
type Result struct {
	ChannelID string
	Name      string
	OK        bool
	Err       string
}

// Status returns "ok" or the error string, for persisting last_status.
func (r Result) Status() string {
	if r.OK {
		return "ok"
	}
	return r.Err
}

// Dispatcher fans an alert out to channels. The zero value is usable; Timeout
// defaults to 8s when zero.
type Dispatcher struct {
	Timeout time.Duration
}

// Dispatch sends the alert to every channel whose min-severity gate the alert
// passes, concurrently, and returns one Result per attempted channel. Channels
// that don't pass the severity gate are skipped (not in the result set).
func (d *Dispatcher) Dispatch(ctx context.Context, a Alert, channels []Channel) []Result {
	timeout := d.Timeout
	if timeout == 0 {
		timeout = 8 * time.Second
	}

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results []Result
	)
	for _, ch := range channels {
		if !SeverityAtLeast(a.Severity, ch.MinSeverity) {
			continue
		}
		wg.Add(1)
		go func(ch Channel) {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			err := send(cctx, ch, a)
			r := Result{ChannelID: ch.ID, Name: ch.Name, OK: err == nil}
			if err != nil {
				r.Err = err.Error()
			}
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		}(ch)
	}
	wg.Wait()
	return results
}

// Test sends the alert to a single channel and returns the outcome — used by
// the "Test channel" button.
func (d *Dispatcher) Test(ctx context.Context, ch Channel, a Alert) Result {
	timeout := d.Timeout
	if timeout == 0 {
		timeout = 8 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	err := send(cctx, ch, a)
	r := Result{ChannelID: ch.ID, Name: ch.Name, OK: err == nil}
	if err != nil {
		r.Err = err.Error()
	}
	return r
}

// send dispatches to the correct sender by channel type.
func send(ctx context.Context, ch Channel, a Alert) error {
	switch strings.ToLower(ch.Type) {
	case "webhook":
		return sendWebhook(ctx, ch, a)
	case "slack":
		return sendSlack(ctx, ch, a)
	case "syslog":
		return sendSyslog(ctx, ch, a)
	case "cef":
		return sendCEF(ctx, ch, a)
	default:
		return errUnknownType(ch.Type)
	}
}
