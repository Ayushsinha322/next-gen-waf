// Package reports builds and delivers scheduled security reports.
//
// A report is one tenant's (optionally one site's) view of a period: events by
// decision, top rules, top sources, top countries, attack categories, a
// per-day trend and the learning-mode false-positive candidates — everything
// already in ClickHouse, rendered as HTML (for a mailbox) or CSV (for a
// spreadsheet) and pushed to a notification channel or e-mail on a daily or
// weekly schedule. PDF is deliberately not offered: HTML prints to PDF from any
// browser and a PDF renderer would be the largest dependency in the binary.
package reports

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/your-org/sentinel-waf/control-plane/internal/clickhouse"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/jobs"
	"github.com/your-org/sentinel-waf/control-plane/internal/mailer"
	"github.com/your-org/sentinel-waf/control-plane/internal/notify"
)

// ---------------------------------------------------------------------------
// Scheduling
// ---------------------------------------------------------------------------

// ScheduledAt returns the most recent scheduled fire time at or before now.
func ScheduledAt(s db.ReportScheduleRow, now time.Time) time.Time {
	now = now.UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), s.HourUTC, 0, 0, 0, time.UTC)
	if s.Cadence == "daily" {
		if today.After(now) {
			today = today.AddDate(0, 0, -1)
		}
		return today
	}
	// weekly: walk back to the configured weekday
	for int(today.Weekday()) != s.DayOfWeek || today.After(now) {
		today = today.AddDate(0, 0, -1)
	}
	return today
}

// Period is the window a report fired at `at` covers: the full previous day or week.
func Period(s db.ReportScheduleRow, at time.Time) (from, to time.Time) {
	if s.Cadence == "daily" {
		return at.AddDate(0, 0, -1), at
	}
	return at.AddDate(0, 0, -7), at
}

// IsDue: enabled, the scheduled time has passed, and nothing ran since it.
func IsDue(s db.ReportScheduleRow, now time.Time) bool {
	if !s.Enabled {
		return false
	}
	at := ScheduledAt(s, now)
	return s.LastRunAt == nil || s.LastRunAt.Before(at)
}

// ---------------------------------------------------------------------------
// Building
// ---------------------------------------------------------------------------

type Report struct {
	Title     string                    `json:"title"`
	Site      string                    `json:"site"` // "" = all sites
	From      time.Time                 `json:"from"`
	To        time.Time                 `json:"to"`
	Generated time.Time                 `json:"generated"`
	Summary   *clickhouse.ReportSummary `json:"summary"`
	// Learning-mode rules that would have blocked: the false-positive candidates.
	Learning []clickhouse.LearningStat `json:"learning"`
}

// Build gathers the report from the event store.
func Build(ctx context.Context, ch *clickhouse.Client, tenant, site string, from, to time.Time) (*Report, error) {
	if ch == nil || !ch.Enabled() {
		return nil, fmt.Errorf("the event store (ClickHouse) is not configured — reports read from it")
	}
	sum, err := ch.ReportSummary(ctx, tenant, site, from.Unix(), to.Unix())
	if err != nil {
		return nil, fmt.Errorf("event store query: %w", err)
	}
	learning, err := ch.LearningStats(ctx, tenant, site, from.Unix(), to.Unix(), 3)
	if err != nil {
		learning = nil // the summary is still worth sending
	}
	if len(learning) > 15 {
		learning = learning[:15]
	}
	scope := "all sites"
	if site != "" {
		scope = site
	}
	return &Report{
		Title: fmt.Sprintf("WAF security report — %s — %s to %s", scope, from.UTC().Format("2006-01-02"), to.UTC().Format("2006-01-02")),
		Site:  site, From: from.UTC(), To: to.UTC(), Generated: time.Now().UTC(), Summary: sum, Learning: learning,
	}, nil
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

// CSV: one file, sectioned, so it opens in a spreadsheet without parsing.
func (r *Report) CSV() []byte {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	s := r.Summary
	row := func(vals ...any) {
		out := make([]string, len(vals))
		for i, v := range vals {
			out[i] = fmt.Sprint(v)
		}
		_ = w.Write(out)
	}
	row("report", r.Title)
	row("period_from", r.From.Format(time.RFC3339), "period_to", r.To.Format(time.RFC3339), "generated", r.Generated.Format(time.RFC3339))
	row()
	row("section", "totals")
	row("events", s.Total, "blocked", s.Blocked, "detected_learning", s.Detected, "distinct_sources", s.Sources)
	row()
	row("section", "by_day")
	row("day", "events", "blocked")
	for _, d := range s.ByDay {
		row(d.Day, d.Total, d.Blocked)
	}
	row()
	row("section", "by_action")
	row("action", "events")
	for _, f := range s.ByAction {
		row(f.Key, f.Count)
	}
	row()
	row("section", "by_severity")
	row("severity", "events")
	for _, f := range s.BySeverity {
		row(f.Key, f.Count)
	}
	row()
	row("section", "top_attack_categories")
	row("attack", "events")
	for _, f := range s.ByAttack {
		row(f.Key, f.Count)
	}
	row()
	row("section", "top_rules")
	row("rule_id", "events", "blocked")
	for _, h := range s.TopRules {
		row(h.RuleID, h.Count, h.Blocked)
	}
	row()
	row("section", "top_sources")
	row("ip", "country", "events", "blocked", "last_seen")
	for _, a := range s.TopSources {
		row(a.IP, a.Country, a.Requests, a.Blocked, time.Unix(a.LastSeen, 0).UTC().Format(time.RFC3339))
	}
	row()
	row("section", "top_countries")
	row("country", "events")
	for _, f := range s.ByCountry {
		row(f.Key, f.Count)
	}
	row()
	row("section", "false_positive_candidates_learning_mode")
	row("rule_id", "category", "severity", "would_have_blocked", "message", "sample")
	for _, l := range r.Learning {
		sample := ""
		if len(l.Samples) > 0 {
			sample = l.Samples[0]
		}
		row(l.RuleID, l.Category, l.Severity, l.Count, l.Message, sample)
	}
	w.Flush()
	return buf.Bytes()
}

// HTML: self-contained, no external assets, prints to PDF cleanly.
func (r *Report) HTML() []byte {
	s := r.Summary
	e := html.EscapeString
	var b strings.Builder
	b.WriteString(`<!doctype html><html><head><meta charset="utf-8"><title>` + e(r.Title) + `</title>
<style>body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1a2233;margin:32px;max-width:900px}
h1{font-size:20px;margin:0 0 4px}h2{font-size:14px;text-transform:uppercase;letter-spacing:.06em;color:#4b5a70;margin:28px 0 8px}
.meta{color:#4b5a70;font-size:13px}.kpis{display:flex;gap:14px;margin:18px 0;flex-wrap:wrap}
.kpi{border:1px solid #d9dfe8;border-radius:8px;padding:12px 16px;min-width:140px}.kpi b{display:block;font-size:22px}.kpi span{font-size:12px;color:#4b5a70}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #e6eaf0}th{color:#4b5a70;font-weight:600}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}.foot{margin-top:32px;font-size:12px;color:#6b7a90}</style></head><body>`)
	fmt.Fprintf(&b, `<h1>%s</h1><div class="meta">Period %s → %s (UTC) · generated %s</div>`,
		e(r.Title), r.From.Format("2006-01-02 15:04"), r.To.Format("2006-01-02 15:04"), r.Generated.Format("2006-01-02 15:04 UTC"))
	fmt.Fprintf(&b, `<div class="kpis"><div class="kpi"><b>%d</b><span>WAF events</span></div><div class="kpi"><b>%d</b><span>blocked</span></div>`+
		`<div class="kpi"><b>%d</b><span>detected (learning)</span></div><div class="kpi"><b>%d</b><span>distinct sources</span></div></div>`,
		s.Total, s.Blocked, s.Detected, s.Sources)
	table := func(title string, heads []string, rows [][]string, numeric map[int]bool) {
		b.WriteString("<h2>" + e(title) + "</h2>")
		if len(rows) == 0 {
			b.WriteString(`<div class="meta">none in this period</div>`)
			return
		}
		b.WriteString("<table><tr>")
		for i, h := range heads {
			cls := ""
			if numeric[i] {
				cls = ` class="n"`
			}
			b.WriteString("<th" + cls + ">" + e(h) + "</th>")
		}
		b.WriteString("</tr>")
		for _, row := range rows {
			b.WriteString("<tr>")
			for i, c := range row {
				cls := ""
				if numeric[i] {
					cls = ` class="n"`
				}
				b.WriteString("<td" + cls + ">" + e(c) + "</td>")
			}
			b.WriteString("</tr>")
		}
		b.WriteString("</table>")
	}
	var rows [][]string
	for _, d := range s.ByDay {
		rows = append(rows, []string{d.Day, fmt.Sprint(d.Total), fmt.Sprint(d.Blocked)})
	}
	table("Events per day", []string{"Day", "Events", "Blocked"}, rows, map[int]bool{1: true, 2: true})
	rows = nil
	for _, f := range s.ByAttack {
		rows = append(rows, []string{f.Key, fmt.Sprint(f.Count)})
	}
	table("Attack categories", []string{"Category", "Events"}, rows, map[int]bool{1: true})
	rows = nil
	for _, h := range s.TopRules {
		rows = append(rows, []string{h.RuleID, fmt.Sprint(h.Count), fmt.Sprint(h.Blocked)})
	}
	table("Top rules", []string{"Rule", "Events", "Blocked"}, rows, map[int]bool{1: true, 2: true})
	rows = nil
	for _, a := range s.TopSources {
		rows = append(rows, []string{a.IP, a.Country, fmt.Sprint(a.Requests), fmt.Sprint(a.Blocked), time.Unix(a.LastSeen, 0).UTC().Format("2006-01-02 15:04")})
	}
	table("Top sources", []string{"IP", "Country", "Events", "Blocked", "Last seen (UTC)"}, rows, map[int]bool{2: true, 3: true})
	rows = nil
	for _, f := range s.ByCountry {
		rows = append(rows, []string{f.Key, fmt.Sprint(f.Count)})
	}
	table("Top countries", []string{"Country", "Events"}, rows, map[int]bool{1: true})
	rows = nil
	for _, l := range r.Learning {
		sample := ""
		if len(l.Samples) > 0 {
			sample = l.Samples[0]
		}
		rows = append(rows, []string{l.RuleID, l.Category, l.Severity, fmt.Sprint(l.Count), l.Message, sample})
	}
	table("False-positive candidates (learning mode — would have blocked)", []string{"Rule", "Category", "Severity", "Count", "Message", "Sample"}, rows, map[int]bool{3: true})
	b.WriteString(`<div class="foot">Generated by the WAF control plane from the event store. Blocked = request denied; detected = a site in learning mode recorded what it would have blocked. Country data: IP Geolocation by DB-IP.</div></body></html>`)
	return []byte(b.String())
}

// Text: the short form for Slack/webhook channels.
func (r *Report) Text() string {
	s := r.Summary
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n%d WAF events · %d blocked · %d detected in learning mode · %d distinct sources\n",
		r.Title, s.Total, s.Blocked, s.Detected, s.Sources)
	if len(s.TopRules) > 0 {
		b.WriteString("Top rules: ")
		for i, h := range s.TopRules {
			if i == 5 {
				break
			}
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%s (%d)", h.RuleID, h.Count)
		}
		b.WriteString("\n")
	}
	if len(s.TopSources) > 0 {
		b.WriteString("Top sources: ")
		for i, a := range s.TopSources {
			if i == 5 {
				break
			}
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%s (%d)", a.IP, a.Requests)
		}
		b.WriteString("\n")
	}
	if n := len(r.Learning); n > 0 {
		fmt.Fprintf(&b, "%d false-positive candidate rule(s) from learning mode.\n", n)
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Delivery
// ---------------------------------------------------------------------------

// Deliverer runs due schedules (leader only) and delivers on demand.
type Deliverer struct {
	store  *db.Store
	ch     *clickhouse.Client
	mail   func() *mailer.Mailer
	notify *notify.Dispatcher
	log    *zap.Logger
	job    *jobs.Job
	done   chan struct{}
	once   sync.Once
}

func NewDeliverer(store *db.Store, ch *clickhouse.Client, mail func() *mailer.Mailer, log *zap.Logger) *Deliverer {
	d := &Deliverer{store: store, ch: ch, mail: mail, notify: &notify.Dispatcher{}, log: log, done: make(chan struct{})}
	d.job = jobs.Register("reports.dispatch",
		"Send every scheduled security report whose time has come (daily/weekly per site, to a channel or mailbox). Run now = deliver everything that is due.",
		time.Hour, func(ctx context.Context) (string, error) { return d.tickOnce(ctx) })
	return d
}

// Start: first pass two minutes after boot (let ClickHouse come up), then hourly.
func (d *Deliverer) Start() {
	go func() {
		select {
		case <-d.done:
			return
		case <-time.After(2 * time.Minute):
		}
		d.track()
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-d.done:
				return
			case <-t.C:
				d.track()
			}
		}
	}()
}

func (d *Deliverer) Stop() { d.once.Do(func() { close(d.done) }) }

func (d *Deliverer) track() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	d.job.Track(func() (string, error) { return d.tickOnce(ctx) })
}

func (d *Deliverer) tickOnce(ctx context.Context) (string, error) {
	if d.store == nil {
		return "skipped — no database", nil
	}
	list, err := d.store.ListEnabledReportSchedulesGlobal(ctx)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	due, sent, failed := 0, 0, 0
	var firstErr error
	for _, s := range list {
		if !IsDue(s, now) {
			continue
		}
		due++
		at := ScheduledAt(s, now)
		if _, err := d.Run(ctx, s, at); err != nil {
			failed++
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", s.Name, err)
			}
			continue
		}
		sent++
	}
	note := fmt.Sprintf("%d schedules, %d due, %d sent, %d failed", len(list), due, sent, failed)
	if failed > 0 {
		return note, firstErr
	}
	return note, nil
}

// Run builds the report for the period ending at `at` and delivers it to the
// schedule's targets, recording the outcome on the schedule. Returns the
// per-target results.
func (d *Deliverer) Run(ctx context.Context, s db.ReportScheduleRow, at time.Time) ([]notify.Result, error) {
	from, to := Period(s, at)
	rep, err := Build(ctx, d.ch, s.TenantID, s.Site, from, to)
	if err != nil {
		_ = d.store.MarkReportRun(ctx, s.ID, time.Now().UTC(), "failed: "+err.Error())
		return nil, err
	}
	results := d.Deliver(ctx, s, rep)
	okN := 0
	var errs []string
	for _, r := range results {
		if r.OK {
			okN++
		} else {
			errs = append(errs, r.Name+": "+r.Err)
		}
	}
	status := fmt.Sprintf("sent to %d/%d target(s)", okN, len(results))
	if len(results) == 0 {
		status = "built, no delivery target configured"
	}
	if len(errs) > 0 {
		status += " — " + strings.Join(errs, "; ")
	}
	_ = d.store.MarkReportRun(ctx, s.ID, time.Now().UTC(), status)
	if len(results) > 0 && okN == 0 {
		return results, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return results, nil
}

// Deliver pushes a built report to the schedule's channel and/or mailbox.
func (d *Deliverer) Deliver(ctx context.Context, s db.ReportScheduleRow, rep *Report) []notify.Result {
	var out []notify.Result
	if s.ChannelID != nil && *s.ChannelID != "" {
		row, err := d.store.GetChannelGlobal(ctx, s.TenantID, *s.ChannelID)
		switch {
		case err != nil:
			out = append(out, notify.Result{ChannelID: *s.ChannelID, Name: "channel", Err: "channel not found: " + err.Error()})
		case !row.Enabled:
			out = append(out, notify.Result{ChannelID: row.ID, Name: row.Name, Err: "channel is disabled"})
		default:
			var cfg notify.Config
			_ = json.Unmarshal(row.Config, &cfg)
			ch := notify.Channel{ID: row.ID, Name: row.Name, Type: row.Type, MinSeverity: row.MinSeverity, Config: cfg}
			details := map[string]interface{}{"site": s.Site, "period_from": rep.From, "period_to": rep.To,
				"events": rep.Summary.Total, "blocked": rep.Summary.Blocked, "detected": rep.Summary.Detected, "sources": rep.Summary.Sources}
			if s.Format == "csv" {
				details["csv"] = string(rep.CSV())
			}
			// A report is addressed to this channel explicitly, so it bypasses the
			// channel's alert-severity gate: Test() is the direct-send path.
			out = append(out, d.notify.Test(ctx, ch, notify.Alert{
				ID: s.ID, Severity: "info", Kind: "scheduled_report", Summary: rep.Text(), Tenant: s.TenantID,
				Site: s.Site, Details: details, CreatedAt: time.Now().UTC(),
			}))
		}
	}
	if len(s.Recipients) > 0 {
		m := d.mail()
		for _, to := range s.Recipients {
			msg := mailer.Message{To: to, Subject: rep.Title, Text: rep.Text(), HTML: string(rep.HTML())}
			if s.Format == "csv" {
				// No attachment support in the mailer: the CSV rides in the text part.
				msg.Text = rep.Text() + "\n\n--- CSV ---\n" + string(rep.CSV())
			}
			err := m.Send(msg)
			r := notify.Result{ChannelID: "email", Name: "email " + to, OK: err == nil}
			if err != nil {
				r.Err = err.Error()
			}
			out = append(out, r)
		}
	}
	return out
}
