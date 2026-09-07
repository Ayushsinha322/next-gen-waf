package reports

import (
	"strings"
	"testing"
	"time"

	"github.com/your-org/sentinel-waf/control-plane/internal/clickhouse"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
)

func weekly(dow, hour int) db.ReportScheduleRow {
	return db.ReportScheduleRow{Cadence: "weekly", DayOfWeek: dow, HourUTC: hour, Enabled: true}
}

func TestScheduledAtWalksBackToTheConfiguredSlot(t *testing.T) {
	// Wednesday 2026-09-09 10:00 UTC
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	got := ScheduledAt(weekly(1, 6), now) // Mondays 06:00
	if got != time.Date(2026, 9, 7, 6, 0, 0, 0, time.UTC) {
		t.Fatalf("weekly Monday 06:00 from Wed: got %v", got)
	}
	// Same weekday, but before the hour → last week's slot.
	got = ScheduledAt(weekly(3, 12), now)
	if got != time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC) {
		t.Fatalf("weekly Wed 12:00 at Wed 10:00: got %v", got)
	}
	d := db.ReportScheduleRow{Cadence: "daily", HourUTC: 6, Enabled: true}
	if got := ScheduledAt(d, now); got != time.Date(2026, 9, 9, 6, 0, 0, 0, time.UTC) {
		t.Fatalf("daily 06:00 at 10:00: got %v", got)
	}
	if got := ScheduledAt(db.ReportScheduleRow{Cadence: "daily", HourUTC: 23}, now); got != time.Date(2026, 9, 8, 23, 0, 0, 0, time.UTC) {
		t.Fatalf("daily 23:00 at 10:00 → yesterday: got %v", got)
	}
}

func TestIsDueOnceUntilItRuns(t *testing.T) {
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	s := weekly(1, 6)
	if !IsDue(s, now) {
		t.Fatal("never run → due")
	}
	ran := time.Date(2026, 9, 7, 6, 1, 0, 0, time.UTC)
	s.LastRunAt = &ran
	if IsDue(s, now) {
		t.Fatal("ran after this week's slot → not due")
	}
	old := time.Date(2026, 9, 1, 6, 1, 0, 0, time.UTC)
	s.LastRunAt = &old
	if !IsDue(s, now) {
		t.Fatal("last ran before this week's slot → due")
	}
	s.Enabled = false
	if IsDue(s, now) {
		t.Fatal("disabled is never due")
	}
	from, to := Period(weekly(1, 6), time.Date(2026, 9, 7, 6, 0, 0, 0, time.UTC))
	if to.Sub(from) != 7*24*time.Hour {
		t.Fatalf("weekly period must be 7 days, got %v", to.Sub(from))
	}
}

func sample() *Report {
	return &Report{
		Title: "WAF security report — juice — 2026-09-01 to 2026-09-08",
		Site:  "juice", From: time.Date(2026, 9, 1, 6, 0, 0, 0, time.UTC), To: time.Date(2026, 9, 8, 6, 0, 0, 0, time.UTC),
		Generated: time.Date(2026, 9, 8, 6, 0, 5, 0, time.UTC),
		Summary: &clickhouse.ReportSummary{
			Total: 1234, Blocked: 1100, Detected: 34, Sources: 87,
			ByAction:   []clickhouse.Facet{{Key: "BLOCK", Count: 1100}, {Key: "DETECT", Count: 34}},
			ByAttack:   []clickhouse.Facet{{Key: "sqli", Count: 600}, {Key: "xss", Count: 300}},
			TopRules:   []clickhouse.RuleHit{{RuleID: "942100", Count: 500, Blocked: 500}},
			TopSources: []clickhouse.Attacker{{IP: "203.0.113.9", Country: "US", Requests: 400, Blocked: 399, LastSeen: 1757300000}},
			ByCountry:  []clickhouse.Facet{{Key: "US", Count: 700}},
			ByDay:      []clickhouse.DayBucket{{Day: "2026-09-01", Total: 100, Blocked: 90}},
		},
		Learning: []clickhouse.LearningStat{{RuleID: "920350", Category: "protocol", Severity: "WARNING", Count: 34,
			Message: "Host header is a numeric IP address", Samples: []string{"<script>evil</script>"}}},
	}
}

func TestRenderersCarryTheNumbersAndEscapeHTML(t *testing.T) {
	r := sample()
	csv := string(r.CSV())
	for _, want := range []string{"events,1234,blocked,1100", "942100,500,500", "203.0.113.9,US,400,399", "920350,protocol,WARNING,34"} {
		if !strings.Contains(csv, want) {
			t.Errorf("csv missing %q:\n%s", want, csv)
		}
	}
	h := string(r.HTML())
	for _, want := range []string{"<b>1234</b>", "942100", "203.0.113.9", "IP Geolocation by DB-IP"} {
		if !strings.Contains(h, want) {
			t.Errorf("html missing %q", want)
		}
	}
	if strings.Contains(h, "<script>evil</script>") || !strings.Contains(h, "&lt;script&gt;evil&lt;/script&gt;") {
		t.Fatal("a matched payload quoted into the report must be HTML-escaped")
	}
	txt := r.Text()
	if !strings.Contains(txt, "1234 WAF events · 1100 blocked") || !strings.Contains(txt, "942100 (500)") {
		t.Fatalf("text summary wrong:\n%s", txt)
	}
}
