package clickhouse

// Live compatibility test: every query the control plane sends to ClickHouse,
// run against a real server.
//
// Skipped unless SENTINEL_CH_LIVE_URL names one, e.g.
//
//	SENTINEL_CH_LIVE_URL=http://sentinel:sentinel_dev@127.0.0.1:8123/sentinel_logs \
//	  go test ./internal/clickhouse -run TestLive -v
//
// The unit tests here check the SQL we BUILD; only a server can say whether
// that SQL still parses, runs and returns the shapes the console decodes. It
// exists for ClickHouse version changes (the first was 1.1.14's 24.10 → 26.3;
// 1.1.13's 26.8 was withdrawn after it SIGILLed on an x86-64-v1 CPU):
// run it against the old version and the new one, on the same data, before
// changing the pin. The schema is the data plane's — create it first with the
// sentinel-storage live tests (`cargo test -p sentinel-storage -- --ignored`).
//
// It writes rows under a tenant of its own and deletes them afterwards (a
// lightweight DELETE), so it is safe on a scratch server — point it at one.

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func liveClient(t *testing.T) *Client {
	t.Helper()
	url := os.Getenv("SENTINEL_CH_LIVE_URL")
	if url == "" {
		t.Skip("set SENTINEL_CH_LIVE_URL=http://user:pass@host:8123/db to run against a live ClickHouse")
	}
	t.Setenv("SENTINEL_CLICKHOUSE_URL", url)
	t.Setenv("SENTINEL_CLICKHOUSE_DB", "")
	t.Setenv("SENTINEL_CLICKHOUSE_USER", "")
	t.Setenv("SENTINEL_CLICKHOUSE_PASSWORD", "")
	c := FromEnv()
	if !c.Enabled() {
		t.Fatalf("client not enabled for %q", url)
	}
	return c
}

func TestLiveEveryControlPlaneQueryRuns(t *testing.T) {
	c := liveClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tenant := fmt.Sprintf("live-test-%d", time.Now().UnixNano())
	now := time.Now().UTC()
	from, to := now.Add(-time.Hour).Unix(), now.Add(time.Hour).Unix()
	// Epoch seconds, not a "YYYY-MM-DD hh:mm:ss" string: ClickHouse reads a
	// naive DateTime string in the SERVER's timezone, so on an Asia/Kolkata
	// server the rows landed 5.5 h away from the ±1 h query window.
	ts := now.Unix()

	type ev struct{ id, ip, rule, attack, action, sev, country string }
	events := []ev{
		{"11111111-1111-4111-8111-111111111111", "203.0.113.7", "942100", "SQL Injection", "BLOCK", "CRITICAL", "IN"},
		{"22222222-2222-4222-8222-222222222222", "203.0.113.7", "941100", "XSS", "BLOCK", "CRITICAL", "IN"},
		{"33333333-3333-4333-8333-333333333333", "198.51.100.9", "951220", "mssql SQL Information Leakage", "DETECT", "CRITICAL", "US"},
	}
	var rows strings.Builder
	for _, e := range events {
		fmt.Fprintf(&rows,
			`{"ts":%d,"ip":"%s","country":"%s","site":"live.example","tenant":"%s","method":"GET",`+
				`"path":"/search","query":"q=x","matched":"' OR 1=1--","rule":"%s","attack":"%s","action":"%s",`+
				`"severity":"%s","score":5,"status":403,"protocol":"h2","request_id":"%s","target":"ARGS:q",`+
				`"mode":"blocking","threshold":10,"explanation":"live test","ja4":"t13d_live",`+
				`"rules":"[{\"id\":\"%s\",\"score\":5,\"target\":\"ARGS:q\"}]",`+
				`"headers":"{\"user-agent\":\"live\",\"cookie\":\"sid=[redacted]\"}","ua":"live-agent"}`+"\n",
			ts, e.ip, e.country, tenant, e.rule, e.attack, e.action, e.sev, e.id, e.rule)
	}
	if _, err := c.query(ctx, fmt.Sprintf(
		"INSERT INTO %s.waf_events (ts, ip, country, site, tenant, method, path, query, matched, rule, attack, action, "+
			"severity, score, status, protocol, request_id, target, mode, threshold, explanation, ja4, rules, headers, ua) "+
			"FORMAT JSONEachRow\n%s", c.db, rows.String())); err != nil {
		t.Fatalf("insert waf_events: %v", err)
	}
	if _, err := c.query(ctx, fmt.Sprintf(
		"INSERT INTO %s.traffic_buckets (ts, tenant, site_id, reqs, blocked, p99_ms) FORMAT JSONEachRow\n"+
			`{"ts":%d,"tenant":"%s","site_id":"live.example","reqs":100,"blocked":3,"p99_ms":12.5}`+"\n",
		c.db, ts, tenant)); err != nil {
		t.Fatalf("insert traffic_buckets: %v", err)
	}
	t.Cleanup(func() {
		for _, tbl := range []string{"waf_events", "traffic_buckets"} {
			// A lightweight DELETE, not ALTER … DELETE: a mutation rewrites every
			// part of the table, which is not harmless on a large shared server.
			_, _ = c.query(context.Background(), fmt.Sprintf(
				"DELETE FROM %s.%s WHERE tenant = '%s'", c.db, tbl, esc(tenant)))
		}
	})

	st, err := c.Status(ctx, tenant)
	if err != nil || st["reachable"] != true {
		t.Fatalf("Status: %v %v", st, err)
	}
	if st["events"] != int64(3) || st["traffic_buckets"] != int64(1) {
		t.Errorf("Status counts: %v", st)
	}

	got, err := c.Search(ctx, SearchFilter{Tenant: tenant, From: from, To: to, Limit: 50})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("Search returned %d events, want 3", len(got))
	}
	for _, e := range got {
		if len(e.Rules) == 0 || len(e.Headers) == 0 || e.UA != "live-agent" {
			t.Errorf("event %s lost its detail columns: rules=%s headers=%s ua=%q", e.RequestID, e.Rules, e.Headers, e.UA)
		}
	}
	if f, err := c.Search(ctx, SearchFilter{Tenant: tenant, From: from, To: to, Rule: "951220", Limit: 50}); err != nil || len(f) != 1 {
		t.Errorf("Search by rule: %d events, %v", len(f), err)
	}
	if f, err := c.Search(ctx, SearchFilter{Tenant: tenant, From: from, To: to, Query: "Leakage", Limit: 50}); err != nil || len(f) != 1 {
		t.Errorf("Search by text: %d events, %v", len(f), err)
	}

	sid, err := c.FindBySupportID(ctx, tenant, events[1].id)
	if err != nil || len(sid) != 1 || sid[0].Rule != "941100" {
		t.Errorf("FindBySupportID: %+v %v", sid, err)
	}

	if tl, err := c.Timeline(ctx, tenant, from, to, 300); err != nil || len(tl) == 0 {
		t.Errorf("Timeline: %d buckets, %v", len(tl), err)
	}
	if sl, err := c.SeverityTimeline(ctx, tenant, from, to, 300); err != nil || len(sl) == 0 {
		t.Errorf("SeverityTimeline: %d buckets, %v", len(sl), err)
	}
	for _, col := range []string{"rule", "ip", "country", "action", "site", "severity", "protocol", "attack"} {
		fs, err := c.Facets(ctx, col, tenant, from, to, 10)
		if err != nil || len(fs) == 0 {
			t.Errorf("Facets(%s): %d, %v", col, len(fs), err)
		}
		if col == "rule" && err == nil {
			for _, f := range fs {
				if f.Label == "" {
					t.Errorf("rule facet %s has no label", f.Key)
				}
			}
		}
	}
	if rh, err := c.RuleHits(ctx, tenant, from, to); err != nil || len(rh) == 0 {
		t.Errorf("RuleHits: %d, %v", len(rh), err)
	}
	if _, err := c.LearningStats(ctx, tenant, "live.example", from, to, 5); err != nil {
		t.Errorf("LearningStats: %v", err)
	}
	if ta, err := c.TopAttackers(ctx, tenant, from, to, 10); err != nil || len(ta) == 0 {
		t.Errorf("TopAttackers: %d, %v", len(ta), err)
	}
	if _, err := c.RecentThreatIntelBlocks(ctx, tenant, from, to, 10); err != nil {
		t.Errorf("RecentThreatIntelBlocks: %v", err)
	}

	f := SearchFilter{Tenant: tenant, From: from, To: to}
	if n, err := c.ExportCount(ctx, f); err != nil || n != 3 {
		t.Errorf("ExportCount: %d, %v", n, err)
	}
	for _, name := range []string{"csv", "ndjson", "json"} {
		format, _ := LookupExportFormat(name)
		rc, err := c.ExportStream(ctx, f, format)
		if err != nil {
			t.Errorf("ExportStream(%s): %v", name, err)
			continue
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		for _, e := range events {
			if !strings.Contains(string(b), e.id) {
				t.Errorf("ExportStream(%s) is missing %s", name, e.id)
			}
		}
	}

	if rs, err := c.ReportSummary(ctx, tenant, "", from, to); err != nil || rs == nil {
		t.Errorf("ReportSummary: %+v %v", rs, err)
	}
	if used, free, total, err := c.DiskUsage(ctx); err != nil || total <= 0 || free < 0 || used < 0 || used > 1 {
		t.Errorf("DiskUsage: used=%v free=%d total=%d err=%v", used, free, total, err)
	}

	// The learning report counts every rule in a DETECT event's rules list.
	// Event 3 is a DETECT led by 951220; add one led by 942100 that also lists
	// 951220, as a learning-mode request that scored AND leaked does.
	if _, err := c.query(ctx, fmt.Sprintf(
		"INSERT INTO %s.waf_events (ts, tenant, site, path, rule, attack, action, severity, request_id, rules) FORMAT JSONEachRow\n"+
			`{"ts":%d,"tenant":"%s","site":"live.example","path":"/both","rule":"942100","attack":"SQL Injection","action":"DETECT","severity":"CRITICAL","request_id":"44444444-4444-4444-8444-444444444444",`+
			`"rules":"[{\"id\":\"942100\",\"sev\":\"CRITICAL\",\"msg\":\"SQL Injection\"},{\"id\":\"951220\",\"sev\":\"CRITICAL\",\"msg\":\"mssql SQL Information Leakage\"}]"}`+"\n",
		c.db, now.Unix(), tenant)); err != nil {
		t.Fatalf("insert learning event: %v", err)
	}
	ls, err := c.LearningStats(ctx, tenant, "live.example", from, to, 5)
	if err != nil {
		t.Fatalf("LearningStats: %v", err)
	}
	counts := map[string]int64{}
	for _, r := range ls {
		counts[r.RuleID] = r.Count
	}
	if counts["951220"] != 2 || counts["942100"] != 1 {
		t.Errorf("learning report must count every rule in each DETECT: %v", counts)
	}
}
