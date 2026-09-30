package logs

import (
	"encoding/json"
	"testing"
)

// newTestHub builds a Hub with the aggregation maps initialised but WITHOUT
// starting any file tailers (so the test touches no filesystem).
func newTestHub() *Hub {
	return &Hub{
		subs:       make(map[chan Entry]struct{}),
		blockedIPs: make(map[string]struct{}),
		attackCats: make(map[string]int64),
		byCountry:  make(map[string]int64),
		siteStats:  make(map[string]*SiteStat),
		learnStats: make(map[string]map[string]*LearningStat),
	}
}

func wafEntry(t *testing.T, m map[string]any) Entry {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return Entry{Kind: "waf", Data: b}
}

func TestLearningAggregation(t *testing.T) {
	h := newTestHub()

	// Two DETECT hits for rule 942100 on dvwa (distinct paths), one for 941100.
	h.updateMetrics(wafEntry(t, map[string]any{
		"action": "DETECT", "rule": "942100", "site": "dvwa.local",
		"path": "/login", "sev": "CRITICAL", "attack": "SQLi", "ts": "2026-06-24T10:00:00Z",
		"would_block": true,
	}))
	h.updateMetrics(wafEntry(t, map[string]any{
		"action": "DETECT", "rule": "942100", "site": "dvwa.local",
		"path": "/search", "sev": "CRITICAL", "attack": "SQLi", "ts": "2026-06-24T10:01:00Z",
		"would_block": true,
	}))
	h.updateMetrics(wafEntry(t, map[string]any{
		"action": "DETECT", "rule": "941100", "site": "dvwa.local",
		"path": "/comment", "sev": "HIGH", "attack": "XSS", "ts": "2026-06-24T10:00:30Z",
		"would_block": true,
	}))
	// A real BLOCK (blocking mode) must NOT land in the learning report.
	h.updateMetrics(wafEntry(t, map[string]any{
		"action": "BLOCK", "rule": "930100", "site": "dvwa.local", "path": "/x",
	}))

	rules := h.GetLearningStats("dvwa.local")
	if len(rules) != 2 {
		t.Fatalf("expected 2 learning rules, got %d: %+v", len(rules), rules)
	}
	// Sorted by count desc → 942100 (2) first.
	if rules[0].RuleID != "942100" || rules[0].Count != 2 {
		t.Fatalf("expected 942100 count=2 first, got %s count=%d", rules[0].RuleID, rules[0].Count)
	}
	if len(rules[0].Samples) != 2 {
		t.Fatalf("expected 2 distinct sample paths, got %v", rules[0].Samples)
	}
	if rules[0].LastSeen != "2026-06-24T10:01:00Z" {
		t.Fatalf("expected last_seen to track latest, got %s", rules[0].LastSeen)
	}
	if rules[1].RuleID != "941100" || rules[1].Count != 1 {
		t.Fatalf("expected 941100 count=1 second, got %s count=%d", rules[1].RuleID, rules[1].Count)
	}

	// A 930100 BLOCK should be absent from the learning report entirely.
	for _, r := range rules {
		if r.RuleID == "930100" {
			t.Fatalf("blocking-mode BLOCK leaked into learning report")
		}
	}

	// Scoping: an unknown site yields no rules; "" merges across all sites.
	if got := h.GetLearningStats("nope"); len(got) != 0 {
		t.Fatalf("expected 0 rules for unknown site, got %d", len(got))
	}
	if got := h.GetLearningStats(""); len(got) != 2 {
		t.Fatalf("expected 2 rules merged across all sites, got %d", len(got))
	}
}

func TestLearningSampleCap(t *testing.T) {
	h := newTestHub()
	for i := 0; i < learningSampleCap+5; i++ {
		h.updateMetrics(wafEntry(t, map[string]any{
			"action": "DETECT", "rule": "942100", "site": "s",
			"path": "/p" + string(rune('a'+i)), "would_block": true, "ts": "2026-06-24T10:00:00Z",
		}))
	}
	rules := h.GetLearningStats("s")
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Count != int64(learningSampleCap+5) {
		t.Fatalf("count should track every hit, got %d", rules[0].Count)
	}
	if len(rules[0].Samples) > learningSampleCap {
		t.Fatalf("samples must be capped at %d, got %d", learningSampleCap, len(rules[0].Samples))
	}
}

// Every contributing rule is counted, not only the event's leading one. A
// response-leak rule on a request learning mode had already flagged (leading
// rule = the request's) never had a row before. (Code review finding.)
func TestLearningCountsEveryRuleInTheEvent(t *testing.T) {
	h := newTestHub()
	h.updateMetrics(wafEntry(t, map[string]any{
		"action": "DETECT", "rule": "942100", "site": "app", "path": "/q",
		"sev": "CRITICAL", "attack": "SQLi", "ts": "2026-09-30T10:00:00Z", "would_block": true,
		"rules": []map[string]any{
			{"id": "942100", "sev": "CRITICAL", "msg": "SQLi"},
			{"id": "951220", "sev": "CRITICAL", "msg": "mssql SQL Information Leakage"},
			{"id": "", "sev": "", "msg": ""},
		},
	}))
	got := map[string]int64{}
	for _, r := range h.GetLearningStats("app") {
		got[r.RuleID] = r.Count
	}
	if got["942100"] != 1 || got["951220"] != 1 || len(got) != 2 {
		t.Fatalf("want 942100 and 951220 once each, got %v", got)
	}
}
