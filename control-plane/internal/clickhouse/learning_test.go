package clickhouse

import (
	"strings"
	"testing"
)

// The learning report is the evidence an operator uses to decide a site is safe
// to flip out of learning mode. It used to be served from an in-memory
// aggregate fed by tailing waf.log FROM ITS END (logs.Hub tailKind), so a
// control-plane restart reset it to empty and the operator had no way to tell.
// Serving it from stored events is what makes it survive a restart; these tests
// pin the properties that make the stored version trustworthy.

func TestLearningReportIsTenantScoped(t *testing.T) {
	c := &Client{db: "sentinel_logs"}
	sql := c.learningSQL("tenant-A", "", 0, 0, 5)
	if !strings.Contains(sql, "tenant = 'tenant-A'") {
		t.Fatalf("tenant predicate missing — the in-memory path had none, the stored path must: %q", sql)
	}
	// The in-memory version merged every site in the process. Scoping must be
	// honoured when asked for.
	sql2 := c.learningSQL("tenant-A", "shop.example", 0, 0, 5)
	if !strings.Contains(sql2, "site = 'shop.example'") {
		t.Fatalf("site predicate missing: %q", sql2)
	}
}

func TestLearningReportCountsOnlyWouldHaveBlocked(t *testing.T) {
	c := &Client{db: "sentinel_logs"}
	sql := c.learningSQL("t", "", 0, 0, 5)
	// DETECT is what the data plane writes for a learning-mode would-block.
	// Counting BLOCKs here would inflate the report with requests that were
	// actually stopped, which is the opposite of what the operator is judging.
	if !strings.Contains(sql, "action = 'DETECT'") {
		t.Fatalf("report must count DETECT rows only: %q", sql)
	}
	// Non-rule rows carry "-" and would aggregate into a meaningless bucket.
	if !strings.Contains(sql, "rule != '-'") || !strings.Contains(sql, "rule != ''") {
		t.Fatalf("report must exclude empty/placeholder rule ids: %q", sql)
	}
	if !strings.Contains(sql, "GROUP BY rule_id") {
		t.Fatalf("report must aggregate per rule: %q", sql)
	}
	// Every contributing rule, from the event's rules list — not the leading
	// rule alone (code review: a response-leak rule on an already-flagged
	// request never got a row).
	if !strings.Contains(sql, "JSONExtractArrayRaw(rules)") || !strings.Contains(sql, "arrayJoin") {
		t.Fatalf("report must count every rule in the event's rules list: %q", sql)
	}
}

// A learning window runs for a business cycle (the runbook says 1-2 weeks), so
// silently defaulting to 24 hours would understate what a rule would block --
// the one direction of error that makes flipping to blocking unsafe.
func TestLearningReportHasNoDefaultTimeBound(t *testing.T) {
	c := &Client{db: "sentinel_logs"}
	sql := c.learningSQL("t", "", 0, 0, 5)
	if strings.Contains(sql, "ts >=") || strings.Contains(sql, "ts <=") {
		t.Fatalf("unbounded request must not acquire a time predicate: %q", sql)
	}
	// ...but an explicit window is honoured.
	sql2 := c.learningSQL("t", "", 1756000000, 1756100000, 5)
	if !strings.Contains(sql2, "ts >= toDateTime(1756000000)") ||
		!strings.Contains(sql2, "ts <= toDateTime(1756100000)") {
		t.Fatalf("explicit window not applied: %q", sql2)
	}
}

func TestLearningReportEscapesAndCapsInput(t *testing.T) {
	c := &Client{db: "sentinel_logs"}
	// Site reaches SQL, so it must pass through esc() like every other value.
	sql := c.learningSQL("t", "x' OR '1'='1", 0, 0, 5)
	if !strings.Contains(sql, `\'`) {
		t.Fatalf("site value not escaped: %q", sql)
	}
	// Sample cap is clamped: a caller-supplied cap reaches an aggregate
	// function's parameter position, and an unbounded one would let a noisy
	// rule return an arbitrarily large array per row.
	for _, bad := range []int{0, -1, 999} {
		got := c.learningSQL("t", "", 0, 0, bad)
		if !strings.Contains(got, "groupUniqArray(5)(path)") {
			t.Fatalf("sampleCap %d should clamp to 5: %q", bad, got)
		}
	}
	if ok := c.learningSQL("t", "", 0, 0, 3); !strings.Contains(ok, "groupUniqArray(3)(path)") {
		t.Fatalf("in-range sampleCap should be honoured: %q", ok)
	}
}
