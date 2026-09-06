package main

import (
	"testing"

	"github.com/your-org/sentinel-waf/control-plane/internal/clickhouse"
)

func TestMergeRuleHitsStampsEveryRuleAndTotals(t *testing.T) {
	inv := map[string]any{
		"sites": []any{
			map[string]any{
				"site": "juice",
				"rules": []any{
					map[string]any{"id": float64(942100)},
					map[string]any{"id": float64(941100)},
				},
			},
		},
		"totals": map[string]any{"compiled": float64(2)},
	}
	mergeRuleHits(inv, []clickhouse.RuleHit{
		{RuleID: "942100", Count: 17, Blocked: 15},
		{RuleID: "999999", Count: 3, Blocked: 0}, // fired on a rule not in this inventory
	})
	rules := inv["sites"].([]any)[0].(map[string]any)["rules"].([]any)
	r0 := rules[0].(map[string]any)
	if r0["hits_24h"] != int64(17) || r0["blocks_24h"] != int64(15) {
		t.Fatalf("942100 hits: got %v/%v", r0["hits_24h"], r0["blocks_24h"])
	}
	r1 := rules[1].(map[string]any)
	if r1["hits_24h"] != int64(0) || r1["blocks_24h"] != int64(0) {
		t.Fatalf("941100 must get explicit zeros, got %v/%v", r1["hits_24h"], r1["blocks_24h"])
	}
	if inv["totals"].(map[string]any)["hits_24h"] != int64(20) {
		t.Fatalf("totals.hits_24h should sum every hit, got %v", inv["totals"].(map[string]any)["hits_24h"])
	}
}

func TestURLQueryEscape(t *testing.T) {
	if got := urlQueryEscape("7c0c499b-1"); got != "7c0c499b-1" {
		t.Fatalf("uuid-ish id must pass through, got %q", got)
	}
	if got := urlQueryEscape("a b&c=d"); got != "a%20b%26c%3Dd" {
		t.Fatalf("unsafe chars must be escaped, got %q", got)
	}
}
