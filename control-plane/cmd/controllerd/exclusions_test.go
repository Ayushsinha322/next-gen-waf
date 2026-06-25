package main

import (
	"encoding/json"
	"testing"
)

func TestParseEncodeExclusionsRoundTrip(t *testing.T) {
	// A waf_policy with other keys plus one existing exclusion.
	policy := json.RawMessage(`{
		"mode":"learning",
		"paranoia_level":2,
		"rule_exclusions":[{"rule_id":932236,"exclude_targets":["ARGS_NAMES"]}]
	}`)

	waf, excl := parseExclusions(policy)
	if _, ok := waf["rule_exclusions"]; ok {
		t.Fatal("rule_exclusions must be stripped from the generic map")
	}
	if waf["mode"] == nil || waf["paranoia_level"] == nil {
		t.Fatal("non-exclusion keys must be preserved")
	}
	if len(excl) != 1 || excl[0].RuleID != 932236 {
		t.Fatalf("expected the existing 932236 exclusion, got %+v", excl)
	}

	// Add a one-click disable for 942100.
	excl = append(excl, ruleExclusionSpec{RuleID: 942100, Disable: true})
	out, err := encodeExclusions(waf, excl)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	// Re-parse: both exclusions survive and other keys remain intact.
	waf2, excl2 := parseExclusions(out)
	if waf2["mode"] == nil {
		t.Fatal("mode lost on round-trip")
	}
	if len(excl2) != 2 {
		t.Fatalf("expected 2 exclusions after round-trip, got %d", len(excl2))
	}
	var sawDisable bool
	for _, e := range excl2 {
		if e.RuleID == 942100 && e.Disable {
			sawDisable = true
		}
	}
	if !sawDisable {
		t.Fatal("disable exclusion for 942100 not preserved")
	}
}

func TestParseExclusionsEmptyPolicy(t *testing.T) {
	waf, excl := parseExclusions(nil)
	if waf == nil {
		t.Fatal("expected non-nil map for nil policy")
	}
	if len(excl) != 0 {
		t.Fatalf("expected no exclusions, got %d", len(excl))
	}
}

func TestRuleIDEquals(t *testing.T) {
	// JSON numbers decode to float64 through interface{}.
	if !ruleIDEquals(float64(932236), 932236) {
		t.Fatal("float64 rule_id should match")
	}
	if !ruleIDEquals(932236, 932236) {
		t.Fatal("int rule_id should match")
	}
	if ruleIDEquals("932236", 932236) {
		t.Fatal("string rule_id should not match (not numeric)")
	}
	if ruleIDEquals(float64(941100), 932236) {
		t.Fatal("different IDs must not match")
	}
}
