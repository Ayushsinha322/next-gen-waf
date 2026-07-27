package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// The tuned detection configuration is a pair: anomaly_threshold 10 AND rule
// 920230 disabled (deploy/load-test/waf-detection.yaml, measured at composite
// 99.60% / true-negative 99.29%). Half of it silently reverting to the old
// threshold-5 posture would change every site's false-positive behaviour with no
// test failing, so both halves are pinned here.

func TestBuildRustWafDefaultsToTunedConfig(t *testing.T) {
	waf, err := buildRustWaf(nil)
	if err != nil {
		t.Fatalf("buildRustWaf(nil): %v", err)
	}
	if got := waf["anomaly_threshold"]; got != 10 {
		t.Errorf("anomaly_threshold = %v, want 10 (the benchmarked value)", got)
	}
	if got := waf["paranoia_level"]; got != 2 {
		t.Errorf("paranoia_level = %v, want 2", got)
	}
	if got := waf["mode"]; got != "blocking" {
		t.Errorf("mode = %v, want blocking", got)
	}
}

// A stored policy that omits the threshold must still get the tuned default, and
// an explicit threshold must always win over it.
func TestBuildRustWafThresholdPrecedence(t *testing.T) {
	waf, err := buildRustWaf(json.RawMessage(`{"mode":"learning"}`))
	if err != nil {
		t.Fatalf("buildRustWaf: %v", err)
	}
	if got := waf["anomaly_threshold"]; got != 10 {
		t.Errorf("omitted threshold = %v, want the 10 default", got)
	}

	waf, err = buildRustWaf(json.RawMessage(`{"anomaly_threshold":3}`))
	if err != nil {
		t.Fatalf("buildRustWaf: %v", err)
	}
	if got := waf["anomaly_threshold"]; got != 3 {
		t.Errorf("explicit threshold = %v, want 3 to override the default", got)
	}
}

// defaultWafPolicyJSON is what gets PERSISTED for a site created without a
// policy; buildRustWaf's default is what the data plane is EFFECTIVELY handed.
// If they disagree, a site's stored policy misrepresents how it actually behaves.
func TestDefaultWafPolicyMatchesBuildDefault(t *testing.T) {
	stored, err := buildRustWaf(json.RawMessage(defaultWafPolicyJSON))
	if err != nil {
		t.Fatalf("buildRustWaf(defaultWafPolicyJSON): %v", err)
	}
	built, err := buildRustWaf(nil)
	if err != nil {
		t.Fatalf("buildRustWaf(nil): %v", err)
	}
	for _, k := range []string{"mode", "paranoia_level", "anomaly_threshold"} {
		if stored[k] != built[k] {
			t.Errorf("%s: stored default %v != build default %v — the two have drifted",
				k, stored[k], built[k])
		}
	}
}

func TestBuildRustWafInjectsDefaultExclusions(t *testing.T) {
	waf, err := buildRustWaf(nil)
	if err != nil {
		t.Fatalf("buildRustWaf: %v", err)
	}
	excl, ok := waf["rule_exclusions"].([]map[string]any)
	if !ok {
		t.Fatalf("rule_exclusions has type %T, want []map[string]any", waf["rule_exclusions"])
	}

	var saw932236, saw920230 bool
	for _, e := range excl {
		switch {
		case ruleIDEquals(e["rule_id"], 932236):
			saw932236 = true
			targets, _ := e["exclude_targets"].([]string)
			if len(targets) != 1 || targets[0] != "ARGS_NAMES" {
				t.Errorf("932236 targets = %v, want [ARGS_NAMES]", e["exclude_targets"])
			}
		case ruleIDEquals(e["rule_id"], 920230):
			saw920230 = true
			if dis, _ := e["disable"].(bool); !dis {
				t.Error("920230 must be a whole-rule disable, not a target exclusion")
			}
		}
	}
	if !saw932236 {
		t.Error("default 932236 ARGS_NAMES exclusion not injected")
	}
	if !saw920230 {
		t.Error("default 920230 disable not injected — benign false-positive rate regresses")
	}
}

// Storing an empty entry for a defaulted rule is the documented way to re-enable
// it. The marker must suppress the injected default and not itself reach the data
// plane, where an exclusion with no targets and no disable is a no-op.
func TestDefaultExclusionOptOut(t *testing.T) {
	for _, id := range []int{932236, 920230} {
		policy := json.RawMessage(`{"rule_exclusions":[{"rule_id":` + itoa(id) + `}]}`)
		waf, err := buildRustWaf(policy)
		if err != nil {
			t.Fatalf("buildRustWaf: %v", err)
		}
		excl, _ := waf["rule_exclusions"].([]map[string]any)
		for _, e := range excl {
			if ruleIDEquals(e["rule_id"], id) {
				t.Errorf("rule %d: opt-out marker did not suppress the default (got %+v)", id, e)
			}
		}
	}
}

// An operator-defined exclusion for a defaulted rule must win over the injected
// default rather than being emitted alongside it.
func TestOperatorExclusionOverridesDefault(t *testing.T) {
	policy := json.RawMessage(`{"rule_exclusions":[{"rule_id":920230,"exclude_targets":["ARGS:q"]}]}`)
	waf, err := buildRustWaf(policy)
	if err != nil {
		t.Fatalf("buildRustWaf: %v", err)
	}
	excl, _ := waf["rule_exclusions"].([]map[string]any)

	count := 0
	for _, e := range excl {
		if ruleIDEquals(e["rule_id"], 920230) {
			count++
			if dis, _ := e["disable"].(bool); dis {
				t.Error("operator's target exclusion was replaced by the default disable")
			}
		}
	}
	if count != 1 {
		t.Errorf("got %d entries for 920230, want exactly the operator's one", count)
	}
}

// entry() must hand out a fresh map each call — a shared map would let one site's
// mutation of its exclusion list leak into every other site's config.
func TestDefaultExclusionsAreNotShared(t *testing.T) {
	for _, d := range defaultRuleExclusions {
		a, b := d.entry(), d.entry()
		a["rule_id"] = 1
		if b["rule_id"] == 1 {
			t.Fatalf("rule %d: entry() returns a shared map", d.id)
		}
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// The 18 rules in placement.conf + coverage.conf are what took App-TP from
// 80.30% to 99.09%, and nothing generated by the control plane loaded them until
// 2026-07-27 — every API-created site silently ran stock CRS only. Pin them so
// that cannot regress quietly again.
func TestBuildRustWafAlwaysLoadsSentinelRules(t *testing.T) {
	cases := []struct {
		name   string
		policy json.RawMessage
	}{
		{"no policy at all", nil},
		{"blocking, no categories", json.RawMessage(`{"mode":"blocking"}`)},
		{"learning mode", json.RawMessage(`{"mode":"learning"}`)},
		{"a narrow category selection", json.RawMessage(`{"mode":"blocking","rule_categories":["sqli"]}`)},
		{"the VM's category list", json.RawMessage(`{"mode":"blocking","rule_categories":["sqli","xss","rce","lfi"]}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			waf, err := buildRustWaf(tc.policy)
			if err != nil {
				t.Fatalf("buildRustWaf: %v", err)
			}
			rules, ok := waf["rules"].([]string)
			if !ok {
				t.Fatalf("rules has type %T, want []string", waf["rules"])
			}
			for _, want := range sentinelRuleFiles {
				found := false
				for _, got := range rules {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("%s missing from the rule list — detection drops to stock CRS", want)
				}
			}
		})
	}
}

// Our rules contribute to tx.anomaly_score, which the CRS files establish, so
// they have to be evaluated after them.
func TestSentinelRulesLoadAfterCRS(t *testing.T) {
	waf, err := buildRustWaf(json.RawMessage(`{"mode":"blocking","rule_categories":["sqli","xss"]}`))
	if err != nil {
		t.Fatalf("buildRustWaf: %v", err)
	}
	rules, _ := waf["rules"].([]string)

	lastCRS := -1
	firstOwn := len(rules)
	for i, r := range rules {
		if strings.Contains(r, "owasp-crs") {
			lastCRS = i
		}
		for _, own := range sentinelRuleFiles {
			if r == own && i < firstOwn {
				firstOwn = i
			}
		}
	}
	if lastCRS == -1 || firstOwn == len(rules) {
		t.Fatalf("expected both CRS and sentinel rules, got %v", rules)
	}
	if firstOwn < lastCRS {
		t.Errorf("sentinel rules at %d precede the last CRS file at %d", firstOwn, lastCRS)
	}
}

// Mode "off" means off: no rule engine is built for the site at all.
func TestModeOffLoadsNoRules(t *testing.T) {
	waf, err := buildRustWaf(json.RawMessage(`{"mode":"off"}`))
	if err != nil {
		t.Fatalf("buildRustWaf: %v", err)
	}
	if rules, _ := waf["rules"].([]string); len(rules) != 0 {
		t.Errorf("mode=off loaded %d rule files, want 0", len(rules))
	}
}
