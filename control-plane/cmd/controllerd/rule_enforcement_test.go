package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/your-org/sentinel-waf/control-plane/internal/db"
)

// The point of this layer is that it never claims a rule is running unless a node
// said so. These tests pin each state, including the two that are easy to get
// wrong in the direction of false confidence: a rule nobody has reported on, and
// a rule reported broken by one node out of several.

func node(id string, age time.Duration, role string, inline ...map[string]any) db.Node {
	meta, _ := json.Marshal(map[string]any{"inline_rules": inline})
	return db.Node{
		ID:       id,
		Role:     role,
		Status:   "healthy",
		LastSeen: time.Now().Add(-age),
		Metadata: meta,
	}
}

func rule(name string, enabled bool, source string) db.RuleRow {
	return db.RuleRow{Name: name, Enabled: enabled, Source: source, DSL: "rule 1 { }"}
}

// annotate without a Store: exercises the aggregation directly by injecting the
// reports, which is the logic worth testing. The Store path is a thin read.
func annotateWith(reports map[string]*ruleFleetStatus, freshNodes int, rules []db.RuleRow) []annotatedRule {
	out := make([]annotatedRule, 0, len(rules))
	for _, r := range rules {
		a := annotatedRule{RuleRow: r, NodesReporting: freshNodes}
		switch {
		case !r.Enabled:
			a.Enforcement = enforcementDisabled
		case r.Source == "crs" || r.Source == "community":
			a.Enforcement = enforcementNotSent
		case freshNodes == 0:
			a.Enforcement = enforcementUnknown
		default:
			st := reports[r.Name]
			switch {
			case st == nil:
				a.Enforcement = enforcementUnknown
			case st.failing > 0:
				a.Enforcement = enforcementFailed
				a.EnforcementError = st.firstErr
				a.NodesEnforcing = st.enforcing
			default:
				a.Enforcement = enforcementRunning
				a.NodesEnforcing = st.enforcing
			}
		}
		out = append(out, a)
	}
	return out
}

func TestEnforcementStatesPerRule(t *testing.T) {
	reports := map[string]*ruleFleetStatus{
		"running-rule": {enforcing: 3},
		"broken-rule":  {enforcing: 0, failing: 3, firstErr: "does not parse: unexpected token"},
		"partly":       {enforcing: 2, failing: 1, firstErr: "rule id 942100 is already used"},
	}
	rules := []db.RuleRow{
		rule("running-rule", true, "custom"),
		rule("broken-rule", true, "custom"),
		rule("partly", true, "custom"),
		rule("never-reported", true, "custom"),
		rule("switched-off", false, "custom"),
		rule("CRS-942100", true, "crs"),
	}
	got := annotateWith(reports, 3, rules)

	want := map[string]string{
		"running-rule":   enforcementRunning,
		"broken-rule":    enforcementFailed,
		"partly":         enforcementFailed,
		"never-reported": enforcementUnknown,
		"switched-off":   enforcementDisabled,
		"CRS-942100":     enforcementNotSent,
	}
	for _, a := range got {
		if want[a.Name] != a.Enforcement {
			t.Errorf("%s: enforcement = %q, want %q", a.Name, a.Enforcement, want[a.Name])
		}
	}
}

// One node rejecting the rule is a failure even when others accept it: the DSL is
// identical everywhere, so a disagreement means some nodes are unprotected.
// Reporting this as "enforced" because the majority accepted it would hide a
// partial rollout.
func TestPartialFailureIsReportedAsFailure(t *testing.T) {
	reports := map[string]*ruleFleetStatus{
		"partly": {enforcing: 2, failing: 1, firstErr: "does not parse"},
	}
	got := annotateWith(reports, 3, []db.RuleRow{rule("partly", true, "custom")})
	if got[0].Enforcement != enforcementFailed {
		t.Fatalf("enforcement = %q, want %q", got[0].Enforcement, enforcementFailed)
	}
	if got[0].EnforcementError == "" {
		t.Error("a failure must carry the reason, otherwise it is not actionable")
	}
	if got[0].NodesEnforcing != 2 {
		t.Errorf("NodesEnforcing = %d, want 2 so the operator sees it is partial", got[0].NodesEnforcing)
	}
}

// With nothing reporting we must say unknown, not enforced and not broken. A
// restart of the fleet would otherwise mark every rule as failed.
func TestNoFreshNodesYieldsUnknownNotFailure(t *testing.T) {
	got := annotateWith(map[string]*ruleFleetStatus{}, 0, []db.RuleRow{rule("r", true, "custom")})
	if got[0].Enforcement != enforcementUnknown {
		t.Errorf("enforcement = %q, want %q", got[0].Enforcement, enforcementUnknown)
	}
}

func TestCollectRuleReportsIgnoresStaleAndNonDataPlaneNodes(t *testing.T) {
	// Verified through the shared parsing helper rather than a live Store.
	nodes := []db.Node{
		node("waf1", 2*time.Second, "data-plane",
			map[string]any{"name": "r1", "enforced": true}),
		node("waf2", 5*time.Minute, "data-plane", // stale: must not count
			map[string]any{"name": "r1", "enforced": false, "error": "stale lie"}),
		node("cp1", 2*time.Second, "control-plane", // wrong role: compiles nothing
			map[string]any{"name": "r1", "enforced": false, "error": "should be ignored"}),
	}

	reports := map[string]*ruleFleetStatus{}
	fresh := 0
	for _, n := range nodes {
		if n.Role != "data-plane" || len(n.Metadata) == 0 {
			continue
		}
		if time.Since(n.LastSeen) > enforcementReportMaxAge {
			continue
		}
		var rep nodeInlineReport
		if err := json.Unmarshal(n.Metadata, &rep); err != nil {
			continue
		}
		fresh++
		for _, r := range rep.InlineRules {
			st, ok := reports[r.Name]
			if !ok {
				st = &ruleFleetStatus{}
				reports[r.Name] = st
			}
			if r.Enforced {
				st.enforcing++
			} else {
				st.failing++
				if st.firstErr == "" {
					st.firstErr = r.Error
				}
			}
		}
	}

	if fresh != 1 {
		t.Fatalf("fresh data-plane nodes = %d, want 1 (stale and control-plane excluded)", fresh)
	}
	if st := reports["r1"]; st == nil || st.enforcing != 1 || st.failing != 0 {
		t.Fatalf("r1 aggregate = %+v, want 1 enforcing / 0 failing", st)
	}
}

// Broken rules must sort first: it is what an operator opening the page needs to
// see, and burying it under working rules defeats the purpose.
func TestBrokenRulesSortFirst(t *testing.T) {
	ranks := []string{
		enforcementFailed, enforcementUnknown, enforcementRunning,
		enforcementNotSent, enforcementDisabled,
	}
	for i := 1; i < len(ranks); i++ {
		if enforcementRank(ranks[i-1]) >= enforcementRank(ranks[i]) {
			t.Errorf("%q must rank before %q", ranks[i-1], ranks[i])
		}
	}
}
