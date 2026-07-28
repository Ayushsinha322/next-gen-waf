package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/your-org/sentinel-waf/control-plane/internal/db"
)

// Reporting whether a rule is actually RUNNING, as opposed to merely stored.
//
// "enabled" in the rules table has repeatedly meant "stored", and the gap between
// the two is this codebase's most persistent defect: DLP was configured but never
// wired into the data-plane config, the custom coverage rules were never in the
// category map, and operator-authored rules were stored with compiled bytecode
// and never delivered at all. In each case a surface reported protection that did
// not exist.
//
// The control plane cannot answer the question itself — it has no SRL compiler,
// which is deliberate, because a second parser would drift from the real one. The
// data plane owns the compiler, so it reports per-rule outcomes on its heartbeat
// and this joins them back by name.
//
// The status is therefore an OBSERVATION with a timestamp, never an inference.
// When no node has reported recently we say so rather than guessing, because a
// confident wrong answer here is exactly the failure being fixed.

// How stale a node's heartbeat may be before its report is ignored. The data
// plane heartbeats every 10s; a minute allows several misses without flapping.
const enforcementReportMaxAge = time.Minute

// Enforcement states. Deliberately not booleans: "we do not know" is a distinct
// and honest answer, and collapsing it into false would report a working rule as
// broken every time a node restarts.
const (
	enforcementRunning  = "enforced"     // a node confirms it is compiled and live
	enforcementFailed   = "not_enforced" // a node compiled the config and rejected this rule
	enforcementDisabled = "disabled"     // operator turned it off; nothing to report
	enforcementNotSent  = "not_deployed" // excluded from delivery by design (crs/community)
	enforcementUnknown  = "unknown"      // no fresh node report to rely on
)

// annotatedRule is a rule plus what the fleet says about it. RuleRow is embedded
// so every existing field the dashboard reads is unchanged.
type annotatedRule struct {
	db.RuleRow
	Enforcement      string `json:"enforcement"`
	EnforcementError string `json:"enforcement_error,omitempty"`
	EnforcementNote  string `json:"enforcement_note,omitempty"`
	NodesEnforcing   int    `json:"nodes_enforcing"`
	NodesReporting   int    `json:"nodes_reporting"`
}

// nodeInlineReport is the slice of heartbeat metadata this cares about.
type nodeInlineReport struct {
	InlineRules []struct {
		Name     string `json:"name"`
		Enforced bool   `json:"enforced"`
		Error    string `json:"error"`
	} `json:"inline_rules"`
}

// ruleFleetStatus is the aggregate across nodes for one rule name.
type ruleFleetStatus struct {
	enforcing int
	failing   int
	firstErr  string
}

// collectRuleReports reads fresh data-plane heartbeats and aggregates their
// per-rule outcomes. Returns the aggregate plus how many nodes were fresh enough
// to count, so a caller can distinguish "no node says it is running" from "no
// node has said anything".
func collectRuleReports(ctx context.Context, store *db.Store) (map[string]*ruleFleetStatus, int) {
	out := make(map[string]*ruleFleetStatus)
	if store == nil {
		return out, 0
	}
	nodes, err := store.ListNodes(ctx)
	if err != nil {
		return out, 0
	}
	fresh := 0
	for _, n := range nodes {
		// Data-plane nodes only: a control-plane node compiles nothing.
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
			st, ok := out[r.Name]
			if !ok {
				st = &ruleFleetStatus{}
				out[r.Name] = st
			}
			if r.Enforced {
				st.enforcing++
				continue
			}
			st.failing++
			if st.firstErr == "" {
				st.firstErr = r.Error
			}
		}
	}
	return out, fresh
}

// annotateRuleEnforcement decorates each rule with its observed fleet state.
func annotateRuleEnforcement(ctx context.Context, store *db.Store, rules []db.RuleRow) []annotatedRule {
	reports, freshNodes := collectRuleReports(ctx, store)

	out := make([]annotatedRule, 0, len(rules))
	for _, r := range rules {
		a := annotatedRule{RuleRow: r, NodesReporting: freshNodes}

		switch {
		case !r.Enabled:
			// Nothing to observe, and saying "unknown" about a rule the operator
			// switched off would read as a fault.
			a.Enforcement = enforcementDisabled

		case r.Source == "crs" || r.Source == "community":
			// Excluded from delivery on purpose — see migration 0017. Real CRS
			// rules reach the data plane as files, and these demo rows reuse
			// their ids. Saying "not enforced" without the reason would look
			// like a bug.
			a.Enforcement = enforcementNotSent
			a.EnforcementNote = fmt.Sprintf(
				"rules with source %q are not delivered to the data plane; the shipped "+
					"OWASP CRS is loaded from files instead", r.Source)

		case freshNodes == 0:
			a.Enforcement = enforcementUnknown
			a.EnforcementNote = "no data-plane node has reported within the last minute"

		default:
			st := reports[r.Name]
			switch {
			case st == nil:
				// Nodes are reporting and none mentioned this rule. Most often the
				// rule was created after their last config fetch.
				a.Enforcement = enforcementUnknown
				a.EnforcementNote = "not yet reported by any node; it may not have been " +
					"picked up in a config sync yet"
			case st.failing > 0:
				// A single node rejecting it is enough to surface: the DSL is the
				// same everywhere, so a failure anywhere is a failure.
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

	// Surface the problems first: a broken rule is what an operator opening this
	// page needs to see, and it should not be buried below working ones.
	sort.SliceStable(out, func(i, j int) bool {
		return enforcementRank(out[i].Enforcement) < enforcementRank(out[j].Enforcement)
	})
	return out
}

func enforcementRank(s string) int {
	switch s {
	case enforcementFailed:
		return 0
	case enforcementUnknown:
		return 1
	case enforcementRunning:
		return 2
	case enforcementNotSent:
		return 3
	default: // disabled
		return 4
	}
}
