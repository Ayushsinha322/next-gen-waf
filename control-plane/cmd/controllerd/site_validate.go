package main

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/your-org/sentinel-waf/control-plane/internal/db"
)

// Site-configuration validation for the write path.
//
// Why this exists: /api/v1/internal/config converted every stored site to the
// data-plane shape and, on failure, did `continue` — silently DROPPING the site
// from the config the proxy received. A site with malformed upstream or waf_policy
// JSON therefore just vanished: no error, no log, no alert. Because that endpoint
// is node-global (one shared data plane serves every tenant), one tenant's bad
// record removed THEIR site from protection while the dashboard still showed it as
// active. A config error silently failed open.
//
// The durable fix is to reject the bad configuration at the point of write, so it
// cannot reach the database at all. Read-time reporting (see handleInternalConfig)
// remains as a backstop for records written before this validation existed.
//
// The validator deliberately runs the REAL conversion functions used by the sync
// rather than a parallel schema check. A separate validator would be free to drift
// from what the proxy actually requires, and the divergence would itself be the
// bug — a config that "validates" but still vanishes at sync time.

// SiteConfigProblem is one specific reason a site configuration is unusable.
type SiteConfigProblem struct {
	// Field is the JSON path of the offending input, e.g. "upstream.servers".
	Field string `json:"field"`
	// Problem is a human-readable description of what is wrong.
	Problem string `json:"problem"`
}

func (p SiteConfigProblem) String() string { return p.Field + ": " + p.Problem }

// validateSiteConfig checks that a site configuration will survive conversion to
// the data-plane shape and will actually protect something.
//
// Returns nil when the configuration is usable. `name` and `domains` may be empty
// for a partial update; pass the post-merge values when validating an update.
func validateSiteConfig(name string, domains []string, upstream, wafPolicy json.RawMessage) []SiteConfigProblem {
	var problems []SiteConfigProblem
	add := func(field, problem string) {
		problems = append(problems, SiteConfigProblem{Field: field, Problem: problem})
	}

	if strings.TrimSpace(name) == "" {
		add("name", "must not be empty — the data plane matches sites by name")
	}

	if len(domains) == 0 {
		add("domains", "at least one domain is required, or no traffic can route to this site")
	}
	for i, d := range domains {
		d = strings.TrimSpace(d)
		switch {
		case d == "":
			add(fmt.Sprintf("domains[%d]", i), "must not be empty")
		case strings.ContainsAny(d, " /\\?#"):
			add(fmt.Sprintf("domains[%d]", i), fmt.Sprintf("%q is not a bare hostname (no scheme, path, or spaces)", d))
		}
	}

	// Upstream: must parse into the data-plane shape AND name somewhere to send
	// traffic. An upstream with zero servers parses fine but is a black hole.
	if len(upstream) > 0 && !json.Valid(upstream) {
		add("upstream", "is not valid JSON")
	} else {
		rustUp, err := buildRustUpstream(upstream)
		if err != nil {
			// This is the exact error that used to make the site disappear.
			add("upstream", "cannot be converted to a data-plane upstream: "+err.Error())
		} else if servers, _ := rustUp["servers"].([]map[string]any); len(servers) == 0 {
			add("upstream.servers", "no upstream servers configured — requests to this site would have nowhere to go")
		} else {
			for i, srv := range servers {
				host, _ := srv["host"].(string)
				if strings.TrimSpace(host) == "" {
					add(fmt.Sprintf("upstream.servers[%d].host", i), "must not be empty")
				}
				port, ok := toInt(srv["port"])
				if !ok || port < 1 || port > 65535 {
					add(fmt.Sprintf("upstream.servers[%d].port", i),
						fmt.Sprintf("must be between 1 and 65535, got %v", srv["port"]))
				}
				// Catch a host:port pasted into the host field, which resolves to
				// nothing and is a common operator slip.
				if h, _, err := net.SplitHostPort(host); err == nil && h != "" {
					add(fmt.Sprintf("upstream.servers[%d].host", i),
						fmt.Sprintf("%q looks like host:port — put the port in the port field", host))
				}
			}
		}
	}

	// WAF policy: same treatment.
	if len(wafPolicy) > 0 && !json.Valid(wafPolicy) {
		add("waf_policy", "is not valid JSON")
	} else if _, err := buildRustWaf(wafPolicy); err != nil {
		add("waf_policy", "cannot be converted to a data-plane WAF policy: "+err.Error())
	} else {
		problems = append(problems, validateWafPolicyValues(wafPolicy)...)
	}

	return problems
}

// validateWafPolicyValues checks policy values that convert cleanly but are
// nonsensical, and would silently weaken or disable protection.
func validateWafPolicyValues(raw json.RawMessage) []SiteConfigProblem {
	if len(raw) == 0 {
		return nil
	}
	var p struct {
		Mode             *string `json:"mode"`
		ParanoiaLevel    *int    `json:"paranoia_level"`
		AnomalyThreshold *int    `json:"anomaly_threshold"`
		PathOverrides    []struct {
			PathPrefix       string          `json:"path_prefix"`
			Mode             *string         `json:"mode"`
			AnomalyThreshold *int            `json:"anomaly_threshold"`
			ParanoiaLevel    json.RawMessage `json:"paranoia_level"`
			RuleExclusions   json.RawMessage `json:"rule_exclusions"`
		} `json:"path_overrides"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil // shape errors are already reported by the converter
	}
	var problems []SiteConfigProblem
	add := func(f, m string) { problems = append(problems, SiteConfigProblem{Field: f, Problem: m}) }

	if p.Mode != nil {
		switch *p.Mode {
		case "blocking", "learning", "off":
		default:
			add("waf_policy.mode", fmt.Sprintf("%q is not one of blocking, learning, off", *p.Mode))
		}
	}
	if p.ParanoiaLevel != nil && (*p.ParanoiaLevel < 1 || *p.ParanoiaLevel > 4) {
		add("waf_policy.paranoia_level", fmt.Sprintf("must be 1-4, got %d", *p.ParanoiaLevel))
	}
	if p.AnomalyThreshold != nil && *p.AnomalyThreshold < 1 {
		add("waf_policy.anomaly_threshold",
			fmt.Sprintf("must be >= 1, got %d — a threshold of 0 or less blocks every request", *p.AnomalyThreshold))
	}

	// Per-path overrides. These are rejected rather than silently normalised: an
	// override an operator believes is protecting /api/ but which the data plane
	// ignores is the exact failure mode this codebase keeps producing.
	seen := make(map[string]bool, len(p.PathOverrides))
	for i, o := range p.PathOverrides {
		f := func(sub string) string {
			return fmt.Sprintf("waf_policy.path_overrides[%d].%s", i, sub)
		}
		switch {
		case o.PathPrefix == "":
			add(f("path_prefix"), "must not be empty — an empty prefix matches every request")
		case !strings.HasPrefix(o.PathPrefix, "/"):
			add(f("path_prefix"), fmt.Sprintf("%q must start with '/' — it is matched against the request path", o.PathPrefix))
		case strings.ContainsAny(o.PathPrefix, "?#"):
			add(f("path_prefix"), fmt.Sprintf("%q must not contain '?' or '#' — matching is against the path only, never the query string", o.PathPrefix))
		case seen[o.PathPrefix]:
			add(f("path_prefix"), fmt.Sprintf("%q is listed more than once", o.PathPrefix))
		}
		seen[o.PathPrefix] = true

		if o.Mode != nil {
			switch *o.Mode {
			case "blocking", "learning", "off":
			default:
				add(f("mode"), fmt.Sprintf("%q is not one of blocking, learning, off", *o.Mode))
			}
		}
		if o.AnomalyThreshold != nil && *o.AnomalyThreshold < 1 {
			add(f("anomaly_threshold"),
				fmt.Sprintf("must be >= 1, got %d — a threshold of 0 or less blocks every request", *o.AnomalyThreshold))
		}
		if o.Mode == nil && o.AnomalyThreshold == nil {
			add(f(""), "sets neither mode nor anomaly_threshold, so it would have no effect")
		}
		// paranoia_level and rule_exclusions are applied when the rule engine is
		// COMPILED, not per request, so a per-path value cannot be honoured. Say so
		// instead of accepting it and quietly doing nothing.
		if len(o.ParanoiaLevel) > 0 {
			add(f("paranoia_level"),
				"cannot be overridden per path — it selects which rules are compiled into the engine, so it is site-wide")
		}
		if len(o.RuleExclusions) > 0 {
			add(f("rule_exclusions"),
				"cannot be overridden per path — exclusions are applied when the engine is compiled, so they are site-wide")
		}
	}
	return problems
}

// toInt coerces the numeric forms that survive a JSON round-trip.
func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case json.Number:
		i, err := n.Int64()
		return int(i), err == nil
	default:
		return 0, false
	}
}

// validateSiteRow validates an already-stored site, for the read-time backstop.
func validateSiteRow(s db.SiteRow) []SiteConfigProblem {
	return validateSiteConfig(s.Name, s.Domains, s.Upstream, s.WafPolicy)
}

// mergedSiteForValidation applies a partial update to the current row so the
// result can be validated as a whole.
//
// Validating only the submitted fields would miss the case that matters: a patch
// that is individually fine but produces an unusable site when combined with what
// is already stored.
func mergedSiteForValidation(cur db.SiteRow, req db.UpdateSiteRequest) (string, []string, json.RawMessage, json.RawMessage) {
	name := cur.Name
	if req.Name != nil {
		name = *req.Name
	}
	domains := cur.Domains
	if req.Domains != nil {
		domains = req.Domains
	}
	upstream := cur.Upstream
	if len(req.Upstream) > 0 {
		upstream = req.Upstream
	}
	waf := cur.WafPolicy
	if len(req.WafPolicy) > 0 {
		waf = req.WafPolicy
	}
	return name, domains, upstream, waf
}
