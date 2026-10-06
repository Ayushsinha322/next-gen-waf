package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

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
// maxSitePlugins caps per-site plugin selection. Every selected module runs in
// the request path for that site, so this is a latency budget, not a storage one.
const maxSitePlugins = 16

// validateSitePluginNames rejects a policy that names a plugin this tenant has
// not installed — almost always a typo, and one that would otherwise show up
// only as a /healthz "unresolved" entry after the config had already shipped.
//
// Naming an installed-but-DISABLED plugin is allowed on purpose: selecting the
// site first and enabling the module second is exactly how a staged rollout
// works. Until it is enabled the data plane reports it unresolved and does not
// run it.
func validateSitePluginNames(c *gin.Context, store *db.Store, tenantID, userID string, wafPolicy json.RawMessage) []SiteConfigProblem {
	names := siteEnabledPlugins(wafPolicy)
	if len(names) == 0 || store == nil {
		return nil
	}
	installed, err := store.ListPlugins(c.Request.Context(), tenantID, userID)
	if err != nil {
		// Do not fail the write on a read error: the shape checks already ran,
		// and the data plane reports an unknown name at /healthz.
		return nil
	}
	have := make(map[string]bool, len(installed))
	disabled := make(map[string]bool, len(installed))
	for _, p := range installed {
		have[p.Name] = true
		if !p.Enabled {
			disabled[p.Name] = true
		}
	}
	var problems []SiteConfigProblem
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" || have[n] {
			continue
		}
		problems = append(problems, SiteConfigProblem{
			Field:   "waf_policy.enabled_plugins",
			Problem: fmt.Sprintf("%q is not an installed plugin — install it from the Plugins page first (installed: %s)", n, strings.Join(pluginNames(installed), ", ")),
		})
	}
	return problems
}

func pluginNames(rows []db.PluginRow) []string {
	if len(rows) == 0 {
		return []string{"none"}
	}
	out := make([]string, 0, len(rows))
	for _, p := range rows {
		out = append(out, p.Name)
	}
	return out
}

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
	seen := make(map[string]int, len(domains))
	for i, d := range domains {
		d = strings.TrimSpace(d)
		switch {
		case d == "":
			add(fmt.Sprintf("domains[%d]", i), "must not be empty")
		case strings.ContainsAny(d, " /\\?#"):
			add(fmt.Sprintf("domains[%d]", i), fmt.Sprintf("%q is not a bare hostname (no scheme, path, or spaces)", d))
		default:
			// Host matching is case-insensitive, so "App.example.com" and
			// "app.example.com" are the same claim.
			key := strings.ToLower(d)
			if first, dup := seen[key]; dup {
				add(fmt.Sprintf("domains[%d]", i),
					fmt.Sprintf("%q is already listed at domains[%d]", d, first))
			} else {
				seen[key] = i
			}
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
		Mode             *string  `json:"mode"`
		EnabledPlugins   []string `json:"enabled_plugins"`
		ParanoiaLevel    *int     `json:"paranoia_level"`
		AnomalyThreshold *int     `json:"anomaly_threshold"`
		// float64 so ANY JSON number is judged here; an integer field would fail
		// to unmarshal on an absurd value and skip every check in this function.
		MaxBodySize    *float64 `json:"max_body_size"`
		MaxURILength   *float64 `json:"max_uri_length"`
		MaxHeaderCount *float64 `json:"max_header_count"`
		GeoIP          *struct {
			BlockCountries []string `json:"block_countries"`
			AllowCountries []string `json:"allow_countries"`
		} `json:"geoip"`
		IPReputation *struct {
			Allow []string `json:"allow"`
			Block []string `json:"block"`
			// Raw so a malformed list is reported by feedProblems rather than
			// failing this whole unmarshal, which would skip every check here.
			Feeds json.RawMessage `json:"feeds"`
		} `json:"ip_reputation"`
		PathOverrides []struct {
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
		// Per-site plugin selection: shape only here; whether the named plugin is
		// actually installed needs the database and is checked by
		// validateSitePluginNames at the handler.
		if len(p.EnabledPlugins) > maxSitePlugins {
			add("waf_policy.enabled_plugins", fmt.Sprintf("names %d plugins; the limit is %d per site", len(p.EnabledPlugins), maxSitePlugins))
		}
		seenPlugin := map[string]bool{}
		for _, n := range p.EnabledPlugins {
			trimmed := strings.TrimSpace(n)
			switch {
			case trimmed == "":
				add("waf_policy.enabled_plugins", "contains an empty plugin name")
			case len(trimmed) > 100:
				add("waf_policy.enabled_plugins", "contains a plugin name longer than 100 characters")
			case seenPlugin[trimmed]:
				add("waf_policy.enabled_plugins", fmt.Sprintf("lists %q twice", trimmed))
			}
			seenPlugin[trimmed] = true
		}
	}
	if p.ParanoiaLevel != nil && (*p.ParanoiaLevel < 1 || *p.ParanoiaLevel > 4) {
		add("waf_policy.paranoia_level", fmt.Sprintf("must be 1-4, got %d", *p.ParanoiaLevel))
	}
	if p.AnomalyThreshold != nil && *p.AnomalyThreshold < 1 {
		add("waf_policy.anomaly_threshold",
			fmt.Sprintf("must be >= 1, got %d — a threshold of 0 or less blocks every request", *p.AnomalyThreshold))
	}

	// Request-limit bounds. Mirrors LIMIT_CAPS in dashboard/lib/siteConfig.ts —
	// the console checks first for an immediate message; this is the authority,
	// because the API and scripts never see the console.
	//
	// Written after the first real deployment stored a 976 GB body limit (a byte
	// count typed into a megabyte field) and an 819200-byte URI limit, and nothing
	// refused either. Bodies are buffered for inspection, so a body "limit" that
	// large is no limit and an open door to memory exhaustion. 0 stays legal: the
	// data plane reads it as "unlimited", which is a choice, not a typo.
	checkLimit := func(field string, v *float64, max float64, why string) {
		if v == nil {
			return
		}
		switch {
		case *v < 0:
			add(field, fmt.Sprintf("must be 0 or more, got %v", *v))
		case *v > max:
			add(field, fmt.Sprintf("is %.0f; the largest accepted is %.0f — %s", *v, max, why))
		}
	}
	checkLimit("waf_policy.max_body_size", p.MaxBodySize, maxSiteBodyBytes,
		"request bodies are held in memory while inspected, so a limit this large is no limit "+
			"(a byte count typed into a megabyte field is the usual cause)")
	checkLimit("waf_policy.max_uri_length", p.MaxURILength, maxSiteURIBytes,
		"nginx and Apache refuse request lines past 8 KiB and APISIX past 32 KiB, so a larger "+
			"limit protects nothing; SSO redirects need 16384")
	checkLimit("waf_policy.max_header_count", p.MaxHeaderCount, maxSiteHeaders,
		"browsers send 15-25 headers")

	// Network lists. Refused rather than stored: the data plane skips an entry it
	// cannot parse with nothing but a WARN, so a bad entry saved here is a
	// control the console shows as set and nothing enforces.
	if p.GeoIP != nil {
		for field, list := range map[string][]string{
			"waf_policy.geoip.block_countries": p.GeoIP.BlockCountries,
			"waf_policy.geoip.allow_countries": p.GeoIP.AllowCountries,
		} {
			for _, c := range list {
				if m := countryCodeProblem(c); m != "" {
					add(field, m)
				}
			}
		}
	}
	if p.IPReputation != nil {
		for field, list := range map[string][]string{
			"waf_policy.ip_reputation.allow": p.IPReputation.Allow,
			"waf_policy.ip_reputation.block": p.IPReputation.Block,
		} {
			for _, e := range list {
				if m := ipEntryProblem(e); m != "" {
					add(field, m)
				}
			}
		}
		problems = append(problems, feedProblems(p.IPReputation.Feeds)...)
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

// maxFeedURLLength bounds an IP-reputation feed URL, which is synced to and
// logged by every data-plane node. 2048 leaves ample room for a long path plus
// an access-key query string.
const maxFeedURLLength = 2048

// feedProblems checks waf_policy.ip_reputation.feeds.
//
// Every data-plane node fetches each feed URL itself, so a URL is held to what
// that fetcher accepts: http or https, with a host. Nothing refused a file://
// URL here, and the data plane used to read it off the node's own disk.
//
// The list's shape is checked as well: ip_reputation reaches the data plane
// verbatim and is parsed with the rest of the site, so a feed it cannot read
// (no url, or a url that is not a string) makes it reject the entire site — a
// new site is not served at all, an existing one stays on its last config.
func feedProblems(raw json.RawMessage) []SiteConfigProblem {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	const field = "waf_policy.ip_reputation.feeds"
	var feeds []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &feeds); err != nil {
		return []SiteConfigProblem{{Field: field,
			Problem: `must be a list of feeds, each an object like {"url": "https://…"}`}}
	}
	var problems []SiteConfigProblem
	for i, f := range feeds {
		urlField := fmt.Sprintf("%s[%d].url", field, i)
		rawURL, ok := f["url"]
		if !ok || string(rawURL) == "null" {
			problems = append(problems, SiteConfigProblem{Field: urlField, Problem: "is required"})
			continue
		}
		var u string
		if err := json.Unmarshal(rawURL, &u); err != nil {
			problems = append(problems, SiteConfigProblem{Field: urlField, Problem: "must be a string"})
			continue
		}
		if m := feedURLProblem(u); m != "" {
			problems = append(problems, SiteConfigProblem{Field: urlField, Problem: m})
		}
	}
	return problems
}

// feedURLProblem says what is wrong with one feed URL, or "" if nothing.
func feedURLProblem(raw string) string {
	u := strings.TrimSpace(raw)
	if u == "" {
		return "must not be empty — remove the feed instead"
	}
	if len(u) > maxFeedURLLength {
		return fmt.Sprintf("is %d characters; the longest accepted is %d", len(u), maxFeedURLLength)
	}
	shown := u
	if r := []rune(u); len(r) > 100 {
		shown = string(r[:100]) + "…"
	}
	// Go's parser tolerates a space in the path; the data plane's does not, and
	// the feed would fail on every node at every refresh.
	if strings.ContainsAny(u, " \t") {
		return fmt.Sprintf("%q contains a space — percent-encode it as %%20", shown)
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return fmt.Sprintf("%q is not a valid URL", shown)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Sprintf("%q is not an http:// or https:// URL — feeds are fetched over HTTP(S) only; "+
			"file:// and other schemes are refused", shown)
	}
	if parsed.Hostname() == "" {
		return fmt.Sprintf("%q has no host", shown)
	}
	if p := parsed.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return fmt.Sprintf("%q has port %s; ports are 1-65535", shown, p)
		}
	}
	return ""
}

// Upper bounds for a site's request limits. Kept identical to LIMIT_CAPS in
// dashboard/lib/siteConfig.ts; siteLimits.test.ts reads this file and fails if
// the two drift.
const (
	maxSiteBodyBytes = 10 * 1024 * 1024 * 1024 // 10 GiB
	maxSiteURIBytes  = 131072                  // 128 KiB
	maxSiteHeaders   = 1000
)

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

// domainConflicts reports domains already claimed by another site in the tenant.
//
// Nothing checked this. The data plane routes purely by Host header, so two
// sites claiming "portal.example.com" both matched and whichever the node
// happened to load last won — silently, with no error at create time and no way
// to tell from the console which policy was in force. On a shared internal node
// onboarding several applications that is the highest-consequence missing
// validation in the product: an operator can point a new site at a hostname an
// existing site already protects and quietly replace its policy.
//
// excludeSiteID lets an UPDATE keep its own domains without reporting itself.
// Comparison is case-insensitive because Host matching is.
func domainConflicts(existing []db.SiteRow, domains []string, excludeSiteID string) []SiteConfigProblem {
	claimed := make(map[string]string) // lowercase domain -> owning site name
	for _, row := range existing {
		if row.ID == excludeSiteID {
			continue
		}
		for _, d := range row.Domains {
			if d = strings.TrimSpace(d); d != "" {
				claimed[strings.ToLower(d)] = row.Name
			}
		}
	}
	var problems []SiteConfigProblem
	for i, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if owner, taken := claimed[strings.ToLower(d)]; taken {
			problems = append(problems, SiteConfigProblem{
				Field: fmt.Sprintf("domains[%d]", i),
				Problem: fmt.Sprintf(
					"%q is already served by site %q — the data plane routes by Host header, "+
						"so both sites would match and the policy actually applied would depend "+
						"on which node loaded last", d, owner),
			})
		}
	}
	return problems
}
