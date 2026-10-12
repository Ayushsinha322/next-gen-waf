package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/your-org/sentinel-waf/control-plane/internal/db"
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
	// Detection posture must agree: that pair (threshold 10 + the default
	// exclusions) is the benchmarked configuration, and a site whose stored
	// policy says one thing while the data plane is handed another is the exact
	// drift e7b3249 existed to stop.
	if stored["anomaly_threshold"] != built["anomaly_threshold"] {
		t.Errorf("anomaly_threshold: stored default %v != build default %v — the two have drifted",
			stored["anomaly_threshold"], built["anomaly_threshold"])
	}

	// Paranoia is deliberately different too, for the same fail-safe reason as
	// mode below. A NEW site gets the level measured on real traffic (PL1: 6.2%
	// of legitimate requests blocked on open-appsec's dataset, against 38.8% at
	// PL2, for under one point of detection). A stored row with NO level keeps
	// being read as PL2: lowering an existing site's protection is a decision for
	// its operator, not a side effect of an upgrade.
	if fmt.Sprint(stored["paranoia_level"]) != "1" {
		t.Errorf("a new site must be stored at paranoia level 1, got %v", stored["paranoia_level"])
	}
	if fmt.Sprint(built["paranoia_level"]) != "2" {
		t.Errorf("a row with no level must keep being read as paranoia 2, got %v", built["paranoia_level"])
	}

	// Mode is DELIBERATELY different, and the difference is not drift — the two
	// values answer different questions:
	//
	//   defaultWafPolicyJSON  what to STORE for a brand-new site created with no
	//                         policy. Learning, because a caller who sent no
	//                         policy has not decided one, and enforcing against
	//                         an unmeasured false-positive rate blocks real
	//                         users on someone else's application.
	//   buildRustWaf(nil)     how to INTERPRET a stored row that has no policy
	//                         at all — a legacy or hand-inserted row. Blocking,
	//                         because such a site has been enforcing all along
	//                         and silently switching it to observe-only would
	//                         disable protection nobody asked to disable.
	//
	// Fail-safe therefore points in opposite directions for the two cases. This
	// asserts both, so neither can be "tidied" into the other by someone who
	// reads only one of them.
	if stored["mode"] != "learning" {
		t.Errorf("a new site created with no policy must be stored as learning, got %v",
			stored["mode"])
	}
	if built["mode"] != "blocking" {
		t.Errorf("a stored row with NO policy must still be interpreted as blocking "+
			"(it has been enforcing; do not silently disable it), got %v", built["mode"])
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

// Per-path overrides: the passthrough must survive buildRustWaf, and validation
// must REJECT the two knobs that cannot be honoured per path rather than
// accepting them and silently ignoring them.

func TestPathOverridesReachTheDataPlane(t *testing.T) {
	policy := json.RawMessage(`{"mode":"blocking","path_overrides":[
		{"path_prefix":"/api/","anomaly_threshold":3},
		{"path_prefix":"/assets/","mode":"off"}
	]}`)
	waf, err := buildRustWaf(policy)
	if err != nil {
		t.Fatalf("buildRustWaf: %v", err)
	}
	ov, ok := waf["path_overrides"].([]map[string]any)
	if !ok {
		t.Fatalf("path_overrides has type %T, want []map[string]any", waf["path_overrides"])
	}
	if len(ov) != 2 {
		t.Fatalf("got %d overrides, want 2", len(ov))
	}
	if ov[0]["path_prefix"] != "/api/" {
		t.Errorf("first override prefix = %v, want /api/", ov[0]["path_prefix"])
	}
	if ov[1]["mode"] != "off" {
		t.Errorf("second override mode = %v, want off", ov[1]["mode"])
	}
}

func TestNoPathOverridesKeyWhenNoneSet(t *testing.T) {
	waf, err := buildRustWaf(json.RawMessage(`{"mode":"blocking"}`))
	if err != nil {
		t.Fatalf("buildRustWaf: %v", err)
	}
	if _, present := waf["path_overrides"]; present {
		t.Error("path_overrides must be absent, not an empty array, when unset")
	}
}

func TestPathOverrideValidationRejectsUnhonourableKnobs(t *testing.T) {
	cases := []struct {
		name       string
		policy     string
		wantSubstr string
	}{
		{"per-path paranoia", `{"path_overrides":[{"path_prefix":"/a/","paranoia_level":3}]}`, "paranoia_level"},
		{"per-path exclusions", `{"path_overrides":[{"path_prefix":"/a/","rule_exclusions":[{"rule_id":1}]}]}`, "rule_exclusions"},
		{"empty prefix", `{"path_overrides":[{"path_prefix":"","mode":"off"}]}`, "path_prefix"},
		{"no leading slash", `{"path_overrides":[{"path_prefix":"api/","mode":"off"}]}`, "path_prefix"},
		{"query string in prefix", `{"path_overrides":[{"path_prefix":"/a/?x=1","mode":"off"}]}`, "path_prefix"},
		{"duplicate prefix", `{"path_overrides":[{"path_prefix":"/a/","mode":"off"},{"path_prefix":"/a/","mode":"learning"}]}`, "more than once"},
		{"bad mode", `{"path_overrides":[{"path_prefix":"/a/","mode":"paranoid"}]}`, "blocking, learning, off"},
		{"zero threshold", `{"path_overrides":[{"path_prefix":"/a/","anomaly_threshold":0}]}`, "must be >= 1"},
		{"no effect", `{"path_overrides":[{"path_prefix":"/a/"}]}`, "no effect"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			problems := validateWafPolicyValues(json.RawMessage(tc.policy))
			if len(problems) == 0 {
				t.Fatalf("expected a validation problem mentioning %q, got none", tc.wantSubstr)
			}
			var all string
			for _, p := range problems {
				all += p.Field + " " + p.Problem + "\n"
			}
			if !strings.Contains(all, tc.wantSubstr) {
				t.Errorf("problems did not mention %q:\n%s", tc.wantSubstr, all)
			}
		})
	}
}

func TestValidPathOverridesPass(t *testing.T) {
	policy := json.RawMessage(`{"mode":"blocking","anomaly_threshold":10,"path_overrides":[
		{"path_prefix":"/api/","anomaly_threshold":3},
		{"path_prefix":"/api/admin/","mode":"blocking","anomaly_threshold":2},
		{"path_prefix":"/assets/","mode":"off"},
		{"path_prefix":"/legacy/","mode":"learning"}
	]}`)
	if problems := validateWafPolicyValues(policy); len(problems) != 0 {
		t.Errorf("valid overrides were rejected: %+v", problems)
	}
}

// Rule scoping. A rule with no site_id is deployment-wide (the virtual-patch
// case); one with a site_id must reach only that site. Getting this backwards
// either leaks an app-specific rule across every site or silently drops a
// virtual patch, so both directions are pinned.

func inlineNames(t *testing.T, rs map[string]any) []string {
	t.Helper()
	waf, ok := rs["waf"].(map[string]any)
	if !ok {
		t.Fatalf("no waf block")
	}
	raw, present := waf["inline_rules"]
	if !present {
		return nil
	}
	list, ok := raw.([]map[string]any)
	if !ok {
		t.Fatalf("inline_rules has type %T", raw)
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		out = append(out, e["name"].(string))
	}
	return out
}

func siteScopeFixture(t *testing.T) []db.DeployableRule {
	t.Helper()
	return []db.DeployableRule{
		{Name: "wide-virtual-patch", DSL: "rule 1 { }", SiteID: ""},
		{Name: "only-site-a", DSL: "rule 2 { }", SiteID: "site-a"},
		{Name: "only-site-b", DSL: "rule 3 { }", SiteID: "site-b"},
	}
}

func TestDeploymentWideRuleReachesEverySite(t *testing.T) {
	for _, site := range []string{"site-a", "site-b", "site-c"} {
		rs := map[string]any{"waf": map[string]any{"mode": "blocking"}}
		attachInlineRules(rs, site, siteScopeFixture(t))
		names := inlineNames(t, rs)
		found := false
		for _, n := range names {
			if n == "wide-virtual-patch" {
				found = true
			}
		}
		if !found {
			t.Errorf("site %s did not receive the deployment-wide rule (got %v)", site, names)
		}
	}
}

func TestSiteScopedRuleReachesOnlyThatSite(t *testing.T) {
	rsA := map[string]any{"waf": map[string]any{"mode": "blocking"}}
	attachInlineRules(rsA, "site-a", siteScopeFixture(t))
	namesA := inlineNames(t, rsA)

	rsB := map[string]any{"waf": map[string]any{"mode": "blocking"}}
	attachInlineRules(rsB, "site-b", siteScopeFixture(t))
	namesB := inlineNames(t, rsB)

	has := func(list []string, want string) bool {
		for _, n := range list {
			if n == want {
				return true
			}
		}
		return false
	}
	if !has(namesA, "only-site-a") {
		t.Errorf("site-a missing its own rule: %v", namesA)
	}
	if has(namesA, "only-site-b") {
		t.Errorf("site-a received site-b's rule — scoping leaked: %v", namesA)
	}
	if !has(namesB, "only-site-b") {
		t.Errorf("site-b missing its own rule: %v", namesB)
	}
	if has(namesB, "only-site-a") {
		t.Errorf("site-b received site-a's rule — scoping leaked: %v", namesB)
	}
	if len(namesA) != 2 || len(namesB) != 2 {
		t.Errorf("each site should get exactly 2 rules (wide + own), got a=%v b=%v", namesA, namesB)
	}
}

func TestModeOffSiteGetsNoInlineRules(t *testing.T) {
	rs := map[string]any{"waf": map[string]any{"mode": "off"}}
	attachInlineRules(rs, "site-a", siteScopeFixture(t))
	if names := inlineNames(t, rs); len(names) != 0 {
		t.Errorf("a mode=off site must receive no rules, got %v", names)
	}
}

func TestEmptyDSLIsNotDelivered(t *testing.T) {
	rs := map[string]any{"waf": map[string]any{"mode": "blocking"}}
	attachInlineRules(rs, "site-a", []db.DeployableRule{
		{Name: "blank", DSL: "   ", SiteID: ""},
	})
	if names := inlineNames(t, rs); len(names) != 0 {
		t.Errorf("a blank DSL must not be delivered, got %v", names)
	}
}

// The console's wizard is a THIRD source of a site's initial posture, alongside
// defaultWafPolicyJSON here and first-site.sh. It has drifted twice: the form
// held anomaly_threshold 5 while the pre-selected "Balanced" tile advertised 10
// (applyPreset only runs on click), so every wizard-created site ran half the
// benchmarked threshold — and it defaulted to blocking while every document and
// the CLI said learning-first.
//
// This reads the actual TypeScript and fails if the two sources disagree. A
// comment asking future readers to "keep the two in step" did not prevent the
// drift; a test does.
func TestWizardDefaultsMatchControlPlaneDefaults(t *testing.T) {
	src, err := os.ReadFile("../../../dashboard/lib/siteConfig.ts")
	if err != nil {
		t.Skipf("dashboard sources not present: %v", err)
	}
	text := string(src)

	// 1. The wizard must not hardcode a threshold in emptyForm — it must derive
	//    it from the preset, which is what makes drift impossible rather than
	//    merely corrected.
	if !strings.Contains(text, "anomaly_threshold: PRESETS.balanced.anomaly_threshold") {
		t.Error("emptyForm() should derive anomaly_threshold from PRESETS.balanced, " +
			"not restate it — a literal is how the form and the selected preset " +
			"drifted apart before")
	}

	// 2. The balanced preset's threshold must equal this package's default.
	var wafDefault struct {
		Mode      string `json:"mode"`
		Threshold int    `json:"anomaly_threshold"`
		Paranoia  int    `json:"paranoia_level"`
	}
	if err := json.Unmarshal([]byte(defaultWafPolicyJSON), &wafDefault); err != nil {
		t.Fatalf("defaultWafPolicyJSON does not parse: %v", err)
	}
	want := fmt.Sprintf("anomaly_threshold: %d", wafDefault.Threshold)
	if !strings.Contains(text, want) {
		t.Errorf("PRESETS.balanced must use the control plane's threshold (%q not found in siteConfig.ts)", want)
	}

	// 3. A new site must default to learning. Enforcing on day one blocks real
	//    users against a false-positive rate nobody has measured, and it is the
	//    opposite of what first-site.sh and the runbook do.
	if !strings.Contains(text, `mode: "learning"`) {
		t.Error(`emptyForm() must default mode to "learning" — the CLI path and every ` +
			`operator document soak first and enforce afterwards`)
	}

	// 4. The old fallback installed threshold 5 when the field was left empty,
	//    which reintroduced the un-benchmarked posture through the back door.
	if strings.Contains(text, "Number(f.anomaly_threshold) || 5") {
		t.Error("formToPayload still falls back to threshold 5; an empty field must " +
			"fall back to the benchmarked default")
	}
}

// A site created with no policy must ship with the recon paths locked down.
//
// The default anomaly threshold of 10 means no single CRS rule ever blocks: a
// CRITICAL detection scores 5. Observed live on .71 — a scanner requesting
// /.git/config, /.env and /.env.production fired rule 930130 for a score of 5
// each and was passed straight to the origin. These prefixes carry no
// legitimate traffic, so they get a lower threshold rather than the whole site.
func TestDefaultPolicyLocksDownReconPaths(t *testing.T) {
	stored, err := buildRustWaf(json.RawMessage(defaultWafPolicyJSON))
	if err != nil {
		t.Fatalf("buildRustWaf(defaultWafPolicyJSON): %v", err)
	}
	raw, ok := stored["path_overrides"]
	if !ok {
		t.Fatal("default policy has no path_overrides — recon paths are not covered. " +
			"buildRustWaf is an ALLOWLIST: a key it does not name is stored, echoed " +
			"back and silently dropped, so this must be asserted, not assumed.")
	}
	ov, ok := raw.([]map[string]any)
	if !ok {
		t.Fatalf("path_overrides has type %T, want []map[string]any", raw)
	}

	got := map[string]bool{}
	for _, o := range ov {
		p, _ := o["path_prefix"].(string)
		got[p] = true
		if th, ok := o["anomaly_threshold"]; !ok {
			t.Errorf("override %q sets no anomaly_threshold, so it does nothing", p)
		} else if n, ok := th.(int); ok && n > 5 {
			t.Errorf("override %q threshold %d is not stricter than a CRITICAL rule's 5", p, n)
		}
	}
	for _, want := range []string{"/.git", "/.env", "/.svn", "/.aws", "/.ssh", "/.htpasswd"} {
		if !got[want] {
			t.Errorf("default policy does not lock down %q", want)
		}
	}

	// /.well-known/ is legitimate and load-bearing: ACME HTTP-01 challenges are
	// served from it. A blanket "/." prefix would break certificate issuance,
	// which is why these are enumerated.
	for p := range got {
		if strings.HasPrefix("/.well-known/acme-challenge/x", p) {
			t.Errorf("override %q also covers /.well-known/ — that would break ACME", p)
		}
	}
}

// The real-traffic tuning defaults (open-appsec dataset, 2026-10-12) reach every
// site that sets nothing for those rules.
func TestRealTrafficTuningDefaultsReachEverySite(t *testing.T) {
	waf, err := buildRustWaf(json.RawMessage(`{"mode":"blocking"}`))
	if err != nil {
		t.Fatalf("buildRustWaf: %v", err)
	}
	excl, _ := waf["rule_exclusions"].([]map[string]any)
	find := func(id int) map[string]any {
		for _, e := range excl {
			if ruleIDEquals(e["rule_id"], id) {
				return e
			}
		}
		return nil
	}
	if e := find(932270); e == nil || e["disable"] != true {
		t.Errorf("932270 not disabled by default: %+v", e)
	}
	if e := find(930120); e == nil || fmt.Sprint(e["exclude_targets"]) != "[ARGS_NAMES]" {
		t.Errorf("930120 not limited to values by default: %+v", e)
	}
	for _, id := range []int{942100, 9900100} {
		e := find(id)
		if e == nil || !strings.Contains(fmt.Sprint(e["exclude_targets"]), "ARGS:us_privacy") {
			t.Errorf("%d does not skip the IAB consent strings by default: %+v", id, e)
		}
	}
}
