package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/rbac"
)

// The inspection limits reach the data plane only through buildRustWaf's
// allowlist: a key it does not name is stored, echoed to the console, and
// dropped on the way, with the data plane silently applying its defaults.
func TestBuildRustWafForwardsInspectionLimits(t *testing.T) {
	waf, err := buildRustWaf(json.RawMessage(`{
		"mode": "blocking",
		"max_inspected_args": 3000,
		"max_inspected_arg_bytes": 2097152,
		"inspection_time_budget_ms": 0
	}`))
	if err != nil {
		t.Fatalf("buildRustWaf: %v", err)
	}
	for key, want := range map[string]any{
		"max_inspected_args":        uint32(3000),
		"max_inspected_arg_bytes":   uint64(2097152),
		"inspection_time_budget_ms": uint32(0), // 0 = off, forwarded, not dropped
	} {
		got, ok := waf[key]
		if !ok {
			t.Fatalf("%s missing from the data-plane config: %#v", key, waf)
		}
		if got != want {
			t.Fatalf("%s = %#v, want %#v", key, got, want)
		}
	}
	for _, k := range []string{"max_inspected_args", "max_inspected_arg_bytes", "inspection_time_budget_ms"} {
		if _, ok := knownWafPolicyKeys[k]; !ok {
			t.Fatalf("buildRustWaf forwards %q but knownWafPolicyKeys omits it", k)
		}
	}
}

// Absent means the data plane's defaults, which it applies only when the key
// is absent: an emitted zero would turn the limit off.
func TestBuildRustWafOmitsAbsentInspectionLimits(t *testing.T) {
	waf, err := buildRustWaf(json.RawMessage(`{"mode":"blocking"}`))
	if err != nil {
		t.Fatalf("buildRustWaf: %v", err)
	}
	for _, k := range []string{"max_inspected_args", "max_inspected_arg_bytes", "inspection_time_budget_ms"} {
		if v, present := waf[k]; present {
			t.Fatalf("%s should be omitted when unset, got %#v", k, v)
		}
	}
}

func TestValidateWafPolicyValuesBoundsInspectionLimits(t *testing.T) {
	cases := []struct {
		name      string
		policy    string
		wantField string // "" = no problem expected
	}{
		{"ordinary values", `{"max_inspected_args": 4096, "max_inspected_arg_bytes": 524288, "inspection_time_budget_ms": 10000}`, ""},
		{"0 turns every limit off", `{"max_inspected_args": 0, "max_inspected_arg_bytes": 0, "inspection_time_budget_ms": 0}`, ""},
		{"the caps themselves", `{"max_inspected_args": 100000, "max_inspected_arg_bytes": 16777216, "inspection_time_budget_ms": 60000}`, ""},
		{"the budget floor itself", `{"inspection_time_budget_ms": 100}`, ""},
		{"negative args", `{"max_inspected_args": -1}`, "waf_policy.max_inspected_args"},
		{"args past the cap", `{"max_inspected_args": 100001}`, "waf_policy.max_inspected_args"},
		{"bytes past the cap", `{"max_inspected_arg_bytes": 1e12}`, "waf_policy.max_inspected_arg_bytes"},
		{"a budget past the cap", `{"inspection_time_budget_ms": 3600000}`, "waf_policy.inspection_time_budget_ms"},
		{"seconds typed into the milliseconds field", `{"inspection_time_budget_ms": 5}`, "waf_policy.inspection_time_budget_ms"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			problems := validateWafPolicyValues(json.RawMessage(tc.policy))
			if tc.wantField == "" {
				if len(problems) != 0 {
					t.Fatalf("expected no problems, got %v", problems)
				}
				return
			}
			for _, p := range problems {
				if p.Field == tc.wantField {
					if !strings.Contains(p.Problem, "accepted") && !strings.Contains(p.Problem, "0 or more") {
						t.Fatalf("problem for %s does not say what is accepted: %q", p.Field, p.Problem)
					}
					return
				}
			}
			t.Fatalf("expected a problem on %s, got %v", tc.wantField, problems)
		})
	}
}

// A request refused for an inspection limit is recorded under a built-in rule
// id, so the learning report lists it like a rule, with a Disable button. An
// exclusion of it would be stored and change nothing — the refusal is not a
// compiled rule — so both ways of adding one refuse it and name the setting
// that does govern it.
func TestInspectionLimitRefusalsCannotBeExcluded(t *testing.T) {
	for id, setting := range map[int]string{
		9900401: "max_inspected_args",
		9900402: "max_inspected_arg_bytes",
		9900403: "inspection_time_budget_ms",
	} {
		msg := inspectionLimitExclusionProblem(id)
		if !strings.Contains(msg, setting) {
			t.Fatalf("rule %d: %q does not name %s", id, msg, setting)
		}
	}
	if msg := inspectionLimitExclusionProblem(942100); msg != "" {
		t.Fatalf("a real rule must stay excludable, got %q", msg)
	}

	// Through the site policy.
	problems := validateWafPolicyValues(json.RawMessage(`{"rule_exclusions": [
		{"rule_id": 942100, "disable": true},
		{"rule_id": 9900402, "disable": true}]}`))
	if len(problems) != 1 || problems[0].Field != "waf_policy.rule_exclusions" ||
		!strings.Contains(problems[0].Problem, "max_inspected_arg_bytes") {
		t.Fatalf("expected one problem naming max_inspected_arg_bytes, got %v", problems)
	}
	// A list of an unexpected shape is the converter's to report, and must not
	// switch off the other checks.
	problems = validateWafPolicyValues(json.RawMessage(
		`{"rule_exclusions": [{"rule_id": "x"}], "max_inspected_args": -1}`))
	if len(problems) != 1 || problems[0].Field != "waf_policy.max_inspected_args" {
		t.Fatalf("expected only the max_inspected_args problem, got %v", problems)
	}

	// Through the learning report's one-click action. The store is down, so a
	// request that got past the check would answer 404 instead.
	exclude := func(ruleID string) *httptest.ResponseRecorder {
		gin.SetMode(gin.TestMode)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/sites/s1/exclusions",
			bytes.NewBufferString(`{"rule_id": `+ruleID+`, "disable": true}`))
		c.Request.Header.Set("Content-Type", "application/json")
		c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), auth.ClaimsKey,
			&auth.Claims{TenantID: db.DevTenantID, UserID: db.DevAdminID, Role: "owner"}))
		c.Params = gin.Params{{Key: "id", Value: "s1"}}
		handleAddSiteExclusion(c, rbac.NewEnforcer(), db.NewStore(failingPool{}), nil, nil)
		return w
	}
	if w := exclude("9900401"); w.Code != http.StatusBadRequest ||
		!strings.Contains(w.Body.String(), "max_inspected_args") {
		t.Fatalf("excluding 9900401: %d %s", w.Code, w.Body.String())
	}
	if w := exclude("942100"); w.Code == http.StatusBadRequest {
		t.Fatalf("excluding a real rule was refused: %s", w.Body.String())
	}
}

// inspectionLimitRuleSettings is a copy of what the data plane records: the
// built-in rule id of each inspection limit (InspectionLimit::rule_id in
// sentinel-core) and the setting that limit is for (InspectionLimit::setting).
// If the two drift, the exclusion guard lets the data plane's real ids through
// again — an exclusion stored that changes nothing — and its message names a
// setting that is not the one to raise. This reads the Rust and compares.
func TestInspectionLimitRuleSettingsMatchTheDataPlane(t *testing.T) {
	src, err := os.ReadFile("../../../crates/sentinel-core/src/context.rs")
	if err != nil {
		t.Skipf("data-plane sources not present: %v", err)
	}
	arms := func(fn string) map[string]string {
		re := regexp.MustCompile(`(?s)pub const fn ` + fn + `\(self\) -> &'static str \{\s*match self \{(.*?)\}`)
		m := re.FindSubmatch(src)
		if m == nil {
			t.Fatalf("InspectionLimit::%s not found in context.rs", fn)
		}
		out := map[string]string{}
		for _, arm := range regexp.MustCompile(`Self::(\w+) => "([^"]*)"`).FindAllSubmatch(m[1], -1) {
			out[string(arm[1])] = string(arm[2])
		}
		if len(out) == 0 {
			t.Fatalf("InspectionLimit::%s has no arms this test can read", fn)
		}
		return out
	}
	ids, settings := arms("rule_id"), arms("setting")

	dataPlane := map[int]string{}
	for variant, id := range ids {
		setting, ok := settings[variant]
		if !ok {
			t.Fatalf("InspectionLimit::%s has a rule id but no setting", variant)
		}
		n, err := strconv.Atoi(id)
		if err != nil {
			t.Fatalf("InspectionLimit::%s rule id %q is not a number", variant, id)
		}
		dataPlane[n] = setting
	}
	if !reflect.DeepEqual(dataPlane, inspectionLimitRuleSettings) {
		t.Fatalf("inspectionLimitRuleSettings = %v, but the data plane records %v",
			inspectionLimitRuleSettings, dataPlane)
	}
}
