package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// The first real deployment stored max_body_size=1048576000000 (976 GB — a byte
// count typed into a megabyte field) and max_uri_length=819200 through the
// console, and the control plane accepted both. The API and scripts never see
// the console's checks, so the bound has to live here too.
func TestValidateWafPolicyValuesBoundsRequestLimits(t *testing.T) {
	cases := []struct {
		name      string
		policy    string
		wantField string // "" = no problem expected
	}{
		{"the UAT body limit is refused", `{"max_body_size": 1048576000000}`, "waf_policy.max_body_size"},
		{"the UAT URI limit is refused", `{"max_uri_length": 819200}`, "waf_policy.max_uri_length"},
		{"absurd header count is refused", `{"max_header_count": 5000}`, "waf_policy.max_header_count"},
		{"negative body limit is refused", `{"max_body_size": -1}`, "waf_policy.max_body_size"},
		{"a value too large for an integer is still judged", `{"max_body_size": 1e30}`, "waf_policy.max_body_size"},
		{"50 MB is fine", `{"max_body_size": 52428800}`, ""},
		{"exactly the body cap is fine", `{"max_body_size": 10737418240}`, ""},
		{"0 means unlimited and is a legal choice", `{"max_body_size": 0, "max_uri_length": 0}`, ""},
		{"SSO-sized URI limit is fine", `{"max_uri_length": 16384, "max_header_count": 200}`, ""},
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
					if !strings.Contains(p.Problem, "largest accepted") && !strings.Contains(p.Problem, "0 or more") {
						t.Fatalf("problem for %s does not say what is accepted: %q", p.Field, p.Problem)
					}
					return
				}
			}
			t.Fatalf("expected a problem on %s, got %v", tc.wantField, problems)
		})
	}
}
