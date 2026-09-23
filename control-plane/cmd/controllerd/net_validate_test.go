package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func problemsFor(t *testing.T, policy string) []SiteConfigProblem {
	t.Helper()
	return validateWafPolicyValues(json.RawMessage(policy))
}

// The audit's two silently-inert entries, refused at save time.
func TestBadNetworkListEntriesAreRefused(t *testing.T) {
	cases := []struct {
		policy, field, want string
	}{
		{`{"geoip":{"block_countries":["USA"]}}`, "waf_policy.geoip.block_countries", `did you mean "US"`},
		{`{"geoip":{"allow_countries":["UK"]}}`, "waf_policy.geoip.allow_countries", `did you mean "GB"`},
		{`{"geoip":{"block_countries":["Mars"]}}`, "waf_policy.geoip.block_countries", "two-letter"},
		{`{"ip_reputation":{"block":["not-an-ip"]}}`, "waf_policy.ip_reputation.block", "not an IP address"},
		{`{"ip_reputation":{"allow":["10.0.0.0/33"]}}`, "waf_policy.ip_reputation.allow", "not an IP address"},
	}
	for _, c := range cases {
		ps := problemsFor(t, c.policy)
		if len(ps) != 1 || ps[0].Field != c.field || !strings.Contains(ps[0].Problem, c.want) {
			t.Errorf("%s: got %+v, want one problem on %s mentioning %q", c.policy, ps, c.field, c.want)
		}
	}
}

// What the data plane accepts must be accepted here — above all the bare IP, the
// form operators type and the wizard's own placeholder.
func TestGoodNetworkListEntriesPass(t *testing.T) {
	for _, pol := range []string{
		`{"geoip":{"block_countries":["US","cn","XK"],"allow_countries":[]}}`,
		`{"ip_reputation":{"block":["203.0.113.7","203.0.113.0/24","2001:db8::5","2001:db8::/32"," 10.1.2.3 "],"allow":["10.0.0.0/8"]}}`,
	} {
		if ps := problemsFor(t, pol); len(ps) != 0 {
			t.Errorf("%s: unexpected problems %+v", pol, ps)
		}
	}
}

func TestTheCountryListIsComplete(t *testing.T) {
	if n := len(isoCountrySet); n != 250 {
		t.Fatalf("isoCountrySet has %d codes, want 250 (249 ISO 3166-1 + XK)", n)
	}
}
