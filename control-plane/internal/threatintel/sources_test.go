package threatintel

import (
	"strings"
	"testing"
)

// The built-in UA seed is a substring blocklist on a spoofable header, so the
// contents are a policy decision, not an implementation detail. This test
// pins the two rules in the doc comment: no generic words that collide with
// legitimate software, and no scanners a customer authorises against their own
// site. It fails loudly when someone adds one, which is the point.
func TestBuiltinBadUserAgentsStayHighSignal(t *testing.T) {
	iocs, err := builtinBadUserAgents()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, i := range iocs {
		if i.Type != "user_agent" {
			t.Errorf("%q has type %q, want user_agent", i.Value, i.Type)
		}
		v := i.Value
		if v != strings.ToLower(v) {
			t.Errorf("%q must be lower-case: the data plane lowercases the header before matching", v)
		}
		if len(v) < 4 {
			t.Errorf("%q is too short to be a safe substring match", v)
		}
		if seen[v] {
			t.Errorf("%q is listed twice", v)
		}
		seen[v] = true
	}
	// Names that collide with legitimate software or with authorised scanning.
	for _, banned := range []string{"medusa", "brutus", "qualys", "appscan", "burp", "curl", "python", "go-http-client", "java", "wget"} {
		if seen[banned] {
			t.Errorf("%q must not be a built-in block indicator — see the rules on builtinBadUserAgents", banned)
		}
	}
	// The tools the 2026-09-07 live probe showed walking through.
	for _, want := range []string{"commix", "wfuzz", "ffuf", "w3af"} {
		if !seen[want] {
			t.Errorf("expected %q in the built-in seed", want)
		}
	}
	// A substring indicator must not be a prefix of another one: the shorter
	// entry makes the longer one dead weight and hides what is really matching.
	for a := range seen {
		for b := range seen {
			if a != b && strings.Contains(b, a) {
				t.Errorf("%q is a substring of %q — drop the longer entry, it can never be the reported match", a, b)
			}
		}
	}
}
