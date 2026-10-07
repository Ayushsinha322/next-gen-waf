package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// The site wizard pre-filled 127.0.0.1:8080, the data plane's own listener, and
// validation accepted it: one unedited save made the WAF proxy to itself.
func TestAnOriginThatIsTheWAFItselfIsRefused(t *testing.T) {
	t.Setenv("SENTINEL_ALLOW_LOOPBACK_UPSTREAM", "")
	waf := json.RawMessage(`{"mode":"learning"}`)
	for _, host := range []string{"127.0.0.1", "::1", "[::1]", "0.0.0.0", "localhost", "dataplane", "waf2"} {
		up := json.RawMessage(`{"servers":[{"host":"` + host + `","port":8080}]}`)
		problems := validateSiteConfig("s", []string{"s.example.in"}, up, waf)
		found := false
		for _, p := range problems {
			found = found || strings.Contains(p.Problem, "this WAF node itself")
		}
		if !found {
			t.Errorf("origin %q was accepted: %+v", host, problems)
		}
	}
	for _, host := range []string{"10.0.0.5", "app.internal", "juiceshop"} {
		up := json.RawMessage(`{"servers":[{"host":"` + host + `","port":8080}]}`)
		for _, p := range validateSiteConfig("s", []string{"s.example.in"}, up, waf) {
			if strings.Contains(p.Problem, "this WAF node itself") {
				t.Errorf("a real origin %q was refused", host)
			}
		}
	}
	t.Setenv("SENTINEL_ALLOW_LOOPBACK_UPSTREAM", "1")
	up := json.RawMessage(`{"servers":[{"host":"127.0.0.1","port":3000}]}`)
	for _, p := range validateSiteConfig("s", []string{"s.example.in"}, up, waf) {
		if strings.Contains(p.Problem, "this WAF node itself") {
			t.Error("the development opt-in did not allow a same-host origin")
		}
	}
}
