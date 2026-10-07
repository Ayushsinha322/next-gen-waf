package main

import (
	"encoding/json"
	"testing"
)

// The console's "Force HTTPS" (on by default) was stored and read by nothing.
// It now reaches the data plane as tls.redirect_http.
func TestForceHTTPSReachesTheDataPlane(t *testing.T) {
	cases := []struct {
		policy string
		want   bool
	}{
		{`{}`, true}, // a script- or API-created site gets the console's default
		{`{"frontend":{"https":true}}`, true},
		{`{"frontend":{"force_https":true}}`, true},
		{`{"frontend":{"force_https":false}}`, false},
		{`{"frontend":{"force_https":false},"tls":{"mode":"auto","email":"ops@example.in"}}`, false},
	}
	for _, tc := range cases {
		tls := buildRustSiteTLS(json.RawMessage(tc.policy))
		if got, ok := tls["redirect_http"].(bool); !ok || got != tc.want {
			t.Errorf("%s: redirect_http = %v, want %v", tc.policy, tls["redirect_http"], tc.want)
		}
		if tls["mode"] == nil {
			t.Errorf("%s: the tls mode was lost: %v", tc.policy, tls)
		}
	}
}
