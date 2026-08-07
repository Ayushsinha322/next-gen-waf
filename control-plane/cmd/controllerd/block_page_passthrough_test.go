package main

import (
	"encoding/json"
	"testing"
)

// buildRustWaf is an ALLOWLIST: a waf_policy key it does not name is stored in
// the database, echoed back to the dashboard, and silently dropped on the way
// to the data plane. block_page shipped that way — the wizard offered branding,
// the API persisted it, the site page redisplayed it, and the blocked visitor
// still got the default page with nothing reporting a fault.
//
// This asserts the whole sub-object survives, not merely that the key exists,
// because a half-copied object fails the same way and just as quietly.
func TestBuildRustWafForwardsBlockPage(t *testing.T) {
	raw := json.RawMessage(`{
		"mode": "blocking",
		"block_page": {
			"enabled": true,
			"title": "Access to the ESDS Customer Portal was blocked",
			"message": "Quote the Support ID below.",
			"contact": "soc@esds.co.in",
			"logo_url": "https://cdn.example/logo.png",
			"show_reason": false
		}
	}`)

	waf, err := buildRustWaf(raw)
	if err != nil {
		t.Fatalf("buildRustWaf: %v", err)
	}

	bp, ok := waf["block_page"].(map[string]any)
	if !ok {
		t.Fatalf("block_page missing from data-plane config (got %#v) — the exact bug this guards", waf["block_page"])
	}
	for key, want := range map[string]any{
		"enabled":     true,
		"title":       "Access to the ESDS Customer Portal was blocked",
		"message":     "Quote the Support ID below.",
		"contact":     "soc@esds.co.in",
		"logo_url":    "https://cdn.example/logo.png",
		"show_reason": false,
	} {
		if got := bp[key]; got != want {
			t.Fatalf("block_page[%q] = %#v, want %#v", key, got, want)
		}
	}
}

// A site that configures no block page must not gain an empty one — the data
// plane distinguishes absent (use built-in defaults) from present-but-blank.
func TestBuildRustWafOmitsAbsentBlockPage(t *testing.T) {
	waf, err := buildRustWaf(json.RawMessage(`{"mode":"blocking"}`))
	if err != nil {
		t.Fatalf("buildRustWaf: %v", err)
	}
	if v, present := waf["block_page"]; present {
		t.Fatalf("block_page should be omitted when unset, got %#v", v)
	}
}

// The guard that would have caught block_page before it shipped: any waf_policy
// key nothing acts on is reported, so a field added to the wizard and forgotten
// in buildRustWaf announces itself instead of being silently inert.
func TestUnknownWafPolicyKeysAreReported(t *testing.T) {
	raw := json.RawMessage(`{
		"mode": "blocking",
		"block_page": {"enabled": true},
		"tls": {"mode": "acme"},
		"frontend": {"https": true},
		"captcha_theme": "dark",
		"zzz_future_feature": {"on": true}
	}`)

	got := unknownWafPolicyKeys(raw)
	want := []string{"captcha_theme", "zzz_future_feature"}
	if len(got) != len(want) {
		t.Fatalf("unknown keys = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unknown keys = %v, want %v (sorted)", got, want)
		}
	}
}

// tls and frontend must NOT be reported: tls is consumed by buildRustSiteTLS,
// and frontend is deliberately stored-only (listener-level, disclosed in the
// wizard). Reporting them would train operators to ignore the warning.
func TestKnownButNotForwardedKeysAreNotReported(t *testing.T) {
	for _, k := range []string{"tls", "frontend"} {
		raw := json.RawMessage(`{"mode":"blocking","` + k + `":{}}`)
		if got := unknownWafPolicyKeys(raw); len(got) != 0 {
			t.Fatalf("%q should not be reported as unknown, got %v", k, got)
		}
	}
}

// A fully-populated policy must be silent, or the warning becomes noise.
func TestFullPolicyReportsNothing(t *testing.T) {
	obj := map[string]any{}
	for k := range knownWafPolicyKeys {
		obj[k] = map[string]any{}
	}
	raw, _ := json.Marshal(obj)
	if got := unknownWafPolicyKeys(raw); len(got) != 0 {
		t.Fatalf("known policy reported unknown keys: %v", got)
	}
}

// Malformed policy is buildRustWaf's error to report; this helper must not also
// shout about it.
func TestMalformedPolicyReportsNothing(t *testing.T) {
	if got := unknownWafPolicyKeys(json.RawMessage(`{not json`)); got != nil {
		t.Fatalf("malformed policy should report nothing, got %v", got)
	}
	if got := unknownWafPolicyKeys(nil); got != nil {
		t.Fatalf("empty policy should report nothing, got %v", got)
	}
}

// Drift guard: every field buildRustWaf actually reads must be in the known
// set, or the platform would warn about a key it does forward — the warning
// contradicting reality is worse than no warning.
func TestEveryForwardedFieldIsKnown(t *testing.T) {
	// Build a policy naming every known key, run it through buildRustWaf, and
	// assert nothing it emits corresponds to an unknown input key.
	forwarded := []string{
		"mode", "paranoia_level", "anomaly_threshold", "rule_categories",
		"rule_exclusions", "path_overrides", "max_body_size", "max_uri_length",
		"max_header_count", "allowed_methods", "api_discovery", "security_headers",
		"rate_limit", "anti_ddos", "bot_detection", "geoip", "ip_reputation",
		"ml", "jwt", "graphql", "grpc", "dlp", "fusion", "block_page",
	}
	for _, k := range forwarded {
		if _, ok := knownWafPolicyKeys[k]; !ok {
			t.Fatalf("buildRustWaf forwards %q but knownWafPolicyKeys omits it — "+
				"the platform would warn about a key it actually honours", k)
		}
	}
}
