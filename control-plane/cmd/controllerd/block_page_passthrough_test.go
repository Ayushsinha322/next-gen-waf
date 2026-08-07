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
