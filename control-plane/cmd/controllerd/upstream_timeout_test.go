package main

import (
	"encoding/json"
	"testing"
)

// The per-site upstream timeout exists so one slow app (report generation,
// bulk export) does not force every other site on the node to wait as long.
// It must survive the trip from the API payload to the data-plane config.
func TestBuildRustUpstreamCarriesTimeout(t *testing.T) {
	up, err := buildRustUpstream(json.RawMessage(
		`{"servers":["10.0.0.5:8080"],"load_balancer":"round_robin","timeout_secs":180}`))
	if err != nil {
		t.Fatalf("buildRustUpstream: %v", err)
	}
	got, ok := up["timeout_secs"]
	if !ok {
		t.Fatal("timeout_secs was dropped — the data plane would silently use the default")
	}
	if got != uint64(180) {
		t.Fatalf("timeout_secs = %v, want 180", got)
	}
}

// Absent or zero must OMIT the key rather than send 0. A zero handed to the
// Rust side would read as "no override", so sending it is merely noise — but
// omitting keeps "unset" and "explicitly zero" from ever diverging.
func TestBuildRustUpstreamOmitsUnsetTimeout(t *testing.T) {
	for name, raw := range map[string]string{
		"absent": `{"servers":["10.0.0.5:8080"]}`,
		"zero":   `{"servers":["10.0.0.5:8080"],"timeout_secs":0}`,
	} {
		t.Run(name, func(t *testing.T) {
			up, err := buildRustUpstream(json.RawMessage(raw))
			if err != nil {
				t.Fatalf("buildRustUpstream: %v", err)
			}
			if _, ok := up["timeout_secs"]; ok {
				t.Fatal("timeout_secs should be omitted so the node default applies")
			}
		})
	}
}

// An unbounded wait would pin a request task, and its admission permit, on a
// hung origin — the failure mode the timeout exists to prevent. Clamp instead
// of trusting the caller.
func TestBuildRustUpstreamClampsAbsurdTimeout(t *testing.T) {
	up, err := buildRustUpstream(json.RawMessage(
		`{"servers":["10.0.0.5:8080"],"timeout_secs":86400}`))
	if err != nil {
		t.Fatalf("buildRustUpstream: %v", err)
	}
	if up["timeout_secs"] != maxUpstreamTimeoutSecs {
		t.Fatalf("timeout_secs = %v, want clamp to %d", up["timeout_secs"], maxUpstreamTimeoutSecs)
	}
}
