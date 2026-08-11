package main

import (
	"encoding/json"
	"testing"
)

// WebSocket support is a per-site security control, and it has to survive the
// trip from the API payload into the data-plane config.
//
// It previously did not exist on that path at all: buildRustUpstream forwarded
// only servers / load_balancer / health_check / timeout_secs, so the whole
// `upstream.proxy` object — including `websocket` — was stored, echoed back to
// the UI as though it had been applied, and dropped. The data plane then
// upgraded on any origin 101 regardless, meaning a site that had switched
// WebSockets OFF still got a full bidirectional relay.
func TestBuildRustUpstreamCarriesWebsocketTrue(t *testing.T) {
	up, err := buildRustUpstream(json.RawMessage(
		`{"servers":["10.0.0.5:8080"],"proxy":{"websocket":true,"keepalive":true}}`))
	if err != nil {
		t.Fatalf("buildRustUpstream: %v", err)
	}
	got, ok := up["websocket"]
	if !ok {
		t.Fatal("websocket was dropped — the data plane could not honour the setting")
	}
	if got != true {
		t.Fatalf("websocket = %v, want true", got)
	}
}

// False must be forwarded explicitly, not omitted. The Rust field defaults to
// false, so omitting would happen to work — but then "the operator turned this
// off" and "the key was missing" would arrive identically, and a future change
// to that default would silently flip live sites.
func TestBuildRustUpstreamCarriesWebsocketFalse(t *testing.T) {
	up, err := buildRustUpstream(json.RawMessage(
		`{"servers":["10.0.0.5:8080"],"proxy":{"websocket":false}}`))
	if err != nil {
		t.Fatalf("buildRustUpstream: %v", err)
	}
	got, ok := up["websocket"]
	if !ok {
		t.Fatal("websocket must be emitted even when false, so the enforced value is the chosen one")
	}
	if got != false {
		t.Fatalf("websocket = %v, want false", got)
	}
}

// A site created before this key existed must resolve to false. Defaulting to
// true would re-open the fail-open relay on every pre-existing site the moment
// this shipped, which is the opposite of the point.
func TestBuildRustUpstreamDefaultsWebsocketOffForLegacyConfig(t *testing.T) {
	for name, raw := range map[string]string{
		"no proxy block": `{"servers":["10.0.0.5:8080"]}`,
		"empty proxy":    `{"servers":["10.0.0.5:8080"],"proxy":{}}`,
		"other keys only": `{"servers":["10.0.0.5:8080"],` +
			`"proxy":{"keepalive":true,"read_timeout":"60s"}}`,
		"empty upstream": `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			up, err := buildRustUpstream(json.RawMessage(raw))
			if err != nil {
				t.Fatalf("buildRustUpstream: %v", err)
			}
			got, ok := up["websocket"]
			if !ok {
				t.Fatal("websocket key must always be present")
			}
			if got != false {
				t.Fatalf("websocket = %v, want false for a config that never asked for it", got)
			}
		})
	}
}

// Guard the boundary this bug lived on: the keys the data plane actually reads.
// The other `upstream.proxy` fields are deliberately NOT forwarded and their
// wizard controls are disabled to match. If someone forwards one here without
// adding the data-plane code to read it, that is the same silently-inert defect
// returning, so this test fails until both halves land together.
func TestBuildRustUpstreamForwardsOnlyImplementedKeys(t *testing.T) {
	up, err := buildRustUpstream(json.RawMessage(`{
		"servers":["10.0.0.5:8080"],
		"load_balancer":"least_conn",
		"timeout_secs":90,
		"health_check":{"path":"/healthz"},
		"proxy":{"websocket":true,"keepalive":true,"connect_timeout":"5s",
		         "read_timeout":"60s","host_header":"app.internal",
		         "ssl_sni":true,"ssl_sni_name":"backend.example.com"}
	}`))
	if err != nil {
		t.Fatalf("buildRustUpstream: %v", err)
	}

	implemented := map[string]bool{
		"servers": true, "load_balancer": true, "health_check": true,
		"timeout_secs": true, "websocket": true,
	}
	for k := range up {
		if !implemented[k] {
			t.Errorf("unexpected key %q in the data-plane upstream config: "+
				"forward a key only together with the code that reads it", k)
		}
	}

	// And the inert ones must not have leaked through under their own names.
	for _, k := range []string{
		"keepalive", "connect_timeout", "read_timeout",
		"host_header", "ssl_sni", "ssl_sni_name", "proxy",
	} {
		if _, present := up[k]; present {
			t.Errorf("%q reached the data-plane config but nothing reads it — "+
				"either implement it or leave it out", k)
		}
	}
}
