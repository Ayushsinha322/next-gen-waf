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
		"timeout_secs": true, "websocket": true, "keepalive": true,
		"host_header": true, "connect_timeout_secs": true, "sni_name": true,
	}
	for k := range up {
		if !implemented[k] {
			t.Errorf("unexpected key %q in the data-plane upstream config: "+
				"forward a key only together with the code that reads it", k)
		}
	}

	// Raw dashboard-side spellings must NOT leak through. The data plane reads
	// `connect_timeout_secs` and `sni_name`; forwarding `connect_timeout` ("5s") or
	// `ssl_sni_name` under their UI names would deserialize to nothing and be inert
	// again, which is exactly the bug being closed.
	for _, k := range []string{
		"connect_timeout", "read_timeout", "ssl_sni", "ssl_sni_name", "proxy",
	} {
		if _, present := up[k]; present {
			t.Errorf("%q reached the data-plane config under its UI name, which "+
				"nothing reads — translate it or leave it out", k)
		}
	}
}

// The four controls that used to be stored-and-dropped must now arrive, in the
// spelling the Rust side deserializes.
func TestBuildRustUpstreamCarriesTheFormerlyInertControls(t *testing.T) {
	up, err := buildRustUpstream(json.RawMessage(`{
		"servers":["10.0.0.5:8443"],
		"connect_timeout_secs":5,
		"proxy":{"keepalive":false,"host_header":"app.internal",
		         "ssl_sni":true,"ssl_sni_name":"backend.example.com"}
	}`))
	if err != nil {
		t.Fatalf("buildRustUpstream: %v", err)
	}
	for k, want := range map[string]any{
		"keepalive":            false,
		"host_header":          "app.internal",
		"connect_timeout_secs": uint64(5),
		"sni_name":             "backend.example.com",
	} {
		got, ok := up[k]
		if !ok {
			t.Errorf("%q was dropped — the data plane cannot honour it", k)
			continue
		}
		if got != want {
			t.Errorf("%s = %v (%T), want %v (%T)", k, got, got, want, want)
		}
	}
}

// Keep-alive defaults to TRUE when absent, unlike websocket. A legacy config that
// never mentioned it was getting connection reuse; reading silence as "off" would
// add a TCP+TLS handshake to every request on every existing site.
func TestBuildRustUpstreamKeepaliveDefaultsOnForLegacyConfig(t *testing.T) {
	for name, raw := range map[string]string{
		"no proxy block": `{"servers":["10.0.0.5:8080"]}`,
		"empty proxy":    `{"servers":["10.0.0.5:8080"],"proxy":{}}`,
		"other keys":     `{"servers":["10.0.0.5:8080"],"proxy":{"websocket":true}}`,
	} {
		t.Run(name, func(t *testing.T) {
			up, err := buildRustUpstream(json.RawMessage(raw))
			if err != nil {
				t.Fatalf("buildRustUpstream: %v", err)
			}
			if up["keepalive"] != true {
				t.Fatalf("keepalive = %v, want true for a config that never set it",
					up["keepalive"])
			}
		})
	}
}

// A blank host_header is "not set", not "send an empty Host" — some origins
// reject an empty Host outright.
func TestBuildRustUpstreamOmitsBlankHostHeader(t *testing.T) {
	for name, raw := range map[string]string{
		"empty":      `{"servers":["10.0.0.5:8080"],"proxy":{"host_header":""}}`,
		"whitespace": `{"servers":["10.0.0.5:8080"],"proxy":{"host_header":"   "}}`,
	} {
		t.Run(name, func(t *testing.T) {
			up, err := buildRustUpstream(json.RawMessage(raw))
			if err != nil {
				t.Fatalf("buildRustUpstream: %v", err)
			}
			if _, present := up["host_header"]; present {
				t.Fatal("a blank host_header must be omitted, not forwarded")
			}
		})
	}
}

// SNI needs BOTH the toggle and a name. Either alone is not an intent to
// override, and forwarding half of it would present something nobody chose.
func TestBuildRustUpstreamSniRequiresToggleAndName(t *testing.T) {
	for name, raw := range map[string]string{
		"name without toggle": `{"servers":["10.0.0.5:8443"],"proxy":{"ssl_sni_name":"b.example.com"}}`,
		"toggle without name": `{"servers":["10.0.0.5:8443"],"proxy":{"ssl_sni":true}}`,
		"toggle off":          `{"servers":["10.0.0.5:8443"],"proxy":{"ssl_sni":false,"ssl_sni_name":"b.example.com"}}`,
		"blank name":          `{"servers":["10.0.0.5:8443"],"proxy":{"ssl_sni":true,"ssl_sni_name":"  "}}`,
	} {
		t.Run(name, func(t *testing.T) {
			up, err := buildRustUpstream(json.RawMessage(raw))
			if err != nil {
				t.Fatalf("buildRustUpstream: %v", err)
			}
			if _, present := up["sni_name"]; present {
				t.Fatalf("sni_name must not be forwarded for %q", name)
			}
		})
	}
}

// Clamped at the API edge as well as in the data plane, so a bad value is
// rejected where it is entered rather than relying on the far side.
func TestBuildRustUpstreamClampsAbsurdConnectTimeout(t *testing.T) {
	up, err := buildRustUpstream(json.RawMessage(
		`{"servers":["10.0.0.5:8080"],"connect_timeout_secs":99999}`))
	if err != nil {
		t.Fatalf("buildRustUpstream: %v", err)
	}
	if up["connect_timeout_secs"] != maxUpstreamConnectTimeoutSecs {
		t.Fatalf("connect_timeout_secs = %v, want clamp to %d",
			up["connect_timeout_secs"], maxUpstreamConnectTimeoutSecs)
	}
}
