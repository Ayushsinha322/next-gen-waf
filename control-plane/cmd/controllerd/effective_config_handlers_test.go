package main

import "testing"

func TestDiffJSONFindsDroppedNestedKeyAndDefaults(t *testing.T) {
	pushed := toJSON(map[string]any{
		"id": "juice", "domains": []string{"a", "b"},
		"waf": map[string]any{"mode": "blocking", "paranoia_level": 2, "graphql": map[string]any{"max_depth": 8}},
	})
	applied := toJSON(map[string]any{
		"id": "juice", "domains": []string{"a", "b"},
		"waf": map[string]any{"mode": "blocking", "paranoia_level": 2, "graphql": map[string]any{"max_depth": 12}, "anomaly_threshold": 5},
	})
	d := diffJSON(pushed, applied)
	got := map[string]DiffEntry{}
	for _, e := range d {
		got[e.Path] = e
	}
	if len(d) != 2 {
		t.Fatalf("expected 2 differences, got %d: %+v", len(d), d)
	}
	if e := got["waf.graphql.max_depth"]; e.Pushed != float64(8) || e.Applied != float64(12) {
		t.Fatalf("nested value change not reported: %+v", e)
	}
	if e := got["waf.anomaly_threshold"]; e.Pushed != "(not sent)" || e.Applied != float64(5) {
		t.Fatalf("data-plane default must show as not sent: %+v", e)
	}
}

func TestDiffJSONIdenticalIsEmptyAndRedactionMatchesDataPlane(t *testing.T) {
	v := toJSON(map[string]any{"waf": map[string]any{"jwt": map[string]any{"hs_secret": "x", "issuer": "i"}}})
	if d := diffJSON(v, v); len(d) != 0 {
		t.Fatalf("identical trees must not differ: %+v", d)
	}
	r := redactJSON(toJSON(map[string]any{"waf": map[string]any{"jwt": map[string]any{"hs_secret": "x", "issuer": "i"}}})).(map[string]any)
	jwt := r["waf"].(map[string]any)["jwt"].(map[string]any)
	if jwt["hs_secret"] != "***" || jwt["issuer"] != "i" {
		t.Fatalf("hs_secret must be redacted and issuer kept: %+v", jwt)
	}
}
