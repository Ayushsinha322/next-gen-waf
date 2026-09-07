package main

import (
	"encoding/json"
	"testing"
)

// The bundled catalogue must parse with the SAME validator an upload goes
// through, name the two shipped examples, and declare their host calls
// truthfully — the page shows those permissions as the sandbox contract.
func TestBundledCatalogParsesAndDeclaresHostCalls(t *testing.T) {
	entries, parsed, bad := loadCatalog()
	if len(bad) != 0 {
		t.Fatalf("bundled archives failed validation: %v", bad)
	}
	want := map[string]bool{"scanner-guard": false, "hello-world": false}
	for _, e := range entries {
		if _, ok := want[e.Name]; ok {
			want[e.Name] = true
		}
		if e.SizeBytes < 1000 || e.SizeBytes > 1<<20 {
			t.Errorf("%s: implausible wasm size %d", e.Name, e.SizeBytes)
		}
		if len(parsed[e.Name].wasm) != e.SizeBytes {
			t.Errorf("%s: size mismatch", e.Name)
		}
		var perms map[string]bool
		if err := json.Unmarshal(e.Permissions, &perms); err != nil {
			t.Fatalf("%s: permissions not JSON: %v", e.Name, err)
		}
		if e.Name == "scanner-guard" {
			for _, p := range []string{"host_get_req_header", "host_set_decision", "host_add_score", "host_log"} {
				if !perms[p] {
					t.Errorf("scanner-guard must declare %s", p)
				}
			}
			if perms["host_http_callout"] || perms["host_kv_set"] {
				t.Errorf("scanner-guard declares host calls it does not use: %v", perms)
			}
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("catalogue is missing %s", name)
		}
	}
}
