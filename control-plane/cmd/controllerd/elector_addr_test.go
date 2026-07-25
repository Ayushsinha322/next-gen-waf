package main

import (
	"os"
	"testing"
)

// electorAdvertiseAddr replaced deriveRaftTopology, which computed a numeric Raft
// node ID and a full peer list from the StatefulSet pod ordinal. With leadership
// derived from a Postgres advisory lock there is no peer list and no node
// numbering to get wrong — a node only has to publish where writes should be
// forwarded to it.
func TestElectorAdvertiseAddr(t *testing.T) {
	tests := []struct {
		name      string
		env       map[string]string
		want      string
		wantHostP bool // when true, only assert it is host:port-shaped
	}{
		{
			name: "explicit override with port is used verbatim",
			env:  map[string]string{"SENTINEL_ADVERTISE_ADDR": "cp1.internal:9501"},
			want: "cp1.internal:9501",
		},
		{
			name: "explicit override without port gains the REST port",
			env: map[string]string{
				"SENTINEL_ADVERTISE_ADDR": "cp1.internal",
				"SENTINEL_REST_ADDR":      "0.0.0.0:9599",
			},
			want: "cp1.internal:9599",
		},
		{
			name: "StatefulSet pod + headless service yields stable per-pod DNS",
			env: map[string]string{
				"SENTINEL_POD_NAME":         "sentinel-controlplane-2",
				"SENTINEL_HEADLESS_SERVICE": "sentinel-controlplane-headless",
			},
			want: "sentinel-controlplane-2.sentinel-controlplane-headless:9501",
		},
		{
			name: "pod name alone is not enough — falls back to hostname",
			env: map[string]string{
				"SENTINEL_POD_NAME": "sentinel-controlplane-2",
			},
			wantHostP: true,
		},
		{
			name:      "nothing configured falls back to hostname",
			env:       map[string]string{},
			wantHostP: true,
		},
		{
			name: "REST port override is honoured for pod DNS",
			env: map[string]string{
				"SENTINEL_POD_NAME":          "cp-0",
				"SENTINEL_HEADLESS_SERVICE":  "cp-hl",
				"SENTINEL_CLUSTER_REST_PORT": "9600",
			},
			want: "cp-0.cp-hl:9600",
		},
	}

	// These variables are read by electorAdvertiseAddr / clusterRESTPort; clear
	// them all per case so the ambient environment cannot leak in.
	all := []string{
		"SENTINEL_ADVERTISE_ADDR", "SENTINEL_POD_NAME", "SENTINEL_HEADLESS_SERVICE",
		"SENTINEL_REST_ADDR", "SENTINEL_CLUSTER_REST_PORT",
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range all {
				t.Setenv(k, "")
				os.Unsetenv(k)
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}

			got := electorAdvertiseAddr()
			if tc.wantHostP {
				host, port := splitLast(got)
				if host == "" || port == "" {
					t.Fatalf("expected host:port, got %q", got)
				}
				if port != "9501" {
					t.Errorf("expected the default REST port, got %q in %q", port, got)
				}
				return
			}
			if got != tc.want {
				t.Errorf("electorAdvertiseAddr() = %q, want %q", got, tc.want)
			}
		})
	}
}

// splitLast splits on the final colon, so IPv6 hosts do not break the assertion.
func splitLast(s string) (host, port string) {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return s[:i], s[i+1:]
		}
	}
	return "", ""
}
