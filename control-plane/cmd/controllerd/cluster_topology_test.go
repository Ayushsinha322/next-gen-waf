package main

import "testing"

func TestDeriveRaftTopology(t *testing.T) {
	tests := []struct {
		name      string
		pod       string
		replicas  string
		service   string
		port      string
		wantID    uint64
		wantPeers string
		wantErr   bool
	}{
		{
			name:      "ordinal 0 of 3",
			pod:       "sentinel-controlplane-0",
			replicas:  "3",
			service:   "sentinel-controlplane-hl",
			port:      "9600",
			wantID:    1,
			wantPeers: "2=sentinel-controlplane-1.sentinel-controlplane-hl:9600,3=sentinel-controlplane-2.sentinel-controlplane-hl:9600",
		},
		{
			name:      "ordinal 2 of 3 (last)",
			pod:       "sentinel-controlplane-2",
			replicas:  "3",
			service:   "sentinel-controlplane-hl",
			port:      "9600",
			wantID:    3,
			wantPeers: "1=sentinel-controlplane-0.sentinel-controlplane-hl:9600,2=sentinel-controlplane-1.sentinel-controlplane-hl:9600",
		},
		{
			name:      "single replica has no peers",
			pod:       "cp-0",
			replicas:  "1",
			service:   "cp-hl",
			port:      "9600",
			wantID:    1,
			wantPeers: "",
		},
		{
			name:     "no ordinal suffix",
			pod:      "controlplane",
			replicas: "3",
			service:  "hl",
			port:     "9600",
			wantErr:  true,
		},
		{
			name:     "non-numeric ordinal",
			pod:      "cp-abc",
			replicas: "3",
			service:  "hl",
			port:     "9600",
			wantErr:  true,
		},
		{
			name:     "ordinal out of range",
			pod:      "cp-5",
			replicas: "3",
			service:  "hl",
			port:     "9600",
			wantErr:  true,
		},
		{
			name:     "missing service",
			pod:      "cp-0",
			replicas: "3",
			service:  "",
			port:     "9600",
			wantErr:  true,
		},
		{
			name:     "bad replicas",
			pod:      "cp-0",
			replicas: "0",
			service:  "hl",
			port:     "9600",
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, peers, err := deriveRaftTopology(tc.pod, tc.replicas, tc.service, tc.port)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got id=%d peers=%q", id, peers)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if id != tc.wantID {
				t.Errorf("id = %d, want %d", id, tc.wantID)
			}
			if peers != tc.wantPeers {
				t.Errorf("peers = %q, want %q", peers, tc.wantPeers)
			}
		})
	}
}
