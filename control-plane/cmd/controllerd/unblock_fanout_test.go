package main

import (
	"context"
	"testing"
)

// The unblock request carries the internal secret, so a node's self-reported
// hostname becomes a URL only when it is a plain host name.
func TestUnblockFanOutOnlyUsesPlainHostnames(t *testing.T) {
	for _, h := range []string{"waf1", "waf-2.internal", "10.0.0.7"} {
		if !plainHostname(h) {
			t.Errorf("%q should be accepted", h)
		}
	}
	for _, h := range []string{"", "evil.example/x", "a@b", "host:1", "h ost", "x?y"} {
		if plainHostname(h) {
			t.Errorf("%q must be refused", h)
		}
	}
}

func TestUnblockWithoutANodeRegistryStillReachesTheConfiguredDataPlane(t *testing.T) {
	t.Setenv("SENTINEL_DATAPLANE_URL", "http://dataplane:8080/")
	got := unblockTargets(context.Background(), nil)
	if len(got) != 1 || got[0] != "http://dataplane:8080" {
		t.Fatalf("got %v", got)
	}
}
