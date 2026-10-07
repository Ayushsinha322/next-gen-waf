package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOnlyKnownSubcommandsAreHandled(t *testing.T) {
	for _, args := range [][]string{nil, {}, {"--verbose"}, {"serve"}} {
		if _, handled := runSubcommand(args); handled {
			t.Fatalf("%q must start the server, not run a subcommand", args)
		}
	}
}

// The compose healthcheck: 0 only when /readyz answers 200.
func TestHealthcheckFollowsReadyz(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"checks":{"db":"unreachable"}}`))
	}))
	defer srv.Close()
	t.Setenv("SENTINEL_REST_ADDR", strings.TrimPrefix(srv.URL, "http://"))

	var stderr bytes.Buffer
	if code := healthcheck(&stderr); code != 0 {
		t.Fatalf("ready control plane reported unhealthy: %d %s", code, stderr.String())
	}
	status = http.StatusServiceUnavailable
	if code := healthcheck(&stderr); code != 1 {
		t.Fatalf("a control plane without its database reported healthy (%d)", code)
	}
	if !strings.Contains(stderr.String(), "unreachable") {
		t.Fatalf("the failure should say why: %q", stderr.String())
	}
}

func TestResetAdminExplainsWhereToRunIt(t *testing.T) {
	t.Setenv("SENTINEL_DB_URL", "")
	var stdout, stderr bytes.Buffer
	if code := resetAdminCmd(nil, &stdout, &stderr); code != 1 {
		t.Fatalf("exit %d without a database", code)
	}
	if !strings.Contains(stderr.String(), "docker exec") {
		t.Fatalf("the error should say how to run it: %q", stderr.String())
	}
	if code := resetAdminCmd([]string{"--no-such-flag"}, &stdout, &stderr); code != 2 {
		t.Fatalf("an unknown flag must be a usage error, got %d", code)
	}
}
