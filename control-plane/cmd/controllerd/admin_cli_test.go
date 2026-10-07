package main

import (
	"bytes"
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
