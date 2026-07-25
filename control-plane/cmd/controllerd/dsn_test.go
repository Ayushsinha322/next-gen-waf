package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

const secret = "sup3rs3cr3t"

func TestMaskPasswordURLForm(t *testing.T) {
	dsn := "postgres://sentinel:" + secret + "@sentinel-postgres-rw:5432/sentinel?sslmode=verify-full"
	got := maskPassword(dsn)

	if strings.Contains(got, secret) {
		t.Fatalf("password leaked: %q", got)
	}
	// Everything useful for diagnostics must survive.
	for _, want := range []string{"sentinel-postgres-rw:5432", "sslmode=verify-full", "sentinel:"} {
		if !strings.Contains(got, want) {
			t.Errorf("masked DSN lost %q: %q", want, got)
		}
	}
}

func TestMaskPasswordKeywordForm(t *testing.T) {
	dsn := "host=db user=sentinel password=" + secret + " sslmode=verify-full"
	got := maskPassword(dsn)

	if strings.Contains(got, secret) {
		t.Fatalf("password leaked: %q", got)
	}
	if !strings.Contains(got, "host=db") || !strings.Contains(got, "sslmode=verify-full") {
		t.Errorf("masked DSN lost diagnostics: %q", got)
	}
}

func TestMaskPasswordQueryStringForm(t *testing.T) {
	got := maskPassword("postgres://sentinel@db:5432/sentinel?password=" + secret)
	if strings.Contains(got, secret) {
		t.Fatalf("password leaked from query string: %q", got)
	}
}

func TestMaskPasswordDoesNotEchoUnparseableDSN(t *testing.T) {
	// A DSN we cannot parse is the one case where returning the input would be
	// worst: it is still the string holding the secret.
	got := maskPassword("postgres://user:" + secret + "@host:not-a-port/db")
	if strings.Contains(got, secret) {
		t.Fatalf("unparseable DSN echoed with secret intact: %q", got)
	}
}

func TestMaskPasswordPassesThroughSafeInput(t *testing.T) {
	if got := maskPassword(""); got != "" {
		t.Errorf("empty DSN should stay empty, got %q", got)
	}
	// No credential present — nothing to redact.
	dsn := "postgres://sentinel@db:5432/sentinel?sslmode=verify-full"
	if got := maskPassword(dsn); got != dsn {
		t.Errorf("passwordless DSN altered: %q -> %q", dsn, got)
	}
}

func TestRedactCredentialsScrubsDriverErrors(t *testing.T) {
	// pgx/pgconn failures can quote the DSN they choked on. This is the path
	// that leaks even though we never asked to log the DSN.
	cases := []string{
		`cannot parse "postgres://sentinel:` + secret + `@db:5432/sentinel": invalid port`,
		`failed to connect to host=db user=sentinel password=` + secret + ` database=sentinel`,
		`dial error postgresql://admin:` + secret + `@10.0.0.5:5432/x`,
	}
	for _, in := range cases {
		got := redactCredentials(in)
		if strings.Contains(got, secret) {
			t.Errorf("credential survived redaction:\n in: %s\nout: %s", in, got)
		}
		if !strings.Contains(got, redactedMark) {
			t.Errorf("no redaction marker applied: %s", got)
		}
	}
}

func TestRedactCredentialsPreservesUsefulContext(t *testing.T) {
	got := redactCredentials(`cannot parse "postgres://sentinel:` + secret + `@db:5432/sentinel": invalid port`)
	for _, want := range []string{"invalid port", "db:5432", "sentinel"} {
		if !strings.Contains(got, want) {
			t.Errorf("redaction destroyed context %q: %s", want, got)
		}
	}
}

func TestSafeErrWrapsAndRedacts(t *testing.T) {
	if got := safeErr(nil); got != "" {
		t.Errorf("safeErr(nil) = %q, want empty", got)
	}
	// Mirrors openDBWithRetry's wrapping of the underlying driver error.
	inner := errors.New(`failed to connect to "postgres://sentinel:` + secret + `@db:5432/sentinel"`)
	wrapped := fmt.Errorf("db not reachable after 3 attempts over 30s: %w", inner)
	got := safeErr(wrapped)

	if strings.Contains(got, secret) {
		t.Fatalf("password leaked through wrapped error: %s", got)
	}
	if !strings.Contains(got, "db not reachable after 3 attempts") {
		t.Errorf("safeErr lost the outer context: %s", got)
	}
}
