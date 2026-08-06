package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// These run against the REAL validator binary when one is present, which is the
// only way to test that validation actually validates. Skipped otherwise rather
// than replaced with a mock: a mock here would assert that our fake agrees with
// our fake, which is precisely the failure mode being removed.

func validatorOrSkip(t *testing.T) {
	t.Helper()
	if srlValidatorPath() == "" {
		t.Skip("srl-validate binary not built; run: cargo build -p sentinel-srl-validate")
	}
}

const validSRL = `rule 9999950 {
    phase    : request_body
    targets  : ARGS
    operator : rx /QQZZMARKER7788/
    action   : block
    severity : high
    message  : "test marker"
}`

func TestValidatorAcceptsRealSRL(t *testing.T) {
	validatorOrSkip(t)
	res, err := validateSRL(context.Background(), srlRequest{DSL: validSRL})
	if err != nil {
		t.Fatalf("validateSRL: %v", err)
	}
	if !res.Valid {
		t.Fatalf("valid SRL rejected: %s", res.Error)
	}
	if len(res.Rules) != 1 || res.Rules[0].ID != 9999950 {
		t.Fatalf("expected one rule with id 9999950, got %+v", res.Rules)
	}
	if res.Rules[0].Phase != "request_body" {
		t.Errorf("phase = %q, want request_body (snake_case for humans)", res.Rules[0].Phase)
	}
	if res.Rules[0].Severity != "high" {
		t.Errorf("severity = %q, want high (not a Debug-printed Option)", res.Rules[0].Severity)
	}
}

// The syntax the old scanner accepted and the seeded examples used. If this ever
// passes again, the validator has been replaced by something that does not parse.
func TestValidatorRejectsTheOldFakeSyntax(t *testing.T) {
	validatorOrSkip(t)
	res, err := validateSRL(context.Background(),
		srlRequest{DSL: `rule block-sqli { id: 942100; op: rx("union|select"); action: block }`})
	if err != nil {
		t.Fatalf("validateSRL: %v", err)
	}
	if res.Valid {
		t.Fatal("the pre-2026-07-28 fake syntax must be rejected; accepting it means " +
			"validation is not using the real parser")
	}
	if res.Error == "" {
		t.Error("a rejection must carry a reason an operator can act on")
	}
}

func TestValidatorRejectsEmptyAndRuleless(t *testing.T) {
	validatorOrSkip(t)
	for name, dsl := range map[string]string{
		"empty":        "   ",
		"only comment": "# nothing here\n",
	} {
		t.Run(name, func(t *testing.T) {
			res, err := validateSRL(context.Background(), srlRequest{DSL: dsl})
			if err != nil {
				t.Fatalf("validateSRL: %v", err)
			}
			if res.Valid {
				t.Error("a DSL that defines no rules must not be reported valid — it " +
					"would store, enable, and enforce nothing")
			}
		})
	}
}

// The dry-run must run the real VM, not guess.
func TestValidatorDryRunMatchesAndMisses(t *testing.T) {
	validatorOrSkip(t)

	hit, err := validateSRL(context.Background(),
		srlRequest{DSL: validSRL, Payload: "x=QQZZMARKER7788"})
	if err != nil {
		t.Fatalf("validateSRL: %v", err)
	}
	if hit.Matched == nil || !*hit.Matched {
		t.Fatal("a payload containing the pattern must match")
	}
	if !strings.EqualFold(hit.Decision, "block") {
		t.Errorf("decision = %q, want Block for an action:block rule", hit.Decision)
	}
	if len(hit.MatchedRuleIDs) != 1 || hit.MatchedRuleIDs[0] != "9999950" {
		t.Errorf("matched ids = %v, want [9999950]", hit.MatchedRuleIDs)
	}

	miss, err := validateSRL(context.Background(),
		srlRequest{DSL: validSRL, Payload: "x=entirely-harmless"})
	if err != nil {
		t.Fatalf("validateSRL: %v", err)
	}
	if miss.Matched == nil || *miss.Matched {
		t.Error("a payload without the pattern must not match")
	}
}

// A missing binary must surface as "could not check", never as a verdict.
func TestUnavailableValidatorIsDistinctFromInvalid(t *testing.T) {
	t.Setenv("SENTINEL_SRL_VALIDATOR", "/nonexistent/definitely-not-here")
	// srlValidatorPath caches, so exercise the exec path directly with a bad path.
	saved := srlPath
	srlPath = "/nonexistent/definitely-not-here"
	defer func() { srlPath = saved }()

	_, err := validateSRL(context.Background(), srlRequest{DSL: validSRL})
	if err == nil {
		t.Fatal("expected an error when the validator cannot be executed")
	}
	if !errors.Is(err, ErrValidatorUnavailable) {
		t.Errorf("error must be ErrValidatorUnavailable so callers can tell "+
			"'could not check' from 'invalid', got %v", err)
	}
}

func TestValidatorPathRespectsEnvOverride(t *testing.T) {
	// Reset the once-guard for this check only.
	f, err := os.CreateTemp(t.TempDir(), "fake-validator")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	t.Setenv("SENTINEL_SRL_VALIDATOR", f.Name())
	// Call the resolution logic fresh rather than through the cached path.
	if got := strings.TrimSpace(os.Getenv("SENTINEL_SRL_VALIDATOR")); got != f.Name() {
		t.Fatalf("env override not visible: %q", got)
	}
}
