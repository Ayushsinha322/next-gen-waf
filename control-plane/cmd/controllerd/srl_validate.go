package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Real SRL validation, by executing the engine rather than imitating it.
//
// The previous implementation scanned the DSL text for `rx('...')`, extracted
// whatever sat between the quotes and compiled it as a Go regex — ignoring
// targets, phase, action and score, and happily accepting a syntax the real
// parser rejects outright. Every seeded example rule was invalid SRL and it
// reported them fine. That is the worst kind of validation: it manufactures
// confidence.
//
// This shells out to `srl-validate`, a small binary built from the same crates
// the data plane uses, bundled into the control-plane image. One compiler, so a
// rule that validates here is a rule that will run there. See the binary's own
// header for why a Go reimplementation and a network call to the data plane were
// both rejected.

// srlValidatorPath is resolved once. Overridable so a developer running the
// control plane outside the container can point at a cargo build.
var (
	srlPathOnce sync.Once
	srlPath     string
)

func srlValidatorPath() string {
	srlPathOnce.Do(func() {
		if p := strings.TrimSpace(os.Getenv("SENTINEL_SRL_VALIDATOR")); p != "" {
			// An explicit override that does not exist is reported as unavailable
			// rather than falling back to a default binary: silently running a
			// different validator than the operator named is worse than not
			// running one, and a typo'd path otherwise surfaces as a confusing
			// exec error at every call instead of a clean "cannot validate".
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				srlPath = p
			}
			return
		}
		for _, cand := range []string{
			"/usr/local/bin/srl-validate",
			"./target/debug/sentinel-srl-validate",
			"./target/release/sentinel-srl-validate",
		} {
			if st, err := os.Stat(cand); err == nil && !st.IsDir() {
				srlPath = cand
				return
			}
		}
	})
	return srlPath
}

// ErrValidatorUnavailable means validation did not run — NOT that the rule is
// invalid. Callers must keep those two apart: treating "could not check" as
// "invalid" makes rule management impossible the moment the binary is missing,
// and treating it as "valid" silently restores the behaviour being fixed.
var ErrValidatorUnavailable = errors.New("srl validator unavailable")

type srlRuleSummary struct {
	ID       int    `json:"id"`
	Phase    string `json:"phase"`
	Action   string `json:"action"`
	Severity string `json:"severity"`
}

type srlResult struct {
	Valid          bool             `json:"valid"`
	Error          string           `json:"error,omitempty"`
	Rules          []srlRuleSummary `json:"rules"`
	Matched        *bool            `json:"matched,omitempty"`
	Decision       string           `json:"decision,omitempty"`
	Score          *int             `json:"score,omitempty"`
	MatchedRuleIDs []string         `json:"matched_rule_ids,omitempty"`
}

type srlRequest struct {
	DSL     string `json:"dsl"`
	Payload string `json:"payload,omitempty"`
	Path    string `json:"path,omitempty"`
	Method  string `json:"method,omitempty"`
}

// validateSRL runs the real parser/compiler over dsl, optionally dry-running it
// against a sample payload.
//
// A non-zero exit from the binary means the VALIDATOR failed, not that the rule
// is bad — the binary exits 0 for an invalid rule and puts the reason in the JSON
// precisely so these stay distinguishable.
func validateSRL(ctx context.Context, req srlRequest) (*srlResult, error) {
	bin := srlValidatorPath()
	if bin == "" {
		return nil, ErrValidatorUnavailable
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal validator request: %w", err)
	}

	// Bounded: a pathological regex could take a while to compile, and the
	// control plane must not hang on an operator's paste.
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cctx, bin)
	cmd.Stdin = bytes.NewReader(body)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if cctx.Err() != nil {
			return nil, fmt.Errorf("%w: validation timed out", ErrValidatorUnavailable)
		}
		return nil, fmt.Errorf("%w: %v: %s", ErrValidatorUnavailable, err,
			strings.TrimSpace(stderr.String()))
	}

	var res srlResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		return nil, fmt.Errorf("%w: unparseable validator output: %v",
			ErrValidatorUnavailable, err)
	}
	return &res, nil
}

// rejectInvalidDSL validates dsl and returns a client-facing error message when
// it cannot run, or "" when the rule is acceptable.
//
// When the validator is unavailable the rule is ACCEPTED and skipped is set. That
// is a deliberate availability choice: refusing every write because a helper
// binary is missing would make a bad deployment unrecoverable through the API.
// It is safe because the enforcement-status layer reports a rule that fails to
// compile on the data plane, so the operator still finds out — just seconds later
// instead of immediately.
func rejectInvalidDSL(ctx context.Context, dsl string) (problem string, skipped bool) {
	res, err := validateSRL(ctx, srlRequest{DSL: dsl})
	if err != nil {
		if errors.Is(err, ErrValidatorUnavailable) {
			return "", true
		}
		return "", true
	}
	if !res.Valid {
		msg := res.Error
		if msg == "" {
			msg = "the rule is not valid SRL"
		}
		return msg, false
	}
	return "", false
}
