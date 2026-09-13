package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The bug this file exists to prevent, in one sentence: users.last_login_at was
// created in the very first migration, selected by ListUsers, carried on
// UserRow, and rendered by the console — and NOTHING EVER WROTE IT, so every
// account read "Never" for the life of the product, including the one belonging
// to whoever was looking at the screen.
//
// That is indistinguishable from a dormant account during an access review,
// which is precisely when someone reads that column.
//
// It is also the same shape as several other defects here: a capability built
// end to end except for the one call that would make it run. So the guard is
// not "does MarkLogin work" — the integration test covers that — but "is
// MarkLogin actually CALLED", which is the half that was missing and the half a
// unit test of the store can never notice.
//
// These read source text rather than exercising a handler because handleLogin
// needs a live Postgres, a JWT service and a log hub. A test that cannot run
// without all three would be skipped in CI, and a guard that skips is how this
// class of bug survives.

func loginHandlerSource(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("handlers.go")
	if err != nil {
		t.Fatalf("read handlers.go: %v", err)
	}
	src := string(b)
	start := strings.Index(src, "func handleLogin(")
	if start == -1 {
		t.Fatal("handleLogin not found — this guard is looking in the wrong place")
	}
	// The handler ends where the next top-level func begins.
	rest := src[start+1:]
	end := strings.Index(rest, "\nfunc ")
	if end == -1 {
		return src[start:]
	}
	return src[start : start+1+end]
}

// argumentList returns the text between the opening parenthesis at the start of
// s and its matching close.
func argumentList(s string) string {
	depth := 0
	for i, r := range s {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return s[1:i]
			}
		}
	}
	return s
}

// A successful sign-in must record that it happened.
func TestLoginStampsLastLogin(t *testing.T) {
	body := loginHandlerSource(t)
	if !strings.Contains(body, "store.MarkLogin(") {
		t.Fatal("handleLogin never calls store.MarkLogin — last_login_at will read " +
			"\"Never\" for every account, however correct the store and the console are")
	}
}

// It must not be able to cost anyone their session. The login has already
// succeeded by this point and the audit entry is the record that matters, so a
// failure to stamp is logged and stepped over, never returned to the caller.
func TestLastLoginFailureDoesNotFailTheLogin(t *testing.T) {
	body := loginHandlerSource(t)
	idx := strings.Index(body, "store.MarkLogin(")
	if idx == -1 {
		t.Skip("covered by TestLoginStampsLastLogin")
	}
	// Look at the handful of lines around the call for an early return.
	window := body[idx:]
	if len(window) > 400 {
		window = window[:400]
	}
	if regexp.MustCompile(`MarkLogin\([^)]*\);\s*err\s*!=\s*nil\s*\{[^}]*\breturn\b`).MatchString(window) {
		t.Fatal("a failure to stamp last_login_at aborts the login — the sign-in has " +
			"already succeeded at that point, so this would lock users out over a " +
			"convenience timestamp")
	}
	if !strings.Contains(window, "log.Warn") && !strings.Contains(window, "log.Error") {
		t.Fatal("the stamp error is discarded silently — best-effort must still be " +
			"visible, or the column can stop updating again with no trace")
	}
}

// The write is scoped to the caller's own tenant, not to a hardcoded one. The
// control plane has a DevTenantID constant that several call sites use, and
// using it here would stamp the wrong row for any account outside it.
func TestLastLoginUsesTheCallersTenant(t *testing.T) {
	body := loginHandlerSource(t)
	idx := strings.Index(body, "store.MarkLogin(")
	if idx == -1 {
		t.Skip("covered by TestLoginStampsLastLogin")
	}
	// Take the WHOLE argument list, matching parentheses. Cutting at the first
	// ")" stops inside c.Request.Context() and reads none of the arguments.
	call := argumentList(body[idx+len("store.MarkLogin"):])
	if strings.Contains(call, "DevTenantID") {
		t.Fatalf("MarkLogin is called with the dev tenant rather than the user's own: %s", call)
	}
	if !strings.Contains(call, "claims.TenantID") {
		t.Fatalf("MarkLogin should be called with claims.TenantID, got: %s", call)
	}
}

// The store method must actually write the column. A method that compiles,
// returns nil and updates nothing would satisfy the wiring test above.
func TestMarkLoginWritesTheColumn(t *testing.T) {
	b, err := os.ReadFile("../../internal/db/user_store.go")
	if err != nil {
		t.Fatalf("read user_store.go: %v", err)
	}
	src := string(b)
	start := strings.Index(src, "func (s *Store) MarkLogin(")
	if start == -1 {
		t.Fatal("Store.MarkLogin not found")
	}
	rest := src[start+1:]
	end := strings.Index(rest, "\nfunc ")
	body := src[start:]
	if end != -1 {
		body = src[start : start+1+end]
	}

	if !strings.Contains(body, "UPDATE users") || !strings.Contains(body, "last_login_at = now()") {
		t.Fatal("MarkLogin does not update users.last_login_at")
	}
	// Tenant predicate alongside the id, matching every other write in that file:
	// isolation must not depend solely on row-level security being active.
	if !strings.Contains(body, "tenant_id = $2") {
		t.Fatal("MarkLogin does not scope its update by tenant_id — RLS must not be " +
			"the only thing standing between tenants")
	}
}
