package main

import (
	"strings"
	"testing"
	"time"
)

func TestValidatePasswordRejectsWeak(t *testing.T) {
	cases := []struct {
		name string
		pw   string
		ok   bool
	}{
		{"empty", "", false},
		{"too short", "Ab3!x", false},
		{"eleven chars", "Abcdefgh123", false},
		{"twelve but one class", "aaaaaaaaaaaa", false},
		{"twelve, two classes", "aaaaaaaaaaa1", true},
		{"long passphrase", "correct horse battery staple", true},
		{"mixed", "Admin@123#xyz", true},
		{"over 256", strings.Repeat("a1", 200), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			problem := validatePassword(c.pw)
			if c.ok && problem != "" {
				t.Fatalf("expected %q to be accepted, got %q", c.name, problem)
			}
			if !c.ok && problem == "" {
				t.Fatalf("expected %q to be rejected, it was accepted", c.name)
			}
		})
	}
}

// The floor must not drift below the one enforced when an administrator creates
// a user, or a reset becomes a way to install a weaker password than the account
// could have been created with.
func TestPasswordFloorMatchesUserCreation(t *testing.T) {
	if minPasswordLen < 12 {
		t.Fatalf("minPasswordLen dropped to %d; handleCreateUserReal binds min=12", minPasswordLen)
	}
}

func TestSessionEpochCacheInvalidatesOlderTokens(t *testing.T) {
	c := newSessionEpochCache()
	user := "u1"
	now := time.Now().UTC()

	// No epoch recorded: every token is fine.
	if !c.valid(user, now.Add(-time.Hour)) {
		t.Fatal("token rejected for a user that never reset")
	}

	c.set(user, now)

	if c.valid(user, now.Add(-time.Minute)) {
		t.Fatal("a token issued BEFORE the cut-off was accepted — sessions were not invalidated")
	}
	if !c.valid(user, now.Add(time.Minute)) {
		t.Fatal("a token issued AFTER the cut-off was rejected — the user cannot sign back in")
	}
	// Other users are unaffected.
	if !c.valid("u2", now.Add(-time.Hour)) {
		t.Fatal("one user's reset invalidated another user's session")
	}
}

// A token minted in the same whole second as the reset must be accepted: JWT
// "iat" is second-granular, and rejecting it would break the login that
// immediately follows a successful reset.
func TestSessionEpochCacheToleratesSameSecondLogin(t *testing.T) {
	c := newSessionEpochCache()
	base := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	c.set("u1", base.Add(500*time.Millisecond))
	if !c.valid("u1", base) {
		t.Fatal("a login in the same second as the reset was rejected")
	}
	if c.valid("u1", base.Add(-time.Second)) {
		t.Fatal("a token from the previous second was accepted")
	}
}

// replace() must not resurrect sessions that a local reset just ended.
func TestSessionEpochReplaceKeepsNewerLocalEntries(t *testing.T) {
	c := newSessionEpochCache()
	now := time.Now().UTC()
	c.set("u1", now)

	// A snapshot read just before the local reset landed.
	c.replace(map[string]time.Time{"u1": now.Add(-time.Hour)})

	if c.valid("u1", now.Add(-time.Minute)) {
		t.Fatal("a stale DB snapshot rolled back a local reset and revived dead sessions")
	}
}

func TestResetLinkRequiresConfiguredBase(t *testing.T) {
	if _, err := resetLink("", "tok"); err == nil {
		t.Fatal("a reset link was built with no SENTINEL_PUBLIC_URL; the host header must never be trusted here")
	}
	if _, err := resetLink("not-a-url", "tok"); err == nil {
		t.Fatal("a non-absolute base was accepted")
	}
	link, err := resetLink("https://waf.example.com/", "a b+c/d")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(link, " ") {
		t.Fatalf("token was not URL-escaped into the link: %s", link)
	}
	if !strings.HasPrefix(link, "https://waf.example.com/reset-password?token=") {
		t.Fatalf("unexpected link shape: %s", link)
	}
}
