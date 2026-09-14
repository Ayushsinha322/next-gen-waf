package version

import (
	"strings"
	"testing"
)

// The deployment's own value wins over the link-time one, because a deploy that
// retags byte-identical images would otherwise report the previous commit — the
// console did exactly that for two deploys on 2026-09-07.
func TestCommitPrefersTheDeploymentValue(t *testing.T) {
	CommitLinked, BuildDateLinked = "aaaaaaa", "2026-01-01T00:00:00Z"

	t.Setenv("SENTINEL_GIT_SHA", "")
	t.Setenv("SENTINEL_BUILD_DATE", "")
	if got := Commit(); got != "aaaaaaa" {
		t.Errorf("no env → link-time value, got %q", got)
	}

	t.Setenv("SENTINEL_GIT_SHA", "bbbbbbb")
	t.Setenv("SENTINEL_BUILD_DATE", "2026-09-07T00:00:00Z")
	if got := Commit(); got != "bbbbbbb" {
		t.Errorf("env set → env wins, got %q", got)
	}
	if got := BuildDate(); got != "2026-09-07T00:00:00Z" {
		t.Errorf("build date should follow, got %q", got)
	}
	if got := LinkedCommit(); got != "aaaaaaa" {
		t.Errorf("LinkedCommit must stay diagnosable, got %q", got)
	}

	// A retag is exactly the case where the two differ, and Info must say so
	// rather than hiding it.
	info := Info()
	if info["commit"] != "bbbbbbb" || info["binary_built_from"] != "aaaaaaa" {
		t.Errorf("Info must report both on a retag: %v", info)
	}

	// Placeholders and whitespace are not values.
	for _, junk := range []string{"unknown", "   ", ""} {
		t.Setenv("SENTINEL_GIT_SHA", junk)
		if got := Commit(); got != "aaaaaaa" {
			t.Errorf("env %q must fall back to link-time, got %q", junk, got)
		}
	}

	// When they agree, Info stays clean.
	t.Setenv("SENTINEL_GIT_SHA", "aaaaaaa")
	if _, present := Info()["binary_built_from"]; present {
		t.Error("binary_built_from must be absent when the values agree")
	}
}

// Name is spliced directly INTO fmt format strings — the password-reset
// templates close their raw string, concatenate it, and reopen, which keeps
// every existing verb and argument in place. That is only safe while the name
// carries no `%`: one would be read as a verb, and the mail would either lose
// text or print "%!K(MISSING)" to a user who is already locked out.
//
// It also must not be empty, which would silently produce "Reset your
// password" with a gap where the product should be.
func TestNameIsSafeToSpliceIntoFormatStrings(t *testing.T) {
	if Name == "" {
		t.Fatal("version.Name is empty — every message that names the product loses it")
	}
	if strings.Contains(Name, "%") {
		t.Fatalf("version.Name contains %%, which fmt will read as a verb: %q", Name)
	}
}

// The codename must not be the product name. `sentinel` names the module, the
// binaries and the images; it is not what a customer calls this.
func TestNameIsNotTheCodename(t *testing.T) {
	lower := strings.ToLower(Name)
	for _, bad := range []string{"sentinel", "esdswaf", "next-gen esds"} {
		if strings.Contains(lower, bad) {
			t.Fatalf("version.Name is %q, which contains the codename or a superseded name %q", Name, bad)
		}
	}
}
