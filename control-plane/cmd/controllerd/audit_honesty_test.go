package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/your-org/sentinel-waf/control-plane/internal/db"
)

// The audit trail's value rests on it being able to say that something FAILED.
// Before this, the login handler computed "FAILURE" and threw it away
// (`_ = loginResult`), the attempted email was never stored, and the live
// stream hardcoded "result":"SUCCESS" for every entry — so a brute-force run
// against the admin account was indistinguishable, in the audit log, from a
// series of successful logins by that account.

func TestAuditDiffAlwaysStampsAnOutcome(t *testing.T) {
	// Absent extras must still produce a result.
	if got := auditResultOf(auditDiff(auditFailure, nil)); got != auditFailure {
		t.Fatalf("FAILURE not recorded: %q", got)
	}
	if got := auditResultOf(auditDiff(auditSuccess, nil)); got != auditSuccess {
		t.Fatalf("SUCCESS not recorded: %q", got)
	}

	// A caller must not be able to overwrite the outcome through the extras
	// map — the outcome is the one field that has to be trustworthy.
	d := auditDiff(auditFailure, map[string]any{"result": "SUCCESS", "email": "a@b.c"})
	if got := auditResultOf(d); got != auditFailure {
		t.Fatalf("extras overrode the outcome: %q in %s", got, d)
	}
	if !strings.Contains(string(d), "a@b.c") {
		t.Fatalf("extras dropped: %s", d)
	}
}

// The live SSE stream must report the real outcome. It used to publish
// "result":"SUCCESS" unconditionally.
func TestAuditResultOfDefaultsToSuccessOnlyWhenUnstated(t *testing.T) {
	if got := auditResultOf(nil); got != auditSuccess {
		t.Fatalf("absent diff should read as SUCCESS (handlers that only audit their happy path), got %q", got)
	}
	if got := auditResultOf(json.RawMessage(`{"changed":{}}`)); got != auditSuccess {
		t.Fatalf("diff without a result should read as SUCCESS, got %q", got)
	}
	if got := auditResultOf(json.RawMessage(`{"result":"FAILURE"}`)); got != auditFailure {
		t.Fatalf("explicit FAILURE must survive, got %q", got)
	}
	// Malformed JSON must not be reported as a failure it cannot prove, nor
	// crash the publisher.
	if got := auditResultOf(json.RawMessage(`{not json`)); got != auditSuccess {
		t.Fatalf("malformed diff should fall back to SUCCESS, got %q", got)
	}
}

// A credential must never reach the audit log. The login handlers put the
// attempted EMAIL in the diff (needed to detect an attack on an account) and
// never the password.
func TestLoginAuditDiffCarriesEmailNotSecret(t *testing.T) {
	d := auditDiff(auditFailure, map[string]any{
		"email":  "victim@example.com",
		"reason": "invalid_credentials",
	})
	s := string(d)
	if !strings.Contains(s, "victim@example.com") {
		t.Fatalf("attempted email must be recorded (it is the identifier under attack): %s", s)
	}
	for _, forbidden := range []string{"password", "passwd", "secret", "token", "mfa_code"} {
		if strings.Contains(strings.ToLower(s), forbidden) {
			t.Fatalf("audit diff must not carry %q: %s", forbidden, s)
		}
	}
}

// siteChangeDiff is what makes "site X was updated" answerable. Turning a site
// from blocking to off disables protection entirely and used to record only
// that the site had changed.
func TestSiteChangeDiffNamesEnforcementChanges(t *testing.T) {
	before := &db.SiteRow{
		Name: "shop", Status: "active",
		WafPolicy: json.RawMessage(`{"mode":"blocking","anomaly_threshold":10,"paranoia_level":2}`),
	}
	after := &db.SiteRow{
		Name: "shop", Status: "active",
		WafPolicy: json.RawMessage(`{"mode":"off","anomaly_threshold":10,"paranoia_level":2}`),
	}
	d := string(siteChangeDiff(before, after))
	if !strings.Contains(d, `"mode"`) || !strings.Contains(d, "blocking") || !strings.Contains(d, "off") {
		t.Fatalf("mode change must appear with both sides: %s", d)
	}
	// Unchanged fields must NOT be listed, or the diff becomes a snapshot and
	// the actual change is buried.
	if strings.Contains(d, "paranoia_level") {
		t.Fatalf("unchanged fields must be omitted: %s", d)
	}

	// A threshold change is equally material (it decides what gets blocked).
	after2 := &db.SiteRow{
		Name: "shop", Status: "active",
		WafPolicy: json.RawMessage(`{"mode":"blocking","anomaly_threshold":5,"paranoia_level":2}`),
	}
	d2 := string(siteChangeDiff(before, after2))
	if !strings.Contains(d2, "anomaly_threshold") {
		t.Fatalf("threshold change must be recorded: %s", d2)
	}

	// A non-enforcement edit still records the mutation, just with nothing
	// highlighted — it must not fabricate a change.
	d3 := string(siteChangeDiff(before, before))
	if strings.Contains(d3, "changed") {
		t.Fatalf("identical states must not report a change: %s", d3)
	}
	if auditResultOf(json.RawMessage(d3)) != auditSuccess {
		t.Fatalf("a no-op update is still a successful mutation: %s", d3)
	}
}

func TestSiteEnforcementFactsSurvivesMissingPolicy(t *testing.T) {
	// A malformed or absent waf_policy must not panic or silently claim a mode.
	row := &db.SiteRow{Name: "x", Status: "active", WafPolicy: json.RawMessage(`not json`)}
	f := siteEnforcementFacts(row)
	if f["status"] != "active" || f["name"] != "x" {
		t.Fatalf("basic facts lost: %#v", f)
	}
	if _, claimed := f["mode"]; claimed {
		t.Fatalf("mode must not be invented when the policy cannot be parsed: %#v", f)
	}
	if siteEnforcementFacts(nil) != nil {
		t.Fatal("nil row must yield nil facts")
	}
}

// The dev audit key makes the chain forgeable by anyone who can write to the
// database. Production cannot reach it (main.go refuses to boot without
// SENTINEL_AUDIT_HMAC_KEY unless SENTINEL_DEV_LOGIN is set); this pins the
// constant so the fallback stays a single, greppable, obviously-dev value.
func TestDevAuditKeyIsNotUsedWhenConfigured(t *testing.T) {
	t.Setenv("SENTINEL_AUDIT_HMAC_KEY", "a-real-key-of-at-least-32-characters!!")
	if got := string(auditHMACKey()); got == devAuditHMACKey {
		t.Fatal("configured key was ignored in favour of the dev fallback")
	}
	if !strings.Contains(devAuditHMACKey, "dev") {
		t.Fatalf("the fallback must be self-evidently a dev key, got %q", devAuditHMACKey)
	}
}
