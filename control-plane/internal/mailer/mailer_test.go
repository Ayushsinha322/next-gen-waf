package mailer

import (
	"strings"
	"testing"
	"time"
)

// The recipient address arrives from an UNAUTHENTICATED request body, so a CRLF
// in it would let a caller append their own headers — a Bcc to themselves on
// someone else's reset mail.
func TestBuildRejectsHeaderInjection(t *testing.T) {
	m := New(Config{Host: "localhost", Port: 25, From: "waf@example.com", FromName: "WAF"})

	if err := m.Send(Message{To: "victim@example.com\r\nBcc: attacker@evil.com", Subject: "x", Text: "y"}); err == nil {
		t.Fatal("an address containing CRLF was accepted")
	}
	for _, bad := range []string{"no-at-sign", "a@b@c", "spaced addr@x.com", "", "a@"} {
		if err := m.Send(Message{To: bad, Subject: "x", Text: "y"}); err == nil {
			t.Fatalf("invalid address %q was accepted", bad)
		}
	}
}

// A subject is operator- or template-controlled, but stripping CRLF there too
// costs nothing and closes the same class of bug.
//
// The property that matters is that no NEW header LINE appears. Residue left
// inline ("WAFX-Evil: 1" as a display name) is malformed but harmless — it is
// still one header. Asserting on the substring instead would pass only by
// accident of how the value is mangled.
func TestBuildStripsCRLFFromHeaders(t *testing.T) {
	m := New(Config{Host: "h", Port: 25, From: "waf@example.com", FromName: "WAF\r\nX-Evil: 1"})
	out := m.build("user@example.com", Message{Subject: "Reset\r\nX-Evil: 2", Text: "body"})

	headerBlock, _, _ := strings.Cut(out, "\r\n\r\n")
	for _, line := range strings.Split(headerBlock, "\r\n") {
		if strings.HasPrefix(line, "X-Evil") {
			t.Fatalf("header injection created a new header line:\n%s", headerBlock)
		}
	}
	// And the intended headers must still be intact and on their own lines.
	for _, want := range []string{"To: user@example.com", "MIME-Version: 1.0"} {
		if !strings.Contains(headerBlock, "\r\n"+want) && !strings.HasPrefix(headerBlock, want) {
			t.Fatalf("expected header %q missing from:\n%s", want, headerBlock)
		}
	}
}

// A body line beginning with "." would otherwise terminate the SMTP DATA block.
func TestNormalizeCRLFDotStuffs(t *testing.T) {
	got := normalizeCRLF("line one\n.\nline two")
	if !strings.Contains(got, "\r\n..\r\n") {
		t.Fatalf("leading dot was not stuffed: %q", got)
	}
}

func TestNotConfiguredWhenHostOrFromMissing(t *testing.T) {
	if (Config{From: "a@b.com"}).Configured() {
		t.Fatal("configured with no host")
	}
	if (Config{Host: "smtp"}).Configured() {
		t.Fatal("configured with no sender")
	}
	if !(Config{Host: "smtp", From: "a@b.com"}).Configured() {
		t.Fatal("host+from should be enough")
	}
	if err := New(Config{}).Send(Message{To: "a@b.com"}); err != ErrNotConfigured {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
}

// The password must never be renderable. Redacted() is what the settings API
// returns, so this is the guard against leaking it to the console.
func TestRedactedNeverCarriesThePassword(t *testing.T) {
	cfg := Config{Host: "smtp", From: "a@b.com", Username: "u", Password: "sup3r-s3cret-value"}
	r := cfg.Redacted()
	for k, v := range r {
		if s, ok := v.(string); ok && strings.Contains(s, "sup3r-s3cret-value") {
			t.Fatalf("password leaked through Redacted()[%q]", k)
		}
	}
	if r["password_set"] != true {
		t.Fatal("password_set should report that a password is configured")
	}
}

// The reset link is the one secret in the mail. It belongs in the body, and the
// templates must not smuggle it into the subject (which lands in more logs).
func TestResetEmailKeepsTokenOutOfSubject(t *testing.T) {
	link := "https://waf.example.com/reset-password?token=SECRETTOKENVALUE"
	msg := ResetEmail("Ayush", link, time.Now().Add(30*time.Minute), false)
	if strings.Contains(msg.Subject, "SECRETTOKENVALUE") {
		t.Fatal("reset token appeared in the subject line")
	}
	if !strings.Contains(msg.Text, link) || !strings.Contains(msg.HTML, link) {
		t.Fatal("reset link missing from the message body")
	}
	if !strings.Contains(msg.Text, "30 minutes") {
		t.Fatalf("expiry not stated in the message: %s", msg.Text)
	}
}

// The operator notice exists so a recovery is visible; it must not be a way for
// whoever reads that mailbox to take the account over.
func TestAdminNoticeCarriesNoSecret(t *testing.T) {
	msg := AdminNoticeEmail("user@example.com", "10.0.0.1", "self", time.Now())
	low := strings.ToLower(msg.Text)
	for _, forbidden := range []string{"token", "password:"} {
		if strings.Contains(low, forbidden) {
			t.Fatalf("operator notice mentions %q:\n%s", forbidden, msg.Text)
		}
	}
	if !strings.Contains(msg.Text, "user@example.com") {
		t.Fatal("operator notice does not name the account")
	}
}
