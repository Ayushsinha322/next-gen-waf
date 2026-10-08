package notify

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRecipientsRefuseTheWholeListOverOneTypo(t *testing.T) {
	got, err := Recipients("noc@example.in, oncall@example.in;lead@example.in")
	if err != nil || len(got) != 3 {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{"", " , ", "noc@example.in, oncall@", "noc example.in", "Noc <noc@example.in>"} {
		if _, err := Recipients(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestEmailGoesToEveryRecipientAndNamesTheOnesThatFailed(t *testing.T) {
	var sent []string
	var subject, body string
	MailSender = func(to, s, b string) error {
		sent = append(sent, to)
		subject, body = s, b
		if to == "bad@example.in" {
			return errors.New("550 mailbox unavailable")
		}
		return nil
	}
	t.Cleanup(func() { MailSender = nil })
	ch := Channel{Type: "email", Config: Config{To: "noc@example.in, bad@example.in"}}
	a := Alert{Severity: "critical", Kind: "site_refused",
		Summary:   "Node waf1 is refusing every request to shop (503)\r\nBcc: attacker@evil.example",
		Details:   map[string]interface{}{"node": "dp-1", "sites": []string{"shop"}},
		CreatedAt: time.Date(2026, 10, 8, 3, 0, 0, 0, time.UTC)}
	err := send(context.Background(), ch, a)
	if len(sent) != 2 {
		t.Fatalf("sent to %v", sent)
	}
	if err == nil || !strings.Contains(err.Error(), "bad@example.in") || strings.Contains(err.Error(), "noc@example.in") {
		t.Fatalf("the error must name only the recipient that failed: %v", err)
	}
	if strings.ContainsAny(subject, "\r\n") || !strings.HasPrefix(subject, "[Swaraj Kavach] CRITICAL site_refused: ") {
		t.Fatalf("subject: %q", subject)
	}
	for _, want := range []string{"Severity:  CRITICAL", "node: dp-1", "2026-10-08 03:00:00 UTC"} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q:\n%s", want, body)
		}
	}
}

func TestEmailWithoutAMailerSaysSo(t *testing.T) {
	MailSender = nil
	err := send(context.Background(), Channel{Type: "email", Config: Config{To: "noc@example.in"}}, Alert{Summary: "x"})
	if err == nil || !strings.Contains(err.Error(), "mail is not available") {
		t.Fatalf("%v", err)
	}
}
