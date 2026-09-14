package mailer

import (
	"strings"
	"testing"
	"time"

	"github.com/your-org/sentinel-waf/control-plane/internal/version"
)

// These messages are the product's only voice to someone who is locked out of
// the console, and until 2026-09-14 every one of them used "Next-Gen ESDSWAF" —
// the name Swaraj Kavach replaced. The name is now spliced into the fmt
// templates by closing the raw string and concatenating version.Name, which
// keeps every existing verb and argument in place but means a mistake shows up
// as mangled prose rather than a compile error. So render them and look.
func renderAll(t *testing.T) map[string]Message {
	t.Helper()
	when := time.Date(2026, 9, 14, 6, 0, 0, 0, time.UTC)
	return map[string]Message{
		"reset":        ResetEmail("Ayush", "https://waf.example/r/abc", when.Add(30*time.Minute), false),
		"resetByAdmin": ResetEmail("", "https://waf.example/r/abc", when.Add(30*time.Minute), true),
		"changed":      ChangedEmail("Ayush", "10.0.0.9", when),
		"adminNotice":  AdminNoticeEmail("ayush@example.com", "10.0.0.9", "admin", when),
		"test":         TestEmail("waf-21"),
	}
}

func TestMailNamesTheProduct(t *testing.T) {
	for name, m := range renderAll(t) {
		body := m.Subject + "\n" + m.Text + "\n" + m.HTML
		if !strings.Contains(body, version.Name) {
			t.Errorf("%s: never names the product (%q)", name, version.Name)
		}
		for _, bad := range []string{"ESDSWAF", "Next-Gen", "Sentinel WAF"} {
			if strings.Contains(body, bad) {
				t.Errorf("%s: still says %q", name, bad)
			}
		}
	}
}

// A splice that went wrong shows up as a leftover verb or a fmt error string,
// not as a failure to compile. Both are visible in the rendered output.
func TestMailHasNoFormattingResidue(t *testing.T) {
	for name, m := range renderAll(t) {
		for _, part := range []struct{ what, s string }{{"subject", m.Subject}, {"text", m.Text}, {"html", m.HTML}} {
			if strings.Contains(part.s, "%!") {
				t.Errorf("%s %s: fmt error in output: %s", name, part.what, part.s)
			}
			if strings.Contains(part.s, "%s") || strings.Contains(part.s, "%d") {
				t.Errorf("%s %s: an unconsumed verb reached the reader: %s", name, part.what, part.s)
			}
		}
		if m.Subject == "" || strings.TrimSpace(m.Text) == "" {
			t.Errorf("%s: empty subject or body", name)
		}
	}
}
