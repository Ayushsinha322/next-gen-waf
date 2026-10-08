package notify

import (
	"context"
	"fmt"
	"net/mail"
	"os"
	"sort"
	"strings"

	"github.com/your-org/sentinel-waf/control-plane/internal/version"
)

// MailSender delivers one plain-text message through the control plane's SMTP
// relay. main.go sets it to the mailer; nil means mail is not wired in this
// process, which an email channel reports as its delivery error rather than
// dropping the alert silently.
var MailSender func(to, subject, text string) error

// Recipients splits an email channel's "to" field. Every address must parse:
// one typo must not quietly shrink the list of people who get paged.
func Recipients(to string) ([]string, error) {
	fields := strings.FieldsFunc(to, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t' })
	var out []string
	for _, f := range fields {
		addr, err := mail.ParseAddress(f)
		if err != nil || addr.Address != f {
			return nil, fmt.Errorf("email: %q is not an email address", f)
		}
		out = append(out, f)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("email: at least one recipient is required")
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Email — one message per recipient through the SMTP relay in .env.
//
// The other sinks all need something the customer runs (a SIEM, a Slack
// workspace, a webhook receiver). Most installations had none of those wired
// up, so no alert ever reached a person: a node down, a site refusing traffic,
// a certificate about to lapse were rows in a console nobody had open.
// ---------------------------------------------------------------------------

func sendEmail(ctx context.Context, ch Channel, a Alert) error {
	to, err := Recipients(ch.Config.To)
	if err != nil {
		return err
	}
	if MailSender == nil {
		return fmt.Errorf("email: mail is not available in this process")
	}
	subject, text := emailBody(a)
	var failed []string
	for _, r := range to {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := MailSender(r, subject, text); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", r, err))
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("email: %s", strings.Join(failed, "; "))
	}
	return nil
}

// emailBody renders the alert as a subject line and a plain-text body. Plain
// text on purpose: it is read on a phone at 3am, and a NOC mail filter keys on
// the subject, so the severity and the kind lead it.
func emailBody(a Alert) (subject, text string) {
	sev := strings.ToUpper(nonEmpty(a.Severity, "info"))
	subject = fmt.Sprintf("[%s] %s %s: %s", version.Name, sev, nonEmpty(a.Kind, "alert"), oneLine(a.Summary, 140))

	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", a.Summary)
	row := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&b, "%-10s %s\n", k+":", v)
		}
	}
	row("Severity", sev)
	row("Kind", a.Kind)
	row("Site", a.Site)
	row("Source IP", a.SourceIP)
	row("Rule", a.Rule)
	if a.Count > 0 {
		row("Count", itoa(a.Count))
	}
	if !a.CreatedAt.IsZero() {
		row("Time", a.CreatedAt.UTC().Format("2006-01-02 15:04:05 MST"))
	}
	if len(a.Details) > 0 {
		keys := make([]string, 0, len(a.Details))
		for k := range a.Details {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("\nDetails\n")
		for _, k := range keys {
			fmt.Fprintf(&b, "  %s: %v\n", k, a.Details[k])
		}
	}
	if base := strings.TrimRight(os.Getenv("SENTINEL_PUBLIC_URL"), "/"); base != "" {
		fmt.Fprintf(&b, "\nOpen the console: %s/alerts\n", base)
	}
	fmt.Fprintf(&b, "\n— %s %s\n", version.Name, version.Product)
	return subject, b.String()
}

func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > max {
		return string(r[:max-1]) + "…"
	}
	return s
}
