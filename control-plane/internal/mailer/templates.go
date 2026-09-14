package mailer

import (
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/your-org/sentinel-waf/control-plane/internal/version"
)

// The reset link is the only secret these templates carry. It is passed in as an
// already-built URL and is never logged by the caller — the handler logs the
// outcome of sending, not the message.

// ResetEmail builds the password-reset message.
//
// The copy states the expiry explicitly and tells a user who did not ask for
// this that they can ignore it — which is the correct advice, because a reset
// request alone changes nothing until the link is used.
func ResetEmail(name, link string, expiresAt time.Time, byAdmin bool) Message {
	greeting := "Hello"
	if n := strings.TrimSpace(name); n != "" {
		greeting = "Hello " + n
	}
	mins := int(time.Until(expiresAt).Round(time.Minute).Minutes())
	if mins < 1 {
		mins = 1
	}

	reason := "We received a request to reset the password for your " + version.Name + " console account."
	if byAdmin {
		reason = "An administrator has started a password reset for your " + version.Name + " console account."
	}

	text := fmt.Sprintf(`%s,

%s

Set a new password using the link below. It works once and expires in %d minutes:

%s

If you did not expect this, you can ignore this message — your password has not
been changed, and this link can only be used by whoever opens it.

`+version.Name+`
This is an automated message; replies are not monitored.
`, greeting, reason, mins, link)

	esc := html.EscapeString(link)
	htmlBody := fmt.Sprintf(`<div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;font-size:15px;line-height:1.6;color:#1a1a1a;max-width:560px">
<p>%s,</p>
<p>%s</p>
<p>Set a new password using the button below. It works <strong>once</strong> and expires in <strong>%d minutes</strong>.</p>
<p style="margin:26px 0"><a href="%s" style="background:#1d6f7a;color:#ffffff;text-decoration:none;padding:11px 20px;border-radius:4px;display:inline-block;font-weight:600">Set a new password</a></p>
<p style="font-size:13px;color:#555">Or paste this address into your browser:<br><span style="word-break:break-all">%s</span></p>
<p style="font-size:13px;color:#555">If you did not expect this, you can ignore this message &mdash; your password has not been changed.</p>
<hr style="border:0;border-top:1px solid #e0e0e0;margin:22px 0">
<p style="font-size:12px;color:#777">`+version.Name+` &middot; automated message, replies are not monitored.</p>
</div>`, html.EscapeString(greeting), html.EscapeString(reason), mins, esc, esc)

	return Message{Subject: "Reset your " + version.Name + " password", Text: text, HTML: htmlBody}
}

// ChangedEmail confirms to the account holder that their password changed. This
// is the message that turns a silent takeover into one the victim notices.
func ChangedEmail(name, sourceIP string, when time.Time) Message {
	greeting := "Hello"
	if n := strings.TrimSpace(name); n != "" {
		greeting = "Hello " + n
	}
	where := ""
	if sourceIP != "" {
		where = fmt.Sprintf("\nRequest source: %s", sourceIP)
	}
	text := fmt.Sprintf(`%s,

The password for your `+version.Name+` console account was changed at %s UTC.%s

All existing sessions were signed out. If this was you, nothing further is needed.

If this was NOT you, contact your WAF administrator immediately — someone else
may control your account.

`+version.Name+`
This is an automated message; replies are not monitored.
`, greeting, when.UTC().Format("2006-01-02 15:04:05"), where)

	return Message{Subject: "Your " + version.Name + " password was changed", Text: text}
}

// AdminNoticeEmail tells the deployment's security contact that a reset
// completed. Sent to SENTINEL_SECURITY_NOTIFY_EMAIL, so an account recovery is
// visible to the operator even if the account holder never says anything.
//
// It names the account and the source address but carries no token and no
// password — there is nothing in here that helps whoever reads it take an
// account over.
func AdminNoticeEmail(userEmail, sourceIP, initiatedBy string, when time.Time) Message {
	via := "self-service reset link"
	if initiatedBy == "admin" {
		via = "administrator-initiated reset"
	}
	text := fmt.Sprintf(`A console password was reset on this `+version.Name+` deployment.

Account:   %s
Method:    %s
Source IP: %s
Time:      %s UTC

All sessions for that account were invalidated. No action is required if this
was expected. If it was not, review the audit log for user.password.reset.

`+version.Name+`
This is an automated message; replies are not monitored.
`, userEmail, via, orDash(sourceIP), when.UTC().Format("2006-01-02 15:04:05"))

	return Message{Subject: "[" + version.Name + "] Console password reset: " + userEmail, Text: text}
}

// TestEmail is what the settings "send test email" action delivers, so an
// operator can prove the relay works before a user ever needs a reset.
func TestEmail(deployment string) Message {
	text := fmt.Sprintf(`This is a test message from `+version.Name+` (%s).

If you received it, SMTP is configured correctly and password-reset mail will
be delivered.

`+version.Name+`
This is an automated message; replies are not monitored.
`, orDash(deployment))
	return Message{Subject: "[" + version.Name + "] SMTP test message", Text: text}
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
