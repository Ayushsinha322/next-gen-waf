// Package mailer sends the transactional mail the control plane needs —
// currently password reset and the security notices around it.
//
// Everything is read from the environment. There is no default host, no default
// sender and no embedded credential anywhere in this package: a deployment that
// has not been configured simply reports itself as not configured, and the
// caller degrades honestly rather than pretending mail was sent.
package mailer

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"
)

// ErrNotConfigured is returned when no SMTP host or sender is set. Callers treat
// this as an operational condition to surface, never as a reason to leak the
// reset link back through the API instead.
var ErrNotConfigured = errors.New("mailer: SMTP is not configured")

// Config is the resolved SMTP configuration.
//
// Password is never logged and never rendered by String(); the struct is passed
// around by value inside this package only.
type Config struct {
	Host        string
	Port        int
	Username    string
	Password    string
	From        string
	FromName    string
	Security    string // "starttls" (default), "tls" (implicit), "none"
	SkipVerify  bool
	Timeout     time.Duration
	NotifyEmail string // security notifications (e.g. "a reset just completed")
	PublicURL   string // base URL the reset link points at
}

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// FromEnv resolves configuration from the process environment.
//
// SENTINEL_SECURITY_NOTIFY_EMAIL falls back to SENTINEL_ADMIN_EMAIL, which the
// installer already writes. That fallback is the whole reason the operator's
// address is configuration rather than a constant: the address differs per
// deployment, and baking one in would mail someone else's security notices to
// whoever happened to build the image.
func FromEnv() Config {
	port, err := strconv.Atoi(env("SENTINEL_SMTP_PORT", "587"))
	if err != nil || port <= 0 || port > 65535 {
		port = 587
	}
	timeout, err := time.ParseDuration(env("SENTINEL_SMTP_TIMEOUT", "15s"))
	if err != nil || timeout <= 0 {
		timeout = 15 * time.Second
	}
	security := strings.ToLower(env("SENTINEL_SMTP_SECURITY", "starttls"))
	switch security {
	case "starttls", "tls", "none":
	default:
		security = "starttls"
	}
	skip := env("SENTINEL_SMTP_INSECURE_SKIP_VERIFY", "0")

	return Config{
		Host:        env("SENTINEL_SMTP_HOST", ""),
		Port:        port,
		Username:    env("SENTINEL_SMTP_USERNAME", ""),
		Password:    os.Getenv("SENTINEL_SMTP_PASSWORD"),
		From:        env("SENTINEL_SMTP_FROM", ""),
		FromName:    env("SENTINEL_SMTP_FROM_NAME", "Next-Gen ESDSWAF"),
		Security:    security,
		SkipVerify:  skip == "1" || strings.EqualFold(skip, "true"),
		Timeout:     timeout,
		NotifyEmail: env("SENTINEL_SECURITY_NOTIFY_EMAIL", env("SENTINEL_ADMIN_EMAIL", "")),
		PublicURL:   strings.TrimRight(env("SENTINEL_PUBLIC_URL", ""), "/"),
	}
}

// Configured reports whether mail can actually be sent. Both a relay and a
// sender are required — a relay with no From produces mail most servers reject,
// which would fail later and less clearly.
func (c Config) Configured() bool { return c.Host != "" && c.From != "" }

// Redacted renders the configuration for logs and for the settings API. The
// password is represented as a boolean; the value never appears.
func (c Config) Redacted() map[string]any {
	return map[string]any{
		"configured":    c.Configured(),
		"host":          c.Host,
		"port":          c.Port,
		"security":      c.Security,
		"from":          c.From,
		"from_name":     c.FromName,
		"username":      c.Username,
		"password_set":  c.Password != "",
		"skip_verify":   c.SkipVerify,
		"notify_email":  c.NotifyEmail,
		"public_url":    c.PublicURL,
		"auth_required": c.Username != "",
	}
}

// Mailer sends messages using a Config.
type Mailer struct{ cfg Config }

func New(cfg Config) *Mailer { return &Mailer{cfg: cfg} }

func (m *Mailer) Config() Config { return m.cfg }

// headerSafe strips CR and LF from a value destined for a message header.
//
// Without this, an address or subject carrying "\r\n" could append arbitrary
// headers — a Bcc to an attacker, a rewritten From. The reset flow takes an
// email address straight from an unauthenticated request body, so this is on the
// direct path from attacker-controlled input to a header.
func headerSafe(v string) string {
	v = strings.ReplaceAll(v, "\r", "")
	v = strings.ReplaceAll(v, "\n", "")
	return strings.TrimSpace(v)
}

// validAddress is a deliberately conservative check: one "@", no whitespace, no
// control characters. It rejects things a relay would reject anyway, early, and
// before they reach a header.
func validAddress(addr string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" || len(addr) > 320 || strings.ContainsAny(addr, " \t\r\n<>,;") {
		return false
	}
	at := strings.Index(addr, "@")
	return at > 0 && at < len(addr)-1 && strings.Count(addr, "@") == 1
}

// Message is one outbound mail. Text is required; HTML is optional and, when
// present, the message is sent as multipart/alternative.
type Message struct {
	To      string
	Subject string
	Text    string
	HTML    string
}

// Send delivers a message. It returns ErrNotConfigured when SMTP has not been
// set up, so callers can distinguish "operator has not configured mail" from
// "the relay rejected this", which are different problems with different fixes.
func (m *Mailer) Send(msg Message) error {
	if !m.cfg.Configured() {
		return ErrNotConfigured
	}
	to := headerSafe(msg.To)
	if !validAddress(to) {
		return fmt.Errorf("mailer: invalid recipient address")
	}
	if !validAddress(m.cfg.From) {
		return fmt.Errorf("mailer: invalid sender address (SENTINEL_SMTP_FROM)")
	}

	body := m.build(to, msg)
	addr := net.JoinHostPort(m.cfg.Host, strconv.Itoa(m.cfg.Port))

	conn, err := net.DialTimeout("tcp", addr, m.cfg.Timeout)
	if err != nil {
		return fmt.Errorf("mailer: dial %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(m.cfg.Timeout))

	tlsCfg := &tls.Config{
		ServerName:         m.cfg.Host,
		InsecureSkipVerify: m.cfg.SkipVerify, //nolint:gosec // operator opt-in for private relays with internal CAs
		MinVersion:         tls.VersionTLS12,
	}
	if m.cfg.Security == "tls" {
		conn = tls.Client(conn, tlsCfg)
	}

	client, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("mailer: smtp handshake: %w", err)
	}
	defer client.Close()

	if m.cfg.Security == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(tlsCfg); err != nil {
				return fmt.Errorf("mailer: starttls: %w", err)
			}
		} else if m.cfg.Username != "" {
			// Refuse to hand credentials to a server that would take them in the
			// clear. A relay that cannot do STARTTLS and needs no auth is a
			// legitimate internal setup; one that wants a password is not.
			return fmt.Errorf("mailer: server does not offer STARTTLS and credentials were configured; " +
				"set SENTINEL_SMTP_SECURITY=none only for an unauthenticated local relay")
		}
	}

	if m.cfg.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)); err != nil {
			// The error from the library can echo the server banner; it never
			// contains the password, and we do not add it.
			return fmt.Errorf("mailer: authentication failed: %w", err)
		}
	}
	if err := client.Mail(m.cfg.From); err != nil {
		return fmt.Errorf("mailer: MAIL FROM: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("mailer: RCPT TO: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("mailer: DATA: %w", err)
	}
	if _, err := w.Write([]byte(body)); err != nil {
		w.Close()
		return fmt.Errorf("mailer: write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("mailer: close body: %w", err)
	}
	return client.Quit()
}

// build renders an RFC 5322 message, multipart/alternative when HTML is present.
func (m *Mailer) build(to string, msg Message) string {
	var b strings.Builder
	from := headerSafe(m.cfg.From)
	if n := headerSafe(m.cfg.FromName); n != "" {
		fmt.Fprintf(&b, "From: %s <%s>\r\n", n, from)
	} else {
		fmt.Fprintf(&b, "From: %s\r\n", from)
	}
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", headerSafe(msg.Subject))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\n")
	// Reset mail must not be filed as bulk, and must not be auto-replied to.
	b.WriteString("Auto-Submitted: auto-generated\r\n")
	b.WriteString("X-Auto-Response-Suppress: All\r\n")

	if msg.HTML == "" {
		b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
		b.WriteString(normalizeCRLF(msg.Text))
		return b.String()
	}

	boundary := "sentinel-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	fmt.Fprintf(&b, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", boundary)
	fmt.Fprintf(&b, "--%s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n",
		boundary, normalizeCRLF(msg.Text))
	fmt.Fprintf(&b, "--%s\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s\r\n",
		boundary, normalizeCRLF(msg.HTML))
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.String()
}

// normalizeCRLF converts bare newlines to CRLF and dot-stuffs any line that
// begins with "." so a body line cannot terminate the DATA command early.
func normalizeCRLF(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		if strings.HasPrefix(ln, ".") {
			lines[i] = "." + ln
		}
	}
	return strings.Join(lines, "\r\n")
}
