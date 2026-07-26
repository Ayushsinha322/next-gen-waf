package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func errUnknownType(t string) error { return fmt.Errorf("unknown channel type %q", t) }

// httpClient is shared; per-request timeout is enforced via context.
var httpClient = &http.Client{Timeout: 10 * time.Second}

// ---------------------------------------------------------------------------
// Webhook — generic JSON POST, optional HMAC-SHA256 body signature.
// ---------------------------------------------------------------------------

func sendWebhook(ctx context.Context, ch Channel, a Alert) error {
	if ch.Config.URL == "" {
		return fmt.Errorf("webhook: url is required")
	}
	body, err := json.Marshal(struct {
		Event string `json:"event"`
		Alert Alert  `json:"alert"`
	}{Event: "alert", Alert: a})
	if err != nil {
		return err
	}
	method := ch.Config.Method
	if method == "" {
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(ctx, method, ch.Config.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Sentinel-WAF/1.0")
	for k, v := range ch.Config.Headers {
		req.Header.Set(k, v)
	}
	// Optional tamper-evident signature so the receiver can verify origin.
	if ch.Config.Secret != "" {
		mac := hmac.New(sha256.New, []byte(ch.Config.Secret))
		mac.Write(body)
		req.Header.Set("X-Sentinel-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	return doHTTP(req)
}

// ---------------------------------------------------------------------------
// Slack — incoming-webhook formatted message.
// ---------------------------------------------------------------------------

func sendSlack(ctx context.Context, ch Channel, a Alert) error {
	if ch.Config.URL == "" {
		return fmt.Errorf("slack: webhook url is required")
	}
	color := map[string]string{
		"critical": "#d11d2c", "high": "#e8590c", "medium": "#f08c00",
		"low": "#1c7ed6", "info": "#868e96",
	}[strings.ToLower(a.Severity)]
	if color == "" {
		color = "#868e96"
	}
	fields := []map[string]interface{}{
		{"title": "Severity", "value": strings.ToUpper(a.Severity), "short": true},
		{"title": "Kind", "value": a.Kind, "short": true},
	}
	if a.Site != "" {
		fields = append(fields, map[string]interface{}{"title": "Site", "value": a.Site, "short": true})
	}
	if a.SourceIP != "" {
		fields = append(fields, map[string]interface{}{"title": "Source IP", "value": a.SourceIP, "short": true})
	}
	if a.Rule != "" {
		fields = append(fields, map[string]interface{}{"title": "Rule", "value": a.Rule, "short": true})
	}
	payload := map[string]interface{}{
		"attachments": []map[string]interface{}{{
			"fallback": fmt.Sprintf("[%s] %s", strings.ToUpper(a.Severity), a.Summary),
			"color":    color,
			"title":    "🛡️ Sentinel WAF Alert",
			"text":     a.Summary,
			"fields":   fields,
			"ts":       a.CreatedAt.Unix(),
			"footer":   "Sentinel WAF",
		}},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ch.Config.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return doHTTP(req)
}

// ---------------------------------------------------------------------------
// Syslog — RFC 5424 over UDP/TCP (no external dep; works cross-platform).
// ---------------------------------------------------------------------------

func sendSyslog(ctx context.Context, ch Channel, a Alert) error {
	msg := fmt.Sprintf("[%s] %s kind=%s site=%s ip=%s rule=%s",
		strings.ToUpper(a.Severity), a.Summary, a.Kind, a.Site, a.SourceIP, a.Rule)
	return writeSyslog(ctx, ch, a, msg)
}

// ---------------------------------------------------------------------------
// CEF — ArcSight Common Event Format, carried over a syslog header.
// ---------------------------------------------------------------------------

func sendCEF(ctx context.Context, ch Channel, a Alert) error {
	// CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension
	ext := cefExtension(map[string]string{
		"src":        a.SourceIP,
		"cs1Label":   "site",
		"cs1":        a.Site,
		"cs2Label":   "rule",
		"cs2":        a.Rule,
		"cs3Label":   "kind",
		"cs3":        a.Kind,
		"cnt":        itoa(a.Count),
		"externalId": a.ID,
		"rt":         itoa64(a.CreatedAt.UnixMilli()),
	})
	cef := fmt.Sprintf("CEF:0|Sentinel|WAF|1.0|%s|%s|%d|%s",
		cefEscapeHeader(nonEmpty(a.Kind, "alert")),
		cefEscapeHeader(a.Summary),
		cefSeverity(a.Severity),
		ext)
	return writeSyslog(ctx, ch, a, cef)
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

func doHTTP(req *http.Request) error {
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("http %d from %s", resp.StatusCode, req.URL.Host)
	}
	return nil
}

// writeSyslog frames msg with an RFC 5424 header and writes it to the
// configured UDP/TCP endpoint.
func writeSyslog(ctx context.Context, ch Channel, a Alert, msg string) error {
	host := ch.Config.Host
	if host == "" {
		return fmt.Errorf("syslog: host is required")
	}
	port := ch.Config.Port
	if port == 0 {
		port = 514
	}
	proto := strings.ToLower(ch.Config.Protocol)
	if proto != "tcp" {
		proto = "udp"
	}
	facility := ch.Config.Facility
	if facility == 0 {
		facility = 16 // local0
	}
	tag := ch.Config.Tag
	if tag == "" {
		tag = "sentinel-waf"
	}
	pri := facility*8 + syslogSeverity(a.Severity)
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "-"
	}
	ts := a.CreatedAt.UTC().Format(time.RFC3339)
	// <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
	frame := fmt.Sprintf("<%d>1 %s %s %s - alert - %s", pri, ts, hostname, tag, msg)

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, proto, fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return fmt.Errorf("syslog dial: %w", err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(dl)
	}
	if proto == "tcp" {
		frame += "\n"
	}
	if _, err := conn.Write([]byte(frame)); err != nil {
		return fmt.Errorf("syslog write: %w", err)
	}
	return nil
}

// syslogSeverity maps an alert severity to an RFC 5424 severity code (0-7).
func syslogSeverity(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 2 // Critical
	case "high":
		return 3 // Error
	case "medium":
		return 4 // Warning
	case "low":
		return 5 // Notice
	default:
		return 6 // Informational
	}
}

// cefSeverity maps an alert severity to CEF's 0-10 scale.
func cefSeverity(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 10
	case "high":
		return 8
	case "medium":
		return 5
	case "low":
		return 3
	default:
		return 1
	}
}

// cefExtension renders the key=value extension string, skipping empty values
// and escaping per CEF rules (backslash, equals, newline).
func cefExtension(kv map[string]string) string {
	// Stable-ish order: a fixed key sequence keeps output deterministic.
	order := []string{"src", "externalId", "rt", "cnt",
		"cs1Label", "cs1", "cs2Label", "cs2", "cs3Label", "cs3"}
	var b strings.Builder
	for _, k := range order {
		v, ok := kv[k]
		if !ok || v == "" {
			continue // skip only missing/empty — "0" is a legitimate value (e.g. cnt=0)
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(cefEscapeValue(v))
	}
	return b.String()
}

func cefEscapeHeader(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `|`, `\|`)
	return strings.ReplaceAll(s, "\n", " ")
}

func cefEscapeValue(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `=`, `\=`)
	return strings.ReplaceAll(s, "\n", " ")
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func itoa(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("%d", n)
}

func itoa64(n int64) string { return fmt.Sprintf("%d", n) }
