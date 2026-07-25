package db

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
)

// seedAdminPassword decides the initial admin password. Precedence:
//  1. SENTINEL_BOOTSTRAP_ADMIN_PASSWORD  — operator-supplied (recommended in prod)
//  2. "admin123"                          — only when SENTINEL_DEV_LOGIN is on
//  3. a freshly generated random secret   — the secure default for any other deploy
//
// The second return value reports whether the password was generated, so the
// caller can print it once for the operator to retrieve and rotate.
func seedAdminPassword() (string, bool) {
	if pw := strings.TrimSpace(os.Getenv("SENTINEL_BOOTSTRAP_ADMIN_PASSWORD")); pw != "" {
		return pw, false
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SENTINEL_DEV_LOGIN"))) {
	case "1", "true", "yes", "on":
		return "admin123", false
	}
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b), true
}

const (
	// DevTenantID is the well-known UUID for the default dev tenant.
	DevTenantID = "00000000-0000-0000-0000-000000000001"
	// DevAdminID is the well-known UUID for the default dev admin user.
	DevAdminID = "00000000-0000-0000-0000-000000000002"

	// DemoFixturesEnvVar must be "1" to insert fabricated demo content.
	DemoFixturesEnvVar = "SENTINEL_DEV_SEED"
)

// DemoFixturesEnabled reports whether the operator explicitly asked for
// fabricated demo content (sample sites, sample rules, invented alerts).
//
// This used to be unconditional on every privileged boot, which meant a real
// deployment came up pre-populated with seven fabricated security alerts —
// complete with plausible attacker IPs, CRS rule IDs, scores, and a Log4Shell
// CVE reference — that were indistinguishable in the UI from alerts produced by
// actual traffic. Worse, the alert INSERT had no conflict handling, so it added
// another seven on EVERY restart, without bound.
//
// Fabricated security findings in a security product are the one thing that can
// destroy trust outright, so they are now opt-in.
func DemoFixturesEnabled() bool {
	return os.Getenv(DemoFixturesEnvVar) == "1"
}

// SeedDev bootstraps the default tenant and admin user, which every deployment
// needs in order to log in at all. Safe to call on every startup (idempotent).
//
// Fabricated demo content (sample sites, sample rules, sample alerts) is only
// inserted when DemoFixturesEnabled() — see its doc comment.
func SeedDev(ctx context.Context, pool Pool) error {
	// Use a raw pgxPool for seeding because we need to bypass RLS on first
	// insert (tenant row must exist before the policy can reference it).
	pg, ok := pool.(*pgxPool)
	if !ok {
		return fmt.Errorf("seed: pool is not a *pgxPool")
	}

	conn, err := pg.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("seed: acquire conn: %w", err)
	}
	defer conn.Release()

	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("seed: begin: %w", err)
	}
	defer tx.Rollback(ctx)

	// ── Tenant ──────────────────────────────────────────────────────────────
	_, err = tx.Exec(ctx, `
		INSERT INTO tenants (id, slug, name, plan, status)
		VALUES ($1, 'default', 'Default Tenant', 'enterprise', 'active')
		ON CONFLICT (id) DO NOTHING`,
		DevTenantID)
	if err != nil {
		return fmt.Errorf("seed: tenant: %w", err)
	}

	// ── Admin user ───────────────────────────────────────────────────────────
	adminPw, generatedPw := seedAdminPassword()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("seed: salt: %w", err)
	}
	hash := argon2.IDKey([]byte(adminPw), salt, 1, 64*1024, 4, 32)
	pwdHash := fmt.Sprintf("argon2id$%s$%s", hex.EncodeToString(salt), hex.EncodeToString(hash))

	ct, err := tx.Exec(ctx, `
		INSERT INTO users (id, tenant_id, email, name, password_hash, role, status)
		VALUES ($1, $2, 'admin@sentinel.local', 'Admin User', $3, 'admin', 'active')
		ON CONFLICT (id) DO NOTHING`,
		DevAdminID, DevTenantID, pwdHash)
	if err != nil {
		return fmt.Errorf("seed: admin user: %w", err)
	}
	// If we generated the password AND actually created the row (didn't hit the
	// ON CONFLICT no-op), surface it once so the operator can log in and rotate.
	if generatedPw && ct.RowsAffected() > 0 {
		fmt.Fprintf(os.Stderr,
			"\n[sentinel] Seeded initial admin 'admin@sentinel.local' with a GENERATED password:\n"+
				"[sentinel]     %s\n"+
				"[sentinel] Log in and change it immediately. Set SENTINEL_BOOTSTRAP_ADMIN_PASSWORD to control it.\n\n",
			adminPw)
	}

	// Everything below this point is FABRICATED demo content, not configuration a
	// real deployment needs. Commit the bootstrap rows and stop unless the
	// operator explicitly opted in.
	if !DemoFixturesEnabled() {
		return tx.Commit(ctx)
	}

	// ── Sample sites (demo only) ─────────────────────────────────────────────
	type siteSpec struct {
		name     string
		domain   string
		mode     string
		status   string
		upstream string // host:port for the real backend
	}
	sites := []siteSpec{
		// dvwa.local: WAF listens on :9095, upstream is docker on :9096
		{"dvwa.local", "dvwa.local", "blocking", "active", "127.0.0.1:9096"},
		// juice.local: WAF listens on :3000, upstream is docker on :3001
		{"juice.local", "juice.local", "blocking", "active", "127.0.0.1:3001"},
		{"api.acme.com", "api.acme.com", "learning", "active", "127.0.0.1:8080"},
		{"shop.corp.io", "shop.corp.io", "blocking", "active", "127.0.0.1:8080"},
		{"legacy.app.net", "legacy.app.net", "off", "paused", "127.0.0.1:8080"},
	}
	for _, s := range sites {
		up, _ := json.Marshal(map[string]any{
			"servers": []string{s.upstream},
			"lb":      "round_robin",
		})
		wp, _ := json.Marshal(map[string]any{
			"mode":              s.mode,
			"paranoia_level":    2,
			"anomaly_threshold": 5,
		})
		// DO UPDATE ensures the upstream port is always correct on restart.
		_, err = tx.Exec(ctx, `
			INSERT INTO sites (tenant_id, name, domains, upstream, waf_policy, status)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (tenant_id, name) DO UPDATE
			  SET upstream = EXCLUDED.upstream,
			      waf_policy = EXCLUDED.waf_policy`,
			DevTenantID, s.name, []string{s.domain}, up, wp, s.status)
		if err != nil {
			return fmt.Errorf("seed: site %s: %w", s.name, err)
		}
	}

	// ── Sample rules ─────────────────────────────────────────────────────────
	type ruleSpec struct {
		name, source, severity, dsl string
		phase                       int
	}
	rules := []ruleSpec{
		{"CRS-942100", "crs", "critical", `rule block-sqli { id: 942100; op: rx("union|select|insert"); action: block }`, 2},
		{"CRS-941140", "crs", "high", `rule block-xss { id: 941140; op: rx("<script"); action: block }`, 2},
		{"CRS-930100", "crs", "high", `rule block-traversal { id: 930100; op: rx("\.\./"); action: block }`, 1},
		{"CRS-932100", "crs", "critical", `rule block-cmdinj { id: 932100; op: rx("; ?ls |; ?cat "); action: block }`, 2},
		{"VP-CVE-2021-44228", "virtual_patch", "critical", `rule block-log4shell { id: 9999900; op: rx("\$\{jndi:"); action: block }`, 1},
		{"CRS-913100", "crs", "medium", `rule detect-scanner { id: 913100; op: ua_rx("nikto|sqlmap"); action: log }`, 1},
	}
	for _, r := range rules {
		_, err = tx.Exec(ctx, `
			INSERT INTO rules (tenant_id, name, source, phase, severity, dsl, enabled, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, true, $7)
			ON CONFLICT (tenant_id, name) DO NOTHING`,
			DevTenantID, r.name, r.source, r.phase, r.severity, r.dsl, DevAdminID)
		if err != nil {
			return fmt.Errorf("seed: rule %s: %w", r.name, err)
		}
	}

	// ── Sample alerts ─────────────────────────────────────────────────────────
	type alertSpec struct {
		sev, kind, summary, state string
		details                   map[string]any
	}
	alerts := []alertSpec{
		{"critical", "sqli", "SQL Injection via UNION SELECT detected from 185.220.101.45", "open",
			map[string]any{"ip": "185.220.101.45", "rule": "CRS-942100", "score": 24, "action": "BLOCKED", "path": "/api/v1/users"}},
		{"high", "xss", "XSS attempt blocked on juice.local", "open",
			map[string]any{"ip": "103.24.8.122", "rule": "CRS-941140", "score": 15, "action": "BLOCKED", "path": "/search"}},
		{"critical", "log4shell", "Log4Shell probe blocked — CVE-2021-44228", "open",
			map[string]any{"ip": "198.235.24.130", "rule": "VP-CVE-2021-44228", "score": 50, "action": "BLOCKED", "path": "/api/v2/orders"}},
		{"high", "path_traversal", "Path traversal attack blocked", "open",
			map[string]any{"ip": "91.240.118.150", "rule": "CRS-930100", "score": 18, "action": "BLOCKED", "path": "/admin"}},
		{"medium", "rate_limit", "Rate limit exceeded on api.acme.com", "open",
			map[string]any{"ip": "10.0.0.45", "rule": "MOD-RATELIMIT", "score": 8, "action": "RATE_LTD", "path": "/api/v1/token"}},
		{"high", "cmdinj", "Command injection attempt detected", "acked",
			map[string]any{"ip": "45.33.32.156", "rule": "CRS-932100", "score": 22, "action": "BLOCKED", "path": "/api/v1/exec"}},
		{"low", "scanner", "Scanner detected: Nikto/2.1.6", "resolved",
			map[string]any{"ip": "172.16.1.5", "rule": "CRS-913100", "score": 3, "action": "LOGGED", "path": "/robots.txt"}},
	}
	// Insert only into an empty alert table. Unlike the sites and rules above,
	// alerts have no natural unique key to conflict on, so this INSERT was
	// re-running in full on every boot and growing the table without bound.
	var existingAlerts int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM alerts WHERE tenant_id = $1`, DevTenantID).Scan(&existingAlerts); err != nil {
		return fmt.Errorf("seed: counting existing alerts: %w", err)
	}
	if existingAlerts == 0 {
		for _, a := range alerts {
			det, _ := json.Marshal(a.details)
			_, err = tx.Exec(ctx, `
				INSERT INTO alerts (tenant_id, severity, kind, summary, details, state)
				VALUES ($1, $2, $3, $4, $5, $6)`,
				DevTenantID, a.sev, a.kind, a.summary, det, a.state)
			if err != nil {
				return fmt.Errorf("seed: alert: %w", err)
			}
		}
	}

	return tx.Commit(ctx)
}
