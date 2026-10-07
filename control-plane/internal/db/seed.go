package db

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
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

	// BootstrapAdminEmailEnvVar is the console login the first administrator is
	// created with. install.sh writes the "Administrator email" it asks for
	// here, beside SENTINEL_BOOTSTRAP_ADMIN_PASSWORD; like the password it is
	// read only when that account is created.
	//
	// Deliberately not SENTINEL_ADMIN_EMAIL, which every install has carried
	// since the first installer as the security contact while the login stayed
	// DefaultAdminEmail. Keying the login on it would make that value mean the
	// login on new installs and not on upgraded ones, and nothing reading the
	// .env could tell which.
	BootstrapAdminEmailEnvVar = "SENTINEL_BOOTSTRAP_ADMIN_EMAIL"

	// DefaultAdminEmail is the bootstrap login when none is configured, and the
	// login of every installation made before one could be.
	DefaultAdminEmail = "admin@sentinel.local"
)

// BootstrapAdminEmail is the login the bootstrap administrator is created
// with, and the account `controllerd reset-admin` resets when not told which.
func BootstrapAdminEmail() string {
	if e := strings.TrimSpace(os.Getenv(BootstrapAdminEmailEnvVar)); e != "" {
		return e
	}
	return DefaultAdminEmail
}

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

// SeedDev bootstraps the default tenant and, while the tenant has no users at
// all, its first administrator — which a fresh deployment needs in order to log
// in at all. Safe to call on every startup.
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
	// Only into a tenant with no users at all. This was `ON CONFLICT (id) DO
	// NOTHING` on every boot, which re-created a deliberately deleted default
	// admin on the next restart — with the bootstrap password still sitting in
	// .env. Any user means the deployment has been taken over by its operators,
	// and from then on accounts are theirs to manage; `controllerd reset-admin`
	// is the way back in for a lost one. ON CONFLICT stays for two control
	// planes booting together against an empty table.
	adminPw, generatedPw := seedAdminPassword()
	adminEmail := BootstrapAdminEmail()
	pwdHash, err := hashPassword(adminPw)
	if err != nil {
		return fmt.Errorf("seed: %w", err)
	}

	ct, err := tx.Exec(ctx, `
		INSERT INTO users (id, tenant_id, email, name, password_hash, role, status)
		SELECT $1, $2, $3, 'Admin User', $4, 'admin', 'active'
		WHERE NOT EXISTS (SELECT 1 FROM users WHERE tenant_id = $2)
		ON CONFLICT DO NOTHING`,
		DevAdminID, DevTenantID, adminEmail, pwdHash)
	if err != nil {
		return fmt.Errorf("seed: admin user: %w", err)
	}
	// If we generated the password AND actually created the row, surface it
	// once so the operator can log in and rotate. install.sh scrapes the line
	// after "GENERATED password" for installs predating its own .env value, so
	// that two-line shape is load-bearing.
	if generatedPw && ct.RowsAffected() > 0 {
		fmt.Fprintf(os.Stderr,
			"\n[sentinel] Seeded initial admin '%s' with a GENERATED password:\n"+
				"[sentinel]     %s\n"+
				"[sentinel] Log in and change it immediately. Set SENTINEL_BOOTSTRAP_ADMIN_PASSWORD to control it.\n\n",
			adminEmail, adminPw)
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
	// These are DEMO rows, but they are also the examples an operator copies when
	// writing their first rule, so the DSL must be valid SRL. It previously was
	// not: every one used a `rule <name> { id: N; op: rx("...") }` shape that the
	// parser rejects outright — the rule name IS the numeric id, and the operator
	// form is `operator : rx /pattern/`. Nobody noticed because the rows were never
	// delivered to the data plane and /rules/test never parsed SRL either.
	//
	// The four 'crs' rows are kept deliberately crude AND deliberately excluded
	// from delivery by sentinel_deployable_rules() (migration 0017): they reuse
	// real CRS ids and rx /union|select|insert/ would block the word "select".
	// Real CRS reaches the data plane as files. Only the virtual_patch row below
	// is representative of something an operator should actually write.
	rules := []ruleSpec{
		{"CRS-942100", "crs", "critical", `rule 942100 {
    phase    : request_body
    targets  : ARGS
    operator : rx /(?i)(union|select|insert)/
    action   : block
    severity : critical
    message  : "demo only — too broad to deploy"
}`, 2},
		{"CRS-941140", "crs", "high", `rule 941140 {
    phase    : request_body
    targets  : ARGS
    operator : rx /(?i)<script/
    action   : block
    severity : high
    message  : "demo only"
}`, 2},
		{"CRS-930100", "crs", "high", `rule 930100 {
    phase    : request_body
    targets  : ARGS
    operator : rx /\.\.\//
    action   : block
    severity : high
    message  : "demo only"
}`, 1},
		{"CRS-932100", "crs", "critical", `rule 932100 {
    phase    : request_body
    targets  : ARGS
    operator : rx /;\s?(ls|cat)\s/
    action   : block
    severity : critical
    message  : "demo only"
}`, 2},
		{"VP-CVE-2021-44228", "virtual_patch", "critical", `rule 9999900 {
    phase    : request_body
    targets  : ARGS|REQUEST_HEADERS|REQUEST_COOKIES
    operator : rx /\$\{jndi:/
    action   : block
    severity : critical
    message  : "Log4Shell JNDI lookup (CVE-2021-44228)"
}`, 1},
		{"CRS-913100", "crs", "medium", `rule 913100 {
    phase    : request_headers
    targets  : REQUEST_HEADERS:User-Agent
    operator : rx /(?i)(nikto|sqlmap)/
    action   : log
    severity : medium
    message  : "demo only"
}`, 1},
	}
	for _, r := range rules {
		// created_by through a lookup: the bootstrap admin is no longer
		// re-created once deleted, and a dangling id fails the foreign key.
		_, err = tx.Exec(ctx, `
			INSERT INTO rules (tenant_id, name, source, phase, severity, dsl, enabled, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, true, (SELECT id FROM users WHERE id = $7::uuid))
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
