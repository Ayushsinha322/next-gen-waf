package db

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	// DevTenantID is the well-known UUID for the default dev tenant.
	DevTenantID = "00000000-0000-0000-0000-000000000001"
	// DevAdminID is the well-known UUID for the default dev admin user.
	DevAdminID  = "00000000-0000-0000-0000-000000000002"
)

// SeedDev inserts a default tenant, admin user, and sample data if they do
// not already exist. Safe to call on every startup (idempotent).
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

	// ── Admin user (password = admin123) ────────────────────────────────────
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("seed: salt: %w", err)
	}
	hash := argon2.IDKey([]byte("admin123"), salt, 1, 64*1024, 4, 32)
	pwdHash := fmt.Sprintf("argon2id$%s$%s", hex.EncodeToString(salt), hex.EncodeToString(hash))

	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, tenant_id, email, name, password_hash, role, status)
		VALUES ($1, $2, 'admin@sentinel.local', 'Admin User', $3, 'admin', 'active')
		ON CONFLICT (id) DO NOTHING`,
		DevAdminID, DevTenantID, pwdHash)
	if err != nil {
		return fmt.Errorf("seed: admin user: %w", err)
	}

	// ── Sample sites ─────────────────────────────────────────────────────────
	type siteSpec struct {
		name   string
		domain string
		mode   string
		status string
	}
	sites := []siteSpec{
		{"dvwa.local", "dvwa.local", "blocking", "active"},
		{"juice.local", "juice.local", "blocking", "active"},
		{"api.acme.com", "api.acme.com", "learning", "active"},
		{"shop.corp.io", "shop.corp.io", "blocking", "active"},
		{"legacy.app.net", "legacy.app.net", "off", "paused"},
	}
	for _, s := range sites {
		up, _ := json.Marshal(map[string]any{
			"servers": []string{"127.0.0.1:8080"},
			"lb":      "round_robin",
		})
		wp, _ := json.Marshal(map[string]any{
			"mode":              s.mode,
			"paranoia_level":    2,
			"anomaly_threshold": 5,
		})
		_, err = tx.Exec(ctx, `
			INSERT INTO sites (tenant_id, name, domains, upstream, waf_policy, status)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (tenant_id, name) DO NOTHING`,
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

	return tx.Commit(ctx)
}
