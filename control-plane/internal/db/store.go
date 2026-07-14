package db

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// Store provides tenant-scoped data access built on top of Pool.
type Store struct {
	pool Pool
}

// NewStore returns a Store wrapping the given pool.
func NewStore(pool Pool) *Store { return &Store{pool: pool} }

// ---------------------------------------------------------------------------
// Shared types returned to callers
// ---------------------------------------------------------------------------

type SiteRow struct {
	ID        string          `json:"id"`
	TenantID  string          `json:"tenant_id"`
	Name      string          `json:"name"`
	Domains   []string        `json:"domains"`
	Upstream  json.RawMessage `json:"upstream"`
	WafPolicy json.RawMessage `json:"waf_policy"`
	Status    string          `json:"status"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

type RuleRow struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Name      string    `json:"name"`
	Source    string    `json:"source"`
	Phase     int       `json:"phase"`
	Severity  string    `json:"severity"`
	DSL       string    `json:"dsl"`
	Enabled   bool      `json:"enabled"`
	Tags      []string  `json:"tags"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type AlertRow struct {
	ID         string          `json:"id"`
	TenantID   string          `json:"tenant_id"`
	SiteID     *string         `json:"site_id,omitempty"`
	Severity   string          `json:"severity"`
	Kind       string          `json:"kind"`
	Summary    string          `json:"summary"`
	Details    json.RawMessage `json:"details"`
	State      string          `json:"state"`
	CreatedAt  time.Time       `json:"created_at"`
	ResolvedAt *time.Time      `json:"resolved_at,omitempty"`
}

type AuditRow struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	ActorUserID *string   `json:"actor_user_id,omitempty"`
	Action      string    `json:"action"`
	TargetKind  string    `json:"target_kind"`
	TargetID    *string   `json:"target_id,omitempty"`
	IP          *string   `json:"ip,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

type DashboardStats struct {
	TotalSites     int `json:"total_sites"`
	ActiveSites    int `json:"active_sites"`
	TotalRules     int `json:"total_rules"`
	EnabledRules   int `json:"enabled_rules"`
	OpenAlerts     int `json:"open_alerts"`
	CriticalAlerts int `json:"critical_alerts"`
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

// ValidatePassword looks up the user by email and verifies the plaintext
// password against the stored argon2id hash. It returns the user's real
// tenant_id so the issued token carries the correct tenant (not a hardcoded
// one), which is what makes the per-tenant RLS + query predicates actually
// isolate tenants. Returns (true, userID, tenantID, role, nil) on success.
//
// NOTE: pre-auth lookup is intentionally by email (across tenants). Under a
// future non-superuser DB role with FORCE RLS this needs an RLS carve-out for
// the users table (SECURITY DEFINER fn or a login-lookup policy) — see the
// migration 0003 runbook.
func (s *Store) ValidatePassword(ctx context.Context, tenantID, email, password string) (bool, string, string, string, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, "system")
	if err != nil {
		return false, "", "", "", err
	}
	defer tx.Rollback(ctx)

	// Cross-tenant pre-auth lookup via the SECURITY DEFINER carve-out (works
	// under both the superuser and the non-superuser sentinel_app role); see
	// migration 0004.
	var userID, userTenantID, role, pwdHash string
	err = tx.QueryRow(ctx,
		`SELECT id, tenant_id, role, password_hash FROM sentinel_auth_lookup($1)`,
		email).Scan(&userID, &userTenantID, &role, &pwdHash)
	if err != nil {
		// User not found: still run argon2 against a dummy hash so the response
		// time matches the found-but-wrong-password path (no enumeration oracle).
		checkPassword(password, dummyPasswordHash)
		return false, "", "", "", nil
	}
	tx.Commit(ctx)

	if !checkPassword(password, pwdHash) {
		return false, "", "", "", nil
	}
	return true, userID, userTenantID, role, nil
}

// ListAllActiveSites returns all non-deleted sites across EVERY tenant. It is
// used only by the internal data-plane config sync: the shared proxy serves all
// tenants' sites, so this path must not be tenant-scoped (unlike ListSites,
// which is per-tenant for the dashboard). Intentionally node-global.
//
// NOTE: under a non-superuser role with FORCE RLS this returns nothing unless
// granted an RLS bypass for this path — see the migration 0003 runbook.
func (s *Store) ListAllActiveSites(ctx context.Context) ([]SiteRow, error) {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return nil, fmt.Errorf("store: pool is not a *pgxPool")
	}
	// Node-global list via the SECURITY DEFINER carve-out (see migration 0004),
	// so this works under the non-superuser sentinel_app role with FORCE RLS.
	rows, err := pg.pool.Query(ctx,
		`SELECT id, tenant_id, name, domains, upstream, waf_policy, status, created_at, updated_at
		 FROM sentinel_active_sites()`)
	if err != nil {
		return nil, fmt.Errorf("store: list all active sites: %w", err)
	}
	defer rows.Close()

	var sites []SiteRow
	for rows.Next() {
		var r SiteRow
		if err := rows.Scan(&r.ID, &r.TenantID, &r.Name, &r.Domains,
			&r.Upstream, &r.WafPolicy, &r.Status, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		sites = append(sites, r)
	}
	return sites, rows.Err()
}

// checkPassword verifies plaintext against "argon2id$<hexSalt>$<hexHash>".
func checkPassword(plain, stored string) bool {
	parts := strings.SplitN(stored, "$", 3)
	if len(parts) != 3 || parts[0] != "argon2id" {
		return false
	}
	salt, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}
	expected, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	// Reject a malformed/corrupted row with an empty salt or hash segment: a
	// zero-length hash would make argon2 produce a zero-length digest and the
	// constant-time compare of two empty slices would succeed for ANY password.
	if len(salt) == 0 || len(expected) == 0 {
		return false
	}
	hash := argon2.IDKey([]byte(plain), salt, 1, 64*1024, 4, uint32(len(expected)))
	return subtle.ConstantTimeCompare(hash, expected) == 1
}

// dummyPasswordHash is a valid-format argon2id hash computed once at startup. It
// is verified against on the user-not-found login path so the response time of a
// failed login is the same whether or not the email exists — closing the timing
// side channel that would otherwise enumerate valid accounts.
var dummyPasswordHash = func() string {
	salt := []byte("sentinel-dummy16")
	h := argon2.IDKey([]byte("not-a-real-password"), salt, 1, 64*1024, 4, 32)
	return "argon2id$" + hex.EncodeToString(salt) + "$" + hex.EncodeToString(h)
}()

// ---------------------------------------------------------------------------
// DashboardStats
// ---------------------------------------------------------------------------

func (s *Store) GetDashboardStats(ctx context.Context, tenantID, userID string) (*DashboardStats, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var stats DashboardStats

	// Explicit tenant_id predicates (defense-in-depth): dashboard counts must
	// not leak other tenants' totals if RLS is inactive for the connecting role.
	err = tx.QueryRow(ctx,
		`SELECT
			COUNT(*) FILTER (WHERE TRUE),
			COUNT(*) FILTER (WHERE status = 'active')
		 FROM sites WHERE tenant_id = $1`, tenantID).Scan(&stats.TotalSites, &stats.ActiveSites)
	if err != nil {
		return nil, fmt.Errorf("store: sites count: %w", err)
	}

	err = tx.QueryRow(ctx,
		`SELECT
			COUNT(*) FILTER (WHERE TRUE),
			COUNT(*) FILTER (WHERE enabled = true)
		 FROM rules WHERE tenant_id = $1`, tenantID).Scan(&stats.TotalRules, &stats.EnabledRules)
	if err != nil {
		return nil, fmt.Errorf("store: rules count: %w", err)
	}

	err = tx.QueryRow(ctx,
		`SELECT
			COUNT(*) FILTER (WHERE state = 'open'),
			COUNT(*) FILTER (WHERE state = 'open' AND severity = 'critical')
		 FROM alerts WHERE tenant_id = $1`, tenantID).Scan(&stats.OpenAlerts, &stats.CriticalAlerts)
	if err != nil {
		return nil, fmt.Errorf("store: alerts count: %w", err)
	}

	return &stats, tx.Commit(ctx)
}

// ConnRoleIsPrivileged reports whether the role the control plane connects as is
// a Postgres SUPERUSER or has BYPASSRLS — either of which makes FORCE ROW LEVEL
// SECURITY (the backstop for tenant isolation) a silent no-op. Used for a
// boot-time safety assertion so we never run multi-tenant on a role that
// bypasses RLS. Returns the role name for diagnostics.
func (s *Store) ConnRoleIsPrivileged(ctx context.Context) (privileged bool, role string, err error) {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return false, "", fmt.Errorf("store: pool is not a *pgxPool")
	}
	err = pg.pool.QueryRow(ctx,
		`SELECT current_user, rolsuper OR rolbypassrls
		   FROM pg_roles WHERE rolname = current_user`).Scan(&role, &privileged)
	return privileged, role, err
}

// ---------------------------------------------------------------------------
// Sites
// ---------------------------------------------------------------------------

func (s *Store) ListSites(ctx context.Context, tenantID, userID string) ([]SiteRow, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	// Explicit tenant predicate (defense-in-depth): isolation holds even if RLS
	// is bypassed (e.g. the app connects as a superuser/owner). See migration
	// 0003 for the RLS-layer hardening.
	rows, err := tx.Query(ctx,
		`SELECT id, tenant_id, name, domains, upstream, waf_policy, status, created_at, updated_at
		 FROM sites WHERE tenant_id = $1 ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("store: list sites: %w", err)
	}
	defer rows.Close()

	var sites []SiteRow
	for rows.Next() {
		var r SiteRow
		if err := rows.Scan(&r.ID, &r.TenantID, &r.Name, &r.Domains,
			&r.Upstream, &r.WafPolicy, &r.Status, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		sites = append(sites, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	tx.Commit(ctx)
	return sites, nil
}

type CreateSiteRequest struct {
	Name      string          `json:"name"`
	Domains   []string        `json:"domains"`
	Upstream  json.RawMessage `json:"upstream"`
	WafPolicy json.RawMessage `json:"waf_policy"`
}

func (s *Store) CreateSite(ctx context.Context, tenantID, userID string, req CreateSiteRequest) (*SiteRow, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var r SiteRow
	err = tx.QueryRow(ctx,
		`INSERT INTO sites (tenant_id, name, domains, upstream, waf_policy)
		 VALUES ($1,$2,$3,$4,$5)
		 RETURNING id, tenant_id, name, domains, upstream, waf_policy, status, created_at, updated_at`,
		tenantID, req.Name, req.Domains, req.Upstream, req.WafPolicy,
	).Scan(&r.ID, &r.TenantID, &r.Name, &r.Domains, &r.Upstream, &r.WafPolicy, &r.Status, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("store: create site: %w", err)
	}

	return &r, tx.Commit(ctx)
}

func (s *Store) GetSite(ctx context.Context, tenantID, siteID string) (*SiteRow, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, tenantID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var r SiteRow
	err = tx.QueryRow(ctx,
		`SELECT id, tenant_id, name, domains, upstream, waf_policy, status, created_at, updated_at
		 FROM sites WHERE id = $1 AND tenant_id = $2`,
		siteID, tenantID,
	).Scan(&r.ID, &r.TenantID, &r.Name, &r.Domains, &r.Upstream, &r.WafPolicy, &r.Status, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("store: get site: %w", err)
	}
	return &r, tx.Commit(ctx)
}

// UpdateSiteRequest holds the fields that can be changed on an existing site.
type UpdateSiteRequest struct {
	Name      *string         `json:"name,omitempty"`
	Domains   []string        `json:"domains,omitempty"`
	Upstream  json.RawMessage `json:"upstream,omitempty"`
	WafPolicy json.RawMessage `json:"waf_policy,omitempty"`
}

func (s *Store) UpdateSite(ctx context.Context, tenantID, userID, siteID string, req UpdateSiteRequest) (*SiteRow, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var r SiteRow
	err = tx.QueryRow(ctx,
		`UPDATE sites
		 SET name       = COALESCE($3, name),
		     domains    = COALESCE($4, domains),
		     upstream   = COALESCE($5, upstream),
		     waf_policy = COALESCE($6, waf_policy),
		     updated_at = now()
		 WHERE id = $1 AND tenant_id = $2
		 RETURNING id, tenant_id, name, domains, upstream, waf_policy, status, created_at, updated_at`,
		siteID, tenantID, req.Name, nullableStringArray(req.Domains), nullableJSON(req.Upstream), nullableJSON(req.WafPolicy),
	).Scan(&r.ID, &r.TenantID, &r.Name, &r.Domains, &r.Upstream, &r.WafPolicy, &r.Status, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("store: update site: %w", err)
	}
	return &r, tx.Commit(ctx)
}

// nullableStringArray returns nil for empty slices.
func nullableStringArray(s []string) interface{} {
	if len(s) == 0 {
		return nil
	}
	return s
}

func (s *Store) DeleteSite(ctx context.Context, tenantID, siteID string) error {
	tx, err := s.pool.BeginTenant(ctx, tenantID, tenantID)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = tx.Exec(ctx,
		`DELETE FROM sites WHERE id = $1 AND tenant_id = $2`,
		siteID, tenantID); err != nil {
		return fmt.Errorf("store: delete site: %w", err)
	}
	return tx.Commit(ctx)
}

func (s *Store) UpdateSiteStatus(ctx context.Context, tenantID, siteID, status string) error {
	tx, err := s.pool.BeginTenant(ctx, tenantID, tenantID)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = tx.Exec(ctx,
		`UPDATE sites SET status = $1, updated_at = now() WHERE id = $2 AND tenant_id = $3`,
		status, siteID, tenantID); err != nil {
		return fmt.Errorf("store: update site status: %w", err)
	}
	return tx.Commit(ctx)
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

func (s *Store) ListRules(ctx context.Context, tenantID, userID string) ([]RuleRow, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	// Explicit tenant predicate (defense-in-depth): see ListSites / migration 0003.
	rows, err := tx.Query(ctx,
		`SELECT id, tenant_id, name, source, phase, severity, dsl, enabled, tags, created_at, updated_at
		 FROM rules WHERE tenant_id = $1 ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("store: list rules: %w", err)
	}
	defer rows.Close()

	var rules []RuleRow
	for rows.Next() {
		var r RuleRow
		if err := rows.Scan(&r.ID, &r.TenantID, &r.Name, &r.Source, &r.Phase,
			&r.Severity, &r.DSL, &r.Enabled, &r.Tags, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	tx.Commit(ctx)
	return rules, nil
}

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------

func (s *Store) ListAlerts(ctx context.Context, tenantID, userID string, stateFilter string) ([]AlertRow, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	// Explicit tenant predicate (defense-in-depth): see ListSites / migration 0003.
	query := `SELECT id, tenant_id, site_id, severity, kind, summary, details, state, created_at, resolved_at
	          FROM alerts WHERE tenant_id = $1`
	args := []any{tenantID}
	if stateFilter != "" && stateFilter != "all" {
		query += ` AND state = $2`
		args = append(args, stateFilter)
	}
	query += ` ORDER BY created_at DESC LIMIT 200`

	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list alerts: %w", err)
	}
	defer rows.Close()

	var alerts []AlertRow
	for rows.Next() {
		var r AlertRow
		if err := rows.Scan(&r.ID, &r.TenantID, &r.SiteID, &r.Severity, &r.Kind,
			&r.Summary, &r.Details, &r.State, &r.CreatedAt, &r.ResolvedAt); err != nil {
			return nil, err
		}
		alerts = append(alerts, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	tx.Commit(ctx)
	return alerts, nil
}

func (s *Store) AckAlert(ctx context.Context, tenantID, userID, alertID string) error {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := tx.Exec(ctx,
		`UPDATE alerts SET state = 'acked' WHERE id = $1 AND tenant_id = $2`,
		alertID, tenantID); err != nil {
		return fmt.Errorf("store: ack alert: %w", err)
	}
	return tx.Commit(ctx)
}

func (s *Store) ResolveAlert(ctx context.Context, tenantID, userID, alertID string) error {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := tx.Exec(ctx,
		`UPDATE alerts SET state = 'resolved', resolved_at = now() WHERE id = $1 AND tenant_id = $2`,
		alertID, tenantID); err != nil {
		return fmt.Errorf("store: resolve alert: %w", err)
	}
	return tx.Commit(ctx)
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

func (s *Store) ListAuditLogs(ctx context.Context, tenantID, userID string, limit int) ([]AuditRow, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	if limit <= 0 {
		limit = 100
	}

	rows, err := tx.Query(ctx,
		`SELECT id, tenant_id, actor_user_id, action, target_kind, target_id, ip::text, created_at
		 FROM audit_logs ORDER BY created_at DESC LIMIT $1`,
		limit)
	if err != nil {
		return nil, fmt.Errorf("store: list audit: %w", err)
	}
	defer rows.Close()

	var entries []AuditRow
	for rows.Next() {
		var r AuditRow
		if err := rows.Scan(&r.ID, &r.TenantID, &r.ActorUserID, &r.Action,
			&r.TargetKind, &r.TargetID, &r.IP, &r.CreatedAt); err != nil {
			return nil, err
		}
		entries = append(entries, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	tx.Commit(ctx)
	return entries, nil
}

// ---------------------------------------------------------------------------
// Audit write
// ---------------------------------------------------------------------------

// WriteAuditRequest carries the fields for a single audit log write.
type WriteAuditRequest struct {
	TenantID    string
	ActorUserID *string // nil for system actions
	Action      string  // dot-notation: e.g. "user.login", "site.create"
	TargetKind  string  // e.g. "user", "site", "alert"
	TargetID    *string // UUID of the affected resource (may be nil)
	IP          *string
	UserAgent   *string
	Diff        json.RawMessage // optional before/after JSON
}

// WriteAuditLog inserts a signed audit entry.  hmacKey is used to compute the
// tamper-evident HMAC stored alongside the record; use a stable secret loaded
// from the environment.
func (s *Store) WriteAuditLog(ctx context.Context, req WriteAuditRequest, hmacKey []byte) error {
	// Sign over a PERSISTED, deterministic timestamp (truncated to Postgres's
	// microsecond precision so it round-trips exactly) plus every material
	// field, and store that same created_at — otherwise the HMAC could never be
	// recomputed and the "tamper-evident" property would be cosmetic. See
	// VerifyAuditLog, which recomputes and compares.
	createdAt := time.Now().UTC().Truncate(time.Microsecond)
	sig := auditMAC(hmacKey, req.TenantID, req.ActorUserID, req.Action, req.TargetKind,
		req.TargetID, req.IP, req.UserAgent, req.Diff, createdAt)

	// Use a system-level tenant context for the write.  The INSERT policy on
	// audit_logs has WITH CHECK (true) so any tenant_id is accepted.
	tx, err := s.pool.BeginTenant(ctx, req.TenantID, "system")
	if err != nil {
		return fmt.Errorf("store: audit write begin: %w", err)
	}
	defer tx.Rollback(ctx)

	err = tx.Exec(ctx,
		`INSERT INTO audit_logs
			(tenant_id, actor_user_id, action, target_kind, target_id, ip, user_agent, diff, created_at, hmac)
		 VALUES ($1, $2, $3, $4, $5, $6::inet, $7, $8, $9, $10)`,
		req.TenantID,
		req.ActorUserID,
		req.Action,
		req.TargetKind,
		req.TargetID,
		req.IP,
		req.UserAgent,
		nullableJSON(req.Diff),
		createdAt,
		sig,
	)
	if err != nil {
		return fmt.Errorf("store: audit insert: %w", err)
	}
	return tx.Commit(ctx)
}

// auditMAC computes the tamper-evidence HMAC over the persisted, immutable
// fields of an audit row. Used by both WriteAuditLog and VerifyAuditLog so the
// signature is reproducible. The timestamp is formatted at microsecond
// precision to match what Postgres stores.
func auditMAC(key []byte, tenantID string, actor *string, action, targetKind string,
	targetID, ip, userAgent *string, diff json.RawMessage, createdAt time.Time) []byte {
	mac := hmac.New(sha256.New, key)
	fmt.Fprintf(mac, "%s|%s|%s|%s|%s|%s|%s|%s|%s",
		tenantID,
		strPtr(actor),
		action,
		targetKind,
		strPtr(targetID),
		strPtr(ip),
		strPtr(userAgent),
		string(diff),
		createdAt.UTC().Format(time.RFC3339Nano),
	)
	return mac.Sum(nil)
}

// VerifyAuditLog recomputes the HMAC over every stored audit row (optionally
// scoped to a tenant; "" = all) and returns how many were checked plus the IDs
// of any whose stored HMAC does not match — proving the audit log is genuinely
// tamper-evident (a mismatch means the row was altered or signed with a
// different key). limit <= 0 checks all rows.
func (s *Store) VerifyAuditLog(ctx context.Context, tenantID string, hmacKey []byte, limit int) (checked int, bad []string, err error) {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return 0, nil, fmt.Errorf("store: pool is not a *pgxPool")
	}
	q := `SELECT id, tenant_id, actor_user_id, action, target_kind, target_id,
	             host(ip), user_agent, diff, created_at, hmac
	        FROM audit_logs`
	args := []any{}
	if tenantID != "" {
		q += ` WHERE tenant_id = $1`
		args = append(args, tenantID)
	}
	q += ` ORDER BY created_at DESC`
	if limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", limit)
	}
	rows, err := pg.pool.Query(ctx, q, args...)
	if err != nil {
		return 0, nil, fmt.Errorf("store: audit verify query: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, tid, action, targetKind string
		var actor, targetID, ip, ua *string
		var diff json.RawMessage
		var createdAt time.Time
		var storedMAC []byte
		if err := rows.Scan(&id, &tid, &actor, &action, &targetKind, &targetID,
			&ip, &ua, &diff, &createdAt, &storedMAC); err != nil {
			return checked, bad, err
		}
		checked++
		want := auditMAC(hmacKey, tid, actor, action, targetKind, targetID, ip, ua, diff, createdAt)
		if !hmac.Equal(want, storedMAC) {
			bad = append(bad, id)
		}
	}
	return checked, bad, rows.Err()
}

func strPtr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func nullableJSON(raw json.RawMessage) interface{} {
	if len(raw) == 0 {
		return nil
	}
	return raw
}

// ---------------------------------------------------------------------------
// Rule CRUD
// ---------------------------------------------------------------------------

// CreateRuleRequest carries the fields for inserting a new custom rule.
type CreateRuleRequest struct {
	Name     string   `json:"name"     binding:"required"`
	Source   string   `json:"source"`
	Phase    int      `json:"phase"`
	Severity string   `json:"severity"`
	DSL      string   `json:"dsl"`
	Tags     []string `json:"tags"`
	Enabled  *bool    `json:"enabled"`
}

func (s *Store) CreateRule(ctx context.Context, tenantID, userID string, req CreateRuleRequest) (*RuleRow, error) {
	if req.Source == "" {
		req.Source = "custom"
	}
	if req.Severity == "" {
		req.Severity = "medium"
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	if req.Tags == nil {
		req.Tags = []string{}
	}

	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var r RuleRow
	err = tx.QueryRow(ctx,
		`INSERT INTO rules (tenant_id, name, source, phase, severity, dsl, enabled, tags)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		 RETURNING id, tenant_id, name, source, phase, severity, dsl, enabled, tags, created_at, updated_at`,
		tenantID, req.Name, req.Source, req.Phase, req.Severity, req.DSL, enabled, req.Tags,
	).Scan(&r.ID, &r.TenantID, &r.Name, &r.Source, &r.Phase, &r.Severity,
		&r.DSL, &r.Enabled, &r.Tags, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("store: create rule: %w", err)
	}
	return &r, tx.Commit(ctx)
}

func (s *Store) ToggleRule(ctx context.Context, tenantID, userID, ruleID string, enabled bool) error {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := tx.Exec(ctx,
		`UPDATE rules SET enabled=$3, updated_at=NOW() WHERE id=$1 AND tenant_id=$2`,
		ruleID, tenantID, enabled); err != nil {
		return fmt.Errorf("store: toggle rule: %w", err)
	}
	return tx.Commit(ctx)
}

func (s *Store) DeleteRule(ctx context.Context, tenantID, userID, ruleID string) error {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := tx.Exec(ctx,
		`DELETE FROM rules WHERE id=$1 AND tenant_id=$2 AND source NOT IN ('crs','community')`,
		ruleID, tenantID); err != nil {
		return fmt.Errorf("store: delete rule: %w", err)
	}
	return tx.Commit(ctx)
}
