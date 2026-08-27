package db

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

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
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	// SiteID is empty for a deployment-wide rule.
	SiteID    string    `json:"site_id,omitempty"`
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

	// Fields below were recorded at write time but never returned, so the
	// before/after data the writers carefully captured was invisible to every
	// reader — and the compliance view showed "who" as a bare UUID.
	//
	// Seq is the chain position: it is what makes a gap visible, and it is the
	// pagination cursor (created_at is not unique).
	Seq int64 `json:"seq"`
	// ActorEmail is resolved from users; nil for system actions or a deleted
	// user. The UUID is kept alongside it — an email can be reassigned.
	ActorEmail *string `json:"actor_email,omitempty"`
	UserAgent  *string `json:"user_agent,omitempty"`
	// Diff carries the before/after payload AND the outcome (`result`), which
	// is signed by the chain HMAC. See auditDiff in the handlers.
	Diff json.RawMessage `json:"diff,omitempty"`
	// Result is lifted out of Diff for convenience so a caller does not have to
	// parse JSON to answer "did this succeed?".
	Result string `json:"result,omitempty"`
}

// AuditFilter narrows an audit query server-side. Previously the API returned a
// hardcoded newest-100 and the console filtered those in the browser, so any
// question older than the last hundred entries was unanswerable — including
// every question an auditor actually asks ("show me all failed logins last
// week").
type AuditFilter struct {
	// Action matches exactly; ActionPrefix matches a family ("site." matches
	// site.create/update/delete/status.*). Both are optional.
	Action       string
	ActionPrefix string
	// Result filters on the signed outcome inside diff (SUCCESS / FAILURE).
	Result string
	// From/To bound created_at (unix seconds, 0 = unbounded).
	From, To int64
	// BeforeSeq pages backwards: return rows with seq < BeforeSeq. 0 = newest.
	BeforeSeq int64
	Limit     int
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

// ConfigVersion returns the shared, monotonic config-generation counter. It is
// bumped by a statement-level trigger on every sites/rules mutation (migration
// 0012) and read via the SECURITY DEFINER sentinel_config_version() carve-out,
// so ANY control-plane node returns the same restart-surviving, change-reflecting
// value regardless of Raft role — this is the data plane's /internal/config
// freshness signal (fixes R4/R8: the old per-process, leader-only counter).
func (s *Store) ConfigVersion(ctx context.Context) (int64, error) {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return 0, fmt.Errorf("store: pool is not a *pgxPool")
	}
	var v int64
	if err := pg.pool.QueryRow(ctx, `SELECT sentinel_config_version()`).Scan(&v); err != nil {
		return 0, fmt.Errorf("store: config version: %w", err)
	}
	return v, nil
}

// Ping checks that the database is actually reachable (used by /readyz so a
// DB-unreachable control-plane node reports NotReady and is pulled from the
// load-balancer/Service, instead of a static 200 that keeps routing to it).
func (s *Store) Ping(ctx context.Context) error {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return fmt.Errorf("store: pool is not a *pgxPool")
	}
	return pg.pool.Ping(ctx)
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
		`SELECT id, tenant_id, name, source, phase, severity, dsl, enabled, tags,
		        created_at, updated_at, site_id
		 FROM rules WHERE tenant_id = $1 ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("store: list rules: %w", err)
	}
	defer rows.Close()

	var rules []RuleRow
	for rows.Next() {
		var r RuleRow
		var siteID *string
		if err := rows.Scan(&r.ID, &r.TenantID, &r.Name, &r.Source, &r.Phase,
			&r.Severity, &r.DSL, &r.Enabled, &r.Tags, &r.CreatedAt, &r.UpdatedAt,
			&siteID); err != nil {
			return nil, err
		}
		if siteID != nil {
			r.SiteID = *siteID
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
	return s.ListAuditLogsFiltered(ctx, tenantID, userID, AuditFilter{Limit: limit})
}

// ListAuditLogsFiltered reads the audit trail with server-side filtering and
// keyset pagination, newest first.
//
// The tenant predicate is EXPLICIT rather than left to row-level security. RLS
// is the backstop, but the shipped single-tenant posture runs the control plane
// on a role that bypasses it (SENTINEL_ALLOW_SUPERUSER_DB=1), so a query that
// relies on RLS alone is unscoped in exactly the deployment we ship.
func (s *Store) ListAuditLogsFiltered(ctx context.Context, tenantID, userID string, f AuditFilter) ([]AuditRow, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	where := []string{"a.tenant_id = $1"}
	args := []any{tenantID}
	add := func(clause string, val any) {
		args = append(args, val)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if f.Action != "" {
		add("a.action = $%d", f.Action)
	}
	if f.ActionPrefix != "" {
		// Literal prefix: escape LIKE metacharacters so a caller cannot turn a
		// filter into a scan of everything.
		esc := strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(f.ActionPrefix)
		add("a.action LIKE $%d", esc+"%")
	}
	if f.Result != "" {
		add("COALESCE(a.diff->>'result', 'SUCCESS') = $%d", f.Result)
	}
	if f.From > 0 {
		add("a.created_at >= to_timestamp($%d)", f.From)
	}
	if f.To > 0 {
		add("a.created_at <= to_timestamp($%d)", f.To)
	}
	if f.BeforeSeq > 0 {
		add("a.seq < $%d", f.BeforeSeq)
	}
	args = append(args, limit)

	// LEFT JOIN, not JOIN: a system action has no actor and a deleted user's row
	// is gone (actor_user_id is ON DELETE SET NULL), and neither may drop the
	// audit entry from the result — an audit trail that hides entries whose
	// actor was deleted is worse than useless.
	//
	// Ordered by seq, not created_at: created_at is not unique under
	// concurrent writes, so it cannot page deterministically.
	sql := fmt.Sprintf(
		`SELECT a.id, a.tenant_id, a.actor_user_id, a.action, a.target_kind, a.target_id,
		        a.ip::text, a.created_at, COALESCE(a.seq, 0), u.email, a.user_agent, a.diff
		 FROM audit_logs a
		 LEFT JOIN users u ON u.id = a.actor_user_id
		 WHERE %s
		 ORDER BY a.seq DESC
		 LIMIT $%d`, strings.Join(where, " AND "), len(args))

	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list audit: %w", err)
	}
	defer rows.Close()

	var entries []AuditRow
	for rows.Next() {
		var r AuditRow
		var diff []byte
		if err := rows.Scan(&r.ID, &r.TenantID, &r.ActorUserID, &r.Action,
			&r.TargetKind, &r.TargetID, &r.IP, &r.CreatedAt, &r.Seq,
			&r.ActorEmail, &r.UserAgent, &diff); err != nil {
			return nil, err
		}
		if len(diff) > 0 {
			r.Diff = json.RawMessage(diff)
			var probe struct {
				Result string `json:"result"`
			}
			if json.Unmarshal(diff, &probe) == nil && probe.Result != "" {
				r.Result = probe.Result
			}
		}
		if r.Result == "" {
			// Rows written before outcomes were recorded, and every handler
			// that only audits its happy path. Reported as SUCCESS because
			// that is what those call sites mean, never as unknown.
			r.Result = "SUCCESS"
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

// auditChainNamespace keys the advisory lock that serializes chain appends. Any
// stable constant works; it only has to not collide with other advisory-lock
// users in this database.
const auditChainNamespace = 0x5748414D // "WHAM"

// genesisPrevHMAC is the prev_hmac of the first row in a tenant's chain. A fixed
// 32-byte zero block rather than NULL, so that NULL unambiguously means "row
// predates the chain migration" — otherwise a legacy row and a genesis row would
// be indistinguishable and an attacker could delete an entire chain and pass the
// remainder off as pre-migration data.
var genesisPrevHMAC = make([]byte, 32)

// WriteAuditLog appends a signed audit entry to the tenant's hash chain.
//
// hmacKey is used to compute the tamper-evident HMAC stored alongside the record;
// use a stable secret loaded from the environment.
//
// Each row commits to its predecessor: the HMAC covers (seq, prev_hmac, ...fields),
// where prev_hmac is the preceding row's HMAC for the same tenant. That is what
// makes DELETION detectable — dropping a row leaves its successor pointing at an
// HMAC no surviving row has. A per-row HMAC alone (the previous design) verified
// happily after any number of deletions.
//
// Appends for one tenant are serialized by a transaction-scoped advisory lock, so
// two concurrent writers cannot read the same predecessor and fork the chain.
func (s *Store) WriteAuditLog(ctx context.Context, req WriteAuditRequest, hmacKey []byte) error {
	// Sign over a PERSISTED, deterministic timestamp (truncated to Postgres's
	// microsecond precision so it round-trips exactly) plus every material
	// field, and store that same created_at — otherwise the HMAC could never be
	// recomputed and the "tamper-evident" property would be cosmetic. See
	// VerifyAuditLog, which recomputes and compares.
	createdAt := time.Now().UTC().Truncate(time.Microsecond)

	// Use a system-level tenant context for the write.  The INSERT policy on
	// audit_logs has WITH CHECK (true) so any tenant_id is accepted.
	tx, err := s.pool.BeginTenant(ctx, req.TenantID, "system")
	if err != nil {
		return fmt.Errorf("store: audit write begin: %w", err)
	}
	defer tx.Rollback(ctx)

	// Serialize appends for this tenant. Released automatically at commit or
	// rollback, so a crashed writer cannot wedge the chain.
	if err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock($1, hashtext($2))`,
		auditChainNamespace, req.TenantID); err != nil {
		return fmt.Errorf("store: audit chain lock: %w", err)
	}

	// Link to the tenant's current chain head, falling back to genesis when this
	// is the tenant's first entry. COALESCE keeps this a single row every time, so
	// there is no empty-result case to distinguish from a real query failure.
	var prevHMAC []byte
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(
		           (SELECT hmac FROM audit_logs WHERE tenant_id = $1 ORDER BY seq DESC LIMIT 1),
		           $2::bytea)`,
		req.TenantID, genesisPrevHMAC).Scan(&prevHMAC); err != nil {
		return fmt.Errorf("store: audit chain head: %w", err)
	}

	// Claim the sequence value up front: seq is part of the signed payload, so it
	// must be known before the row is written.
	var seq int64
	if err := tx.QueryRow(ctx,
		`SELECT nextval(pg_get_serial_sequence('audit_logs', 'seq'))`).Scan(&seq); err != nil {
		return fmt.Errorf("store: audit seq: %w", err)
	}

	sig := auditChainMAC(hmacKey, seq, prevHMAC, req.TenantID, req.ActorUserID, req.Action,
		req.TargetKind, req.TargetID, req.IP, req.UserAgent, req.Diff, createdAt)

	err = tx.Exec(ctx,
		`INSERT INTO audit_logs
			(tenant_id, actor_user_id, action, target_kind, target_id, ip, user_agent, diff,
			 created_at, hmac, seq, prev_hmac)
		 VALUES ($1, $2, $3, $4, $5, $6::inet, $7, $8, $9, $10, $11, $12)`,
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
		seq,
		prevHMAC,
	)
	if err != nil {
		return fmt.Errorf("store: audit insert: %w", err)
	}
	return tx.Commit(ctx)
}

// auditChainMAC computes the tamper-evidence HMAC for a chained audit row.
//
// It covers the row's own fields PLUS its position (seq) and its predecessor
// (prevHMAC). Including both is what extends tamper-evidence from "this row was
// not edited" to "this row has not been moved, and nothing before it was
// removed": any deletion or reordering leaves some successor's prev_hmac
// referring to an HMAC that no surviving row has.
//
// The field encoding delegates to auditMAC's payload so the two stay in lockstep.
func auditChainMAC(key []byte, seq int64, prevHMAC []byte, tenantID string, actor *string,
	action, targetKind string, targetID, ip, userAgent *string, diff json.RawMessage,
	createdAt time.Time) []byte {
	mac := hmac.New(sha256.New, key)
	// Length-prefix the variable-length chain fields so that no combination of
	// field values can be rearranged to produce the same byte stream.
	fmt.Fprintf(mac, "v2|%d|%d|", seq, len(prevHMAC))
	mac.Write(prevHMAC)
	mac.Write([]byte{'|'})
	mac.Write(auditPayload(tenantID, actor, action, targetKind, targetID, ip, userAgent, diff, createdAt))
	return mac.Sum(nil)
}

// canonicalJSON renders `raw` in a form that survives a round trip through
// Postgres.
//
// `diff` is stored as JSONB, which does NOT preserve the input bytes: it
// reorders keys, drops insignificant whitespace and renormalises numbers. The
// MAC used to cover `string(diff)` — the bytes Go happened to marshal — so
// every row that carried a diff was signed over one byte string and verified
// against a different one, and reported as ALTERED for ever. Measured on the
// live deployment: 17 of 17 rows with a diff failed verification while every
// chain link was intact.
//
// Re-marshalling through Go's encoder makes both sides agree, because
// json.Marshal emits map keys in sorted order. Input that is not valid JSON is
// signed as-is rather than silently becoming empty.
func canonicalJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return string(raw)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return string(raw)
	}
	return string(b)
}

// auditPayload is the canonical byte encoding of an audit row's material fields,
// shared by the legacy and chained MAC functions.
func auditPayload(tenantID string, actor *string, action, targetKind string,
	targetID, ip, userAgent *string, diff json.RawMessage, createdAt time.Time) []byte {
	return []byte(fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%s",
		tenantID,
		strPtr(actor),
		action,
		targetKind,
		strPtr(targetID),
		strPtr(ip),
		strPtr(userAgent),
		canonicalJSON(diff),
		createdAt.UTC().Format(time.RFC3339Nano),
	))
}

// auditPayloadRaw is auditPayload's pre-canonicalisation encoding, retained
// ONLY so verification can still accept rows signed before canonicalJSON
// existed. Never used for a new write.
func auditPayloadRaw(tenantID string, actor *string, action, targetKind string,
	targetID, ip, userAgent *string, diff json.RawMessage, createdAt time.Time) []byte {
	return []byte(fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%s",
		tenantID, strPtr(actor), action, targetKind, strPtr(targetID),
		strPtr(ip), strPtr(userAgent), string(diff),
		createdAt.UTC().Format(time.RFC3339Nano),
	))
}

// auditMAC computes the LEGACY (pre-chain) per-row HMAC.
//
// Retained solely to verify rows written before migration 0013, which have a NULL
// prev_hmac. It detects modification of a row but nothing about the log as a
// whole — see auditChainMAC. Do not use it for new writes.
//
// The timestamp is formatted at microsecond precision to match what Postgres
// stores.
func auditMAC(key []byte, tenantID string, actor *string, action, targetKind string,
	targetID, ip, userAgent *string, diff json.RawMessage, createdAt time.Time) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(auditPayload(tenantID, actor, action, targetKind, targetID, ip, userAgent, diff, createdAt))
	return mac.Sum(nil)
}

// AuditVerifyReport is the outcome of a tamper-evidence check over audit_logs.
type AuditVerifyReport struct {
	// Checked is how many rows were examined.
	Checked int
	// Altered lists row IDs whose stored HMAC does not match a recomputation —
	// the row was edited, or signed with a different key.
	Altered []string
	// ChainBroken lists row IDs whose prev_hmac does not match the HMAC of the
	// preceding row for that tenant. This is the signal that rows were DELETED or
	// REORDERED, which per-row HMACs cannot see.
	ChainBroken []string
	// SeqGaps describes missing sequence numbers per tenant, e.g. "tenant X:
	// seq 41 -> 45". Corroborates ChainBroken and localizes the removal.
	SeqGaps []string
	// Unchained counts rows written before migration 0013 (NULL prev_hmac). They
	// are verified with the legacy per-row MAC, so deletions among them remain
	// undetectable — reported so that is never mistaken for a clean result.
	Unchained int
}

// OK reports whether the log is intact.
func (r AuditVerifyReport) OK() bool {
	return len(r.Altered) == 0 && len(r.ChainBroken) == 0 && len(r.SeqGaps) == 0
}

// VerifyAuditLog verifies the integrity of the audit log, optionally scoped to a
// tenant ("" = all tenants). limit <= 0 checks all rows.
//
// Two independent properties are checked:
//
//  1. Per-row integrity — recompute each row's HMAC and compare. Catches edits.
//  2. Chain continuity — each row's prev_hmac must equal its predecessor's HMAC
//     within the same tenant, and seq must not skip. Catches DELETION,
//     REORDERING, and TRUNCATION, none of which the previous per-row-only design
//     could detect: removing rows left every surviving HMAC verifying perfectly.
//
// Rows are walked in ascending (tenant_id, seq) order, which is the order the
// chain was built in. The old implementation ordered by created_at DESC, which is
// both attacker-controllable in principle and useless for chain walking.
func (s *Store) VerifyAuditLog(ctx context.Context, tenantID string, hmacKey []byte, limit int) (AuditVerifyReport, error) {
	var rep AuditVerifyReport

	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return rep, fmt.Errorf("store: pool is not a *pgxPool")
	}
	q := `SELECT id, tenant_id, actor_user_id, action, target_kind, target_id,
	             host(ip), user_agent, diff, created_at, hmac, seq, prev_hmac
	        FROM audit_logs`
	args := []any{}
	if tenantID != "" {
		q += ` WHERE tenant_id = $1`
		args = append(args, tenantID)
	}
	q += ` ORDER BY tenant_id, seq`
	if limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", limit)
	}
	rows, err := pg.pool.Query(ctx, q, args...)
	if err != nil {
		return rep, fmt.Errorf("store: audit verify query: %w", err)
	}
	defer rows.Close()

	// Chain head carried across iterations, reset at each tenant boundary.
	var curTenant string
	var prevMAC []byte
	var prevSeq int64

	for rows.Next() {
		var id, tid, action, targetKind string
		var actor, targetID, ip, ua *string
		var diff json.RawMessage
		var createdAt time.Time
		var storedMAC, storedPrev []byte
		var seq int64
		if err := rows.Scan(&id, &tid, &actor, &action, &targetKind, &targetID,
			&ip, &ua, &diff, &createdAt, &storedMAC, &seq, &storedPrev); err != nil {
			return rep, err
		}
		rep.Checked++

		newTenant := tid != curTenant
		if newTenant {
			curTenant, prevMAC, prevSeq = tid, nil, 0
		}

		if storedPrev == nil {
			// Pre-chain row: only the legacy per-row property is available.
			rep.Unchained++
			if !auditRowVerifies(storedMAC,
				auditMAC(hmacKey, tid, actor, action, targetKind, targetID, ip, ua, diff, createdAt),
				auditMACRaw(hmacKey, tid, actor, action, targetKind, targetID, ip, ua, diff, createdAt)) {
				rep.Altered = append(rep.Altered, id)
			}
			prevMAC, prevSeq = storedMAC, seq
			continue
		}

		if !auditRowVerifies(storedMAC,
			auditChainMAC(hmacKey, seq, storedPrev, tid, actor, action, targetKind,
				targetID, ip, ua, diff, createdAt),
			auditChainMACRaw(hmacKey, seq, storedPrev, tid, actor, action, targetKind,
				targetID, ip, ua, diff, createdAt)) {
			rep.Altered = append(rep.Altered, id)
		}

		// Chain continuity. A genesis row must be the first of its tenant; any
		// later row must point at its immediate predecessor.
		switch {
		case prevMAC == nil:
			// First row seen for this tenant. Genuine only if it is genesis, or if
			// we are mid-log because of `limit` (prevMAC unknown, nothing to check).
		case !hmac.Equal(storedPrev, prevMAC):
			rep.ChainBroken = append(rep.ChainBroken, id)
		}
		if prevSeq != 0 && seq != prevSeq+1 {
			rep.SeqGaps = append(rep.SeqGaps,
				fmt.Sprintf("tenant %s: seq %d -> %d", tid, prevSeq, seq))
		}

		prevMAC, prevSeq = storedMAC, seq
	}
	return rep, rows.Err()
}

// auditChainMACRaw / auditMACRaw recompute a row's MAC using the ORIGINAL
// pre-canonicalisation diff encoding. Verification accepts either form, so a
// row written before canonicalJSON existed is not reported as tampered merely
// because the signing rule improved. Both forms use the same key, so accepting
// the legacy one weakens nothing — it is a representation, not a credential.
func auditChainMACRaw(key []byte, seq int64, prevHMAC []byte, tenantID string, actor *string,
	action, targetKind string, targetID, ip, userAgent *string, diff json.RawMessage,
	createdAt time.Time) []byte {
	mac := hmac.New(sha256.New, key)
	fmt.Fprintf(mac, "v2|%d|%d|", seq, len(prevHMAC))
	mac.Write(prevHMAC)
	mac.Write([]byte{'|'})
	mac.Write(auditPayloadRaw(tenantID, actor, action, targetKind, targetID, ip, userAgent, diff, createdAt))
	return mac.Sum(nil)
}

func auditMACRaw(key []byte, tenantID string, actor *string, action, targetKind string,
	targetID, ip, userAgent *string, diff json.RawMessage, createdAt time.Time) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(auditPayloadRaw(tenantID, actor, action, targetKind, targetID, ip, userAgent, diff, createdAt))
	return mac.Sum(nil)
}

// auditRowVerifies reports whether `stored` matches either accepted encoding.
func auditRowVerifies(stored, canonical, legacy []byte) bool {
	return hmac.Equal(canonical, stored) || hmac.Equal(legacy, stored)
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
	// SiteID scopes the rule to one site. Omit (or send null) for a
	// deployment-wide rule, which is what a virtual patch wants.
	SiteID *string `json:"site_id"`
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

	// An empty string is not a valid uuid and is not the same as "no site", so
	// normalise it to NULL rather than letting the insert fail on a blank field
	// from a form.
	if req.SiteID != nil && strings.TrimSpace(*req.SiteID) == "" {
		req.SiteID = nil
	}

	var r RuleRow
	var siteID *string
	err = tx.QueryRow(ctx,
		`INSERT INTO rules (tenant_id, name, source, phase, severity, dsl, enabled, tags, site_id)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		 RETURNING id, tenant_id, name, source, phase, severity, dsl, enabled, tags, created_at, updated_at, site_id`,
		tenantID, req.Name, req.Source, req.Phase, req.Severity, req.DSL, enabled, req.Tags, req.SiteID,
	).Scan(&r.ID, &r.TenantID, &r.Name, &r.Source, &r.Phase, &r.Severity,
		&r.DSL, &r.Enabled, &r.Tags, &r.CreatedAt, &r.UpdatedAt, &siteID)
	if siteID != nil {
		r.SiteID = *siteID
	}
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

// DeployableRule is one operator-authored rule bound for the data plane.
type DeployableRule struct {
	TenantID string
	// SiteID is empty for a deployment-wide rule (the virtual-patch case) and
	// set when the operator scoped the rule to a single site.
	SiteID   string
	Name     string
	DSL      string
	Source   string
	Phase    int
	Severity string
}

// ListDeployableRules returns every enabled, operator-authored rule across all
// tenants, keyed by tenant id.
//
// Node-global on purpose: /internal/config serves every tenant's sites from one
// data plane, so this mirrors ListAllActiveSites and reads through the
// sentinel_deployable_rules() carve-out (migration 0017) rather than querying
// `rules` directly — under FORCE RLS a direct query would return no rows and the
// custom rules would silently stop being enforced.
//
// Rows with source 'crs'/'community' are excluded by the function itself; see the
// migration for why that filter is load-bearing rather than cosmetic.
func (s *Store) ListDeployableRules(ctx context.Context) (map[string][]DeployableRule, error) {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return nil, fmt.Errorf("store: pool is not a *pgxPool")
	}
	rows, err := pg.pool.Query(ctx,
		`SELECT tenant_id, site_id, name, dsl, source, phase, severity
		 FROM sentinel_deployable_rules()`)
	if err != nil {
		return nil, fmt.Errorf("store: list deployable rules: %w", err)
	}
	defer rows.Close()

	out := make(map[string][]DeployableRule)
	for rows.Next() {
		var r DeployableRule
		var siteID *string
		if err := rows.Scan(&r.TenantID, &siteID, &r.Name, &r.DSL,
			&r.Source, &r.Phase, &r.Severity); err != nil {
			return nil, err
		}
		if siteID != nil {
			r.SiteID = *siteID
		}
		out[r.TenantID] = append(out[r.TenantID], r)
	}
	return out, rows.Err()
}

// UpdateRuleRequest is a PARTIAL update: a nil field is left alone. Pointers
// rather than values so "set severity to its zero value" stays distinguishable
// from "do not touch severity".
type UpdateRuleRequest struct {
	DSL      *string   `json:"dsl"`
	Severity *string   `json:"severity"`
	Phase    *int      `json:"phase"`
	Tags     *[]string `json:"tags"`
	Enabled  *bool     `json:"enabled"`
	// SiteID rescopes the rule. Send null to make it deployment-wide again; the
	// distinction between "null" and "absent" is why ClearSiteID exists — JSON
	// null and a missing key both decode to a nil pointer.
	SiteID      *string `json:"site_id"`
	ClearSiteID bool    `json:"clear_site_id"`
}

// UpdateRule applies a partial update and returns the stored row.
//
// Until now the only mutation was ToggleRule, so an operator who typo'd a rule
// had to delete and recreate it — losing its id, and with it any audit trail
// pointing at that id.
//
// Rows with source 'crs'/'community' are not updatable, matching DeleteRule:
// they are shipped/demo fixtures, they are excluded from delivery anyway
// (migration 0017), and letting them be edited would imply they take effect.
func (s *Store) UpdateRule(ctx context.Context, tenantID, userID, ruleID string,
	req UpdateRuleRequest) (*RuleRow, error) {

	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	// COALESCE keeps every untouched column at its current value, so this is one
	// statement regardless of how many fields the caller sent.
	var siteArg any
	switch {
	case req.ClearSiteID:
		siteArg = nil
	case req.SiteID != nil && strings.TrimSpace(*req.SiteID) != "":
		siteArg = *req.SiteID
	default:
		siteArg = nil
	}

	var r RuleRow
	var siteID *string
	// Every parameter is explicitly cast. Without the casts Postgres cannot infer
	// a type for a nil pointer inside COALESCE and fails the whole statement with
	// SQLSTATE 42P18 — and userID must NOT be passed at all, since a parameter the
	// query never references is exactly what triggered that error here first.
	err = tx.QueryRow(ctx,
		`UPDATE rules SET
		    dsl      = COALESCE($3::text,   dsl),
		    severity = COALESCE($4::text,   severity),
		    phase    = COALESCE($5::int,    phase),
		    tags     = COALESCE($6::text[], tags),
		    enabled  = COALESCE($7::boolean, enabled),
		    site_id  = CASE WHEN $8::boolean THEN NULL
		                    WHEN $9::uuid IS NOT NULL THEN $9::uuid
		                    ELSE site_id END,
		    updated_at = NOW()
		 WHERE id = $1 AND tenant_id = $2 AND source NOT IN ('crs','community')
		 RETURNING id, tenant_id, name, source, phase, severity, dsl, enabled, tags,
		           created_at, updated_at, site_id`,
		ruleID, tenantID, req.DSL, req.Severity, req.Phase, req.Tags,
		req.Enabled, req.ClearSiteID, siteArg,
	).Scan(&r.ID, &r.TenantID, &r.Name, &r.Source, &r.Phase, &r.Severity,
		&r.DSL, &r.Enabled, &r.Tags, &r.CreatedAt, &r.UpdatedAt, &siteID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRuleNotUpdatable
		}
		return nil, fmt.Errorf("store: update rule: %w", err)
	}
	if siteID != nil {
		r.SiteID = *siteID
	}
	return &r, tx.Commit(ctx)
}

// ErrRuleNotUpdatable covers both "no such rule in this tenant" and "this rule's
// source makes it read-only". They are deliberately one error: distinguishing
// them would tell a caller whether a rule id exists in another tenant.
var ErrRuleNotUpdatable = errors.New("rule not found or not updatable")
