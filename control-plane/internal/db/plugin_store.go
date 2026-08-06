package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// PluginRow is an installed WASM plugin. The module bytes are deliberately NOT
// part of this struct: listings are served constantly by the dashboard and the
// data-plane sync poll, and a plugin can be megabytes. Fetch the bytes
// explicitly with GetPluginWasm when they are actually needed.
type PluginRow struct {
	ID          string          `json:"id"`
	TenantID    string          `json:"tenant_id"`
	Name        string          `json:"name"`
	Version     string          `json:"version"`
	Description string          `json:"description"`
	Author      string          `json:"author"`
	Hooks       json.RawMessage `json:"hooks"`
	Permissions json.RawMessage `json:"permissions"`
	SHA256      string          `json:"sha256"`
	SizeBytes   int64           `json:"size_bytes"`
	Enabled     bool            `json:"enabled"`
	UploadedBy  string          `json:"uploaded_by"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// InstallPluginRequest is a validated plugin ready to be written. The handler is
// responsible for having parsed and vetted the archive before this point.
type InstallPluginRequest struct {
	Name        string
	Version     string
	Description string
	Author      string
	Hooks       json.RawMessage
	Permissions json.RawMessage
	SHA256      string
	Wasm        []byte
	UploadedBy  string
}

// ErrPluginNotFound is returned when a named plugin does not exist for a tenant.
var ErrPluginNotFound = errors.New("plugin not found")

// EnsurePluginSchema idempotently applies the 0016 plugin-upload columns so an
// operator who has not run goose still gets a working plugin system. Mirrors
// EnsureNotificationSchema / EnsureNodesSchema. Uses the raw pool because it is
// DDL and must not be tenant-scoped.
func EnsurePluginSchema(ctx context.Context, pool Pool) error {
	pg, ok := pool.(*pgxPool)
	if !ok {
		return fmt.Errorf("plugin schema: pool is not a *pgxPool")
	}
	const ddl = `
ALTER TABLE plugins
    ADD COLUMN IF NOT EXISTS wasm        BYTEA,
    ADD COLUMN IF NOT EXISTS description TEXT   NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS author      TEXT   NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS hooks       JSONB  NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS permissions JSONB  NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS size_bytes  BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS uploaded_by TEXT   NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS updated_at  TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE plugins ALTER COLUMN wasm_blob_uri SET DEFAULT '';
ALTER TABLE plugins ALTER COLUMN wasm_blob_uri DROP NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS plugins_tenant_name_key ON plugins (tenant_id, name);
CREATE INDEX IF NOT EXISTS plugins_enabled_idx ON plugins (enabled);`
	if _, err := pg.pool.Exec(ctx, ddl); err != nil {
		return fmt.Errorf("plugin schema: %w", err)
	}
	return nil
}

// InstallPlugin inserts or upgrades a plugin. Re-uploading an existing name is an
// upgrade in place (ON CONFLICT on the tenant+name index), which is what an
// operator means by "upload a new build" — it must not leave the old version
// live alongside the new one.
//
// A newly installed plugin is enabled=false. Uploading a module that can set the
// WAF decision is a privileged act, so putting it in the traffic path takes a
// second, explicit action; an upload alone can never change how requests are
// judged. On upgrade the existing enabled state is preserved (COALESCE on the
// excluded value is deliberately NOT used — the row keeps its own flag).
func (s *Store) InstallPlugin(ctx context.Context, tenantID, userID string, r InstallPluginRequest) (*PluginRow, error) {
	hooks := r.Hooks
	if len(hooks) == 0 {
		hooks = json.RawMessage(`{}`)
	}
	perms := r.Permissions
	if len(perms) == 0 {
		perms = json.RawMessage(`{}`)
	}

	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var row PluginRow
	err = tx.QueryRow(ctx, `
INSERT INTO plugins (tenant_id, name, version, description, author, hooks, permissions,
                     sha256, wasm, size_bytes, uploaded_by, enabled, wasm_blob_uri, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, false, '', now())
ON CONFLICT (tenant_id, name) DO UPDATE SET
    version     = EXCLUDED.version,
    description = EXCLUDED.description,
    author      = EXCLUDED.author,
    hooks       = EXCLUDED.hooks,
    permissions = EXCLUDED.permissions,
    sha256      = EXCLUDED.sha256,
    wasm        = EXCLUDED.wasm,
    size_bytes  = EXCLUDED.size_bytes,
    uploaded_by = EXCLUDED.uploaded_by,
    updated_at  = now()
RETURNING id, tenant_id, name, version, description, author, hooks, permissions,
          sha256, size_bytes, enabled, uploaded_by, created_at, updated_at`,
		tenantID, r.Name, r.Version, r.Description, r.Author, hooks, perms,
		r.SHA256, r.Wasm, int64(len(r.Wasm)), r.UploadedBy,
	).Scan(&row.ID, &row.TenantID, &row.Name, &row.Version, &row.Description,
		&row.Author, &row.Hooks, &row.Permissions, &row.SHA256, &row.SizeBytes,
		&row.Enabled, &row.UploadedBy, &row.CreatedAt, &row.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("store: install plugin: %w", err)
	}
	return &row, tx.Commit(ctx)
}

// ListPlugins returns a tenant's installed plugins, newest first. The explicit
// tenant_id predicate is the app-layer guard: RLS is a backstop, not the only
// barrier between tenants, since the runtime role can bypass RLS in the
// single-tenant deployment posture.
func (s *Store) ListPlugins(ctx context.Context, tenantID, userID string) ([]PluginRow, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, `
SELECT id, tenant_id, name, version, description, author, hooks, permissions,
       sha256, size_bytes, enabled, uploaded_by, created_at, updated_at
  FROM plugins WHERE tenant_id = $1 ORDER BY updated_at DESC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("store: list plugins: %w", err)
	}
	defer rows.Close()

	out := make([]PluginRow, 0, 8)
	for rows.Next() {
		var p PluginRow
		if err := rows.Scan(&p.ID, &p.TenantID, &p.Name, &p.Version, &p.Description,
			&p.Author, &p.Hooks, &p.Permissions, &p.SHA256, &p.SizeBytes,
			&p.Enabled, &p.UploadedBy, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store: scan plugin: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}

// SetPluginEnabled flips a plugin in or out of the request path. Uses RETURNING
// so a missing plugin is reported as ErrPluginNotFound rather than a silent
// success — TenantTx.Exec surfaces no rows-affected count.
//
// Returns the plugin's UUID: audit_logs.target_id is a uuid column, so the audit
// trail cannot be keyed on the name that identifies a plugin everywhere else.
func (s *Store) SetPluginEnabled(ctx context.Context, tenantID, userID, name string, enabled bool) (string, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	var id string
	err = tx.QueryRow(ctx,
		`UPDATE plugins SET enabled = $3, updated_at = now()
		  WHERE tenant_id = $1 AND name = $2 RETURNING id`,
		tenantID, name, enabled).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrPluginNotFound
	}
	if err != nil {
		return "", fmt.Errorf("store: set plugin enabled: %w", err)
	}
	return id, tx.Commit(ctx)
}

// DeletePlugin removes a plugin entirely, returning its UUID for the audit trail.
func (s *Store) DeletePlugin(ctx context.Context, tenantID, userID, name string) (string, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	var id string
	err = tx.QueryRow(ctx,
		`DELETE FROM plugins WHERE tenant_id = $1 AND name = $2 RETURNING id`,
		tenantID, name).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrPluginNotFound
	}
	if err != nil {
		return "", fmt.Errorf("store: delete plugin: %w", err)
	}
	return id, tx.Commit(ctx)
}

// EnabledPlugin is the digest a data-plane node needs in order to decide whether
// it must (re)fetch a module: name, version and content hash, without the bytes.
type EnabledPlugin struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size_bytes"`
}

// ListEnabledPluginsGlobal returns every enabled plugin across all tenants, for
// the data-plane config sync. Node-global by design and therefore uses the raw
// pool: one shared data plane serves every tenant's sites, exactly like
// ListAllActiveSites. Ordered by name so the digest a node compares is stable and
// does not appear to change merely because rows came back in a different order.
func (s *Store) ListEnabledPluginsGlobal(ctx context.Context) ([]EnabledPlugin, error) {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return nil, fmt.Errorf("store: pool is not a *pgxPool")
	}
	rows, err := pg.pool.Query(ctx, `
SELECT name, version, sha256, size_bytes
  FROM plugins WHERE enabled = true AND wasm IS NOT NULL ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: list enabled plugins: %w", err)
	}
	defer rows.Close()

	out := make([]EnabledPlugin, 0, 8)
	for rows.Next() {
		var p EnabledPlugin
		if err := rows.Scan(&p.Name, &p.Version, &p.SHA256, &p.Size); err != nil {
			return nil, fmt.Errorf("store: scan enabled plugin: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetEnabledPluginWasmGlobal returns an enabled plugin's bytes by name, without a
// tenant scope, for the data-plane fetch. Only ENABLED plugins are served: a
// disabled plugin must not be loadable, so a node asking for one gets
// ErrPluginNotFound rather than the module.
func (s *Store) GetEnabledPluginWasmGlobal(ctx context.Context, name string) ([]byte, string, error) {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return nil, "", fmt.Errorf("store: pool is not a *pgxPool")
	}
	var wasm []byte
	var sha string
	err := pg.pool.QueryRow(ctx,
		`SELECT wasm, sha256 FROM plugins
		  WHERE name = $1 AND enabled = true AND wasm IS NOT NULL`,
		name).Scan(&wasm, &sha)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", ErrPluginNotFound
	}
	if err != nil {
		return nil, "", fmt.Errorf("store: get enabled plugin wasm: %w", err)
	}
	return wasm, sha, nil
}
