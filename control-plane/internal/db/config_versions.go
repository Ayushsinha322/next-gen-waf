package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Config version snapshots and rollback.
//
// A bad policy push previously had no undo: config reached the data plane by a 5s
// poll that blind-merged whatever the control plane served, and recovery meant
// remembering the old values and retyping them while the site was already broken.
//
// Snapshots are taken BEFORE a mutation, so the newest snapshot is the state that
// was working a moment ago — which is what an operator reaching for "undo" wants.

// ConfigVersionSummary describes a snapshot without carrying its payload, for
// listing in the UI.
type ConfigVersionSummary struct {
	ID         int64     `json:"id"`
	Generation int64     `json:"generation"`
	Reason     string    `json:"reason"`
	SiteCount  int       `json:"site_count"`
	CreatedBy  *string   `json:"created_by,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// maxConfigVersionsPerTenant bounds retained history. Snapshots are taken on every
// config mutation, so unbounded retention would grow with write volume rather than
// with anything an operator cares about.
const maxConfigVersionsPerTenant = 50

// SnapshotConfig records the tenant's current site configuration so it can be
// restored later. `reason` is the mutation about to be applied (e.g. "site.update").
//
// Returns the new snapshot's ID. A snapshot failure must NOT block the mutation it
// precedes — losing an undo point is far less bad than refusing a legitimate
// config change — so callers log and continue.
func (s *Store) SnapshotConfig(ctx context.Context, tenantID, userID, reason string) (int64, error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return 0, fmt.Errorf("store: snapshot begin: %w", err)
	}
	defer tx.Rollback(ctx)

	sites, err := s.listSitesTx(ctx, tx, tenantID)
	if err != nil {
		return 0, err
	}
	payload, err := json.Marshal(sites)
	if err != nil {
		return 0, fmt.Errorf("store: snapshot marshal: %w", err)
	}

	// Read the shared generation counter through the same transaction so the
	// snapshot is labelled with the generation it actually represents.
	var generation int64
	if err := tx.QueryRow(ctx, `SELECT sentinel_config_version()`).Scan(&generation); err != nil {
		// Not fatal: the snapshot is still restorable without a generation label.
		generation = 0
	}

	var actor any
	if userID != "" {
		actor = userID
	}

	var id int64
	if err := tx.QueryRow(ctx, `
		INSERT INTO config_versions (tenant_id, generation, sites, reason, created_by)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id`,
		tenantID, generation, payload, reason, actor).Scan(&id); err != nil {
		return 0, fmt.Errorf("store: snapshot insert: %w", err)
	}

	// Trim history in the same transaction so the cap always holds.
	if err := tx.Exec(ctx, `
		DELETE FROM config_versions
		 WHERE tenant_id = $1
		   AND id NOT IN (
		       SELECT id FROM config_versions
		        WHERE tenant_id = $1
		        ORDER BY id DESC
		        LIMIT $2
		   )`, tenantID, maxConfigVersionsPerTenant); err != nil {
		return 0, fmt.Errorf("store: snapshot trim: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("store: snapshot commit: %w", err)
	}
	return id, nil
}

// ListConfigVersions returns the tenant's snapshots, newest first.
func (s *Store) ListConfigVersions(ctx context.Context, tenantID, userID string, limit int) ([]ConfigVersionSummary, error) {
	if limit <= 0 || limit > maxConfigVersionsPerTenant {
		limit = maxConfigVersionsPerTenant
	}
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, `
		SELECT id, generation, reason, jsonb_array_length(sites), created_by, created_at
		  FROM config_versions
		 WHERE tenant_id = $1
		 ORDER BY id DESC
		 LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list config versions: %w", err)
	}
	defer rows.Close()

	out := make([]ConfigVersionSummary, 0, limit)
	for rows.Next() {
		var v ConfigVersionSummary
		if err := rows.Scan(&v.ID, &v.Generation, &v.Reason, &v.SiteCount, &v.CreatedBy, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// RestoreConfigVersion replaces the tenant's site configuration with a snapshot.
//
// Restores field values onto sites that still exist, matched by site ID, and
// reports what it could not apply. It deliberately does NOT delete sites created
// since the snapshot, nor resurrect sites deleted since:
//
//   - Deleting them would make "undo a policy change" silently destroy unrelated
//     sites added in the meantime, which is a far worse outcome than the mistake
//     being undone.
//   - Re-creating deleted sites would resurrect configuration someone deliberately
//     removed, and their IDs are referenced by audit rows and events.
//
// Both cases are returned in `skipped` so the caller can tell the operator exactly
// what was and was not restored, rather than implying a complete revert.
func (s *Store) RestoreConfigVersion(ctx context.Context, tenantID, userID string, versionID int64) (restored int, skipped []string, err error) {
	tx, err := s.pool.BeginTenant(ctx, tenantID, userID)
	if err != nil {
		return 0, nil, err
	}
	defer tx.Rollback(ctx)

	var payload []byte
	if err := tx.QueryRow(ctx,
		`SELECT sites FROM config_versions WHERE tenant_id = $1 AND id = $2`,
		tenantID, versionID).Scan(&payload); err != nil {
		return 0, nil, fmt.Errorf("store: config version %d not found: %w", versionID, err)
	}

	var snapshot []SiteRow
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return 0, nil, fmt.Errorf("store: decoding snapshot: %w", err)
	}

	// Which sites still exist, so a missing one is reported rather than silently
	// skipped by a zero-row UPDATE.
	current, err := s.listSitesTx(ctx, tx, tenantID)
	if err != nil {
		return 0, nil, err
	}
	exists := make(map[string]bool, len(current))
	for _, c := range current {
		exists[c.ID] = true
	}

	for _, snap := range snapshot {
		if !exists[snap.ID] {
			skipped = append(skipped, fmt.Sprintf("%s (deleted since the snapshot — not re-created)", snap.Name))
			continue
		}
		if err := tx.Exec(ctx, `
			UPDATE sites
			   SET name = $3, domains = $4, upstream = $5, waf_policy = $6, status = $7, updated_at = now()
			 WHERE tenant_id = $1 AND id = $2`,
			tenantID, snap.ID, snap.Name, snap.Domains,
			nullableJSON(snap.Upstream), nullableJSON(snap.WafPolicy), snap.Status); err != nil {
			return 0, nil, fmt.Errorf("store: restoring site %s: %w", snap.Name, err)
		}
		restored++
	}

	// Sites added after the snapshot are left alone, and named so the operator is
	// not misled into thinking this was a full revert.
	snapIDs := make(map[string]bool, len(snapshot))
	for _, snap := range snapshot {
		snapIDs[snap.ID] = true
	}
	for _, c := range current {
		if !snapIDs[c.ID] {
			skipped = append(skipped, fmt.Sprintf("%s (created after the snapshot — left unchanged)", c.Name))
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, nil, fmt.Errorf("store: restore commit: %w", err)
	}
	return restored, skipped, nil
}

// listSitesTx lists the tenant's sites inside an existing transaction, so a
// snapshot or restore sees a single consistent view.
func (s *Store) listSitesTx(ctx context.Context, tx TenantTx, tenantID string) ([]SiteRow, error) {
	rows, err := tx.Query(ctx, `
		SELECT id, tenant_id, name, domains, upstream, waf_policy, status, created_at, updated_at
		  FROM sites
		 WHERE tenant_id = $1
		 ORDER BY name`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("store: listing sites: %w", err)
	}
	defer rows.Close()

	var out []SiteRow
	for rows.Next() {
		var r SiteRow
		if err := rows.Scan(&r.ID, &r.TenantID, &r.Name, &r.Domains, &r.Upstream,
			&r.WafPolicy, &r.Status, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
