package db

import (
	"context"
	"fmt"
	"time"
)

// TenantRow is a tenant in the platform list.
type TenantRow struct {
	ID        string    `json:"id"`
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	Plan      string    `json:"plan"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateTenant provisions a new tenant plus its initial owner user (with an
// argon2id password hash) atomically, via the SECURITY DEFINER carve-out.
// Returns the new tenant + owner user ids.
func (s *Store) CreateTenant(ctx context.Context, slug, name, plan, ownerEmail, ownerName, ownerPassword string) (tenantID, userID string, err error) {
	pwHash, err := hashPassword(ownerPassword)
	if err != nil {
		return "", "", err
	}
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return "", "", fmt.Errorf("store: pool is not a *pgxPool")
	}
	err = pg.pool.QueryRow(ctx,
		`SELECT tenant_id, user_id FROM sentinel_create_tenant($1, $2, $3, $4, $5, $6)`,
		slug, name, plan, ownerEmail, ownerName, pwHash).Scan(&tenantID, &userID)
	if err != nil {
		return "", "", fmt.Errorf("create tenant: %w", err)
	}
	return tenantID, userID, nil
}

// SetTenantStatus changes a tenant's lifecycle status (active/suspended/deleted).
func (s *Store) SetTenantStatus(ctx context.Context, tenantID, status string) error {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return fmt.Errorf("store: pool is not a *pgxPool")
	}
	if _, err := pg.pool.Exec(ctx, `SELECT sentinel_set_tenant_status($1, $2)`, tenantID, status); err != nil {
		return fmt.Errorf("set tenant status: %w", err)
	}
	return nil
}

// ListTenants returns all non-deleted tenants (platform view).
func (s *Store) ListTenants(ctx context.Context) ([]TenantRow, error) {
	pg, ok := s.pool.(*pgxPool)
	if !ok {
		return nil, fmt.Errorf("store: pool is not a *pgxPool")
	}
	rows, err := pg.pool.Query(ctx,
		`SELECT id, slug, name, plan, status, created_at FROM sentinel_list_tenants()`)
	if err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	defer rows.Close()

	var out []TenantRow
	for rows.Next() {
		var t TenantRow
		if err := rows.Scan(&t.ID, &t.Slug, &t.Name, &t.Plan, &t.Status, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
