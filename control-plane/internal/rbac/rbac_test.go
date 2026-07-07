package rbac

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRoleIsValid(t *testing.T) {
	require.True(t, RoleOwner.IsValid())
	require.True(t, RoleAdmin.IsValid())
	require.True(t, RoleEditor.IsValid())
	require.True(t, RoleViewer.IsValid())
	require.True(t, RoleAuditor.IsValid())
	require.False(t, Role("superuser").IsValid())
	require.False(t, Role("").IsValid())
}

func TestOwnerCanDoEverything(t *testing.T) {
	enf := NewEnforcer()
	require.True(t, enf.Allow(RoleOwner, ResourceSite, ActionCreate))
	require.True(t, enf.Allow(RoleOwner, ResourceSite, ActionDelete))
	require.True(t, enf.Allow(RoleOwner, ResourceUser, ActionCreate))
	require.True(t, enf.Allow(RoleOwner, ResourceTenant, ActionDelete))
	require.True(t, enf.Allow(RoleOwner, ResourceAudit, ActionDownload))
}

func TestAdminPermissions(t *testing.T) {
	enf := NewEnforcer()
	// Admin can manage sites.
	require.True(t, enf.Allow(RoleAdmin, ResourceSite, ActionCreate))
	require.True(t, enf.Allow(RoleAdmin, ResourceSite, ActionDelete))
	// Admin can manage users.
	require.True(t, enf.Allow(RoleAdmin, ResourceUser, ActionCreate))
	// Admin CANNOT delete the tenant.
	require.False(t, enf.Allow(RoleAdmin, ResourceTenant, ActionDelete))
	require.False(t, enf.Allow(RoleAdmin, ResourceTenant, ActionUpdate))
}

func TestEditorPermissions(t *testing.T) {
	enf := NewEnforcer()
	// Editor can CRUD rules, sites, plugins.
	require.True(t, enf.Allow(RoleEditor, ResourceRule, ActionCreate))
	require.True(t, enf.Allow(RoleEditor, ResourceSite, ActionCreate))
	require.True(t, enf.Allow(RoleEditor, ResourcePlugin, ActionUpdate))
	// Editor CANNOT manage users.
	require.False(t, enf.Allow(RoleEditor, ResourceUser, ActionCreate))
	require.False(t, enf.Allow(RoleEditor, ResourceUser, ActionRead))
	// Editor CANNOT delete sites (can create but not delete).
	require.False(t, enf.Allow(RoleEditor, ResourceSite, ActionDelete))
}

func TestViewerIsReadOnly(t *testing.T) {
	enf := NewEnforcer()
	require.True(t, enf.Allow(RoleViewer, ResourceSite, ActionRead))
	require.True(t, enf.Allow(RoleViewer, ResourceRule, ActionList))
	require.False(t, enf.Allow(RoleViewer, ResourceSite, ActionCreate))
	require.False(t, enf.Allow(RoleViewer, ResourceSite, ActionUpdate))
	require.False(t, enf.Allow(RoleViewer, ResourceSite, ActionDelete))
	require.False(t, enf.Allow(RoleViewer, ResourceUser, ActionRead))
	require.False(t, enf.Allow(RoleViewer, ResourceAudit, ActionDownload))
}

func TestAuditorCanDownloadAudit(t *testing.T) {
	enf := NewEnforcer()
	require.True(t, enf.Allow(RoleAuditor, ResourceAudit, ActionRead))
	require.True(t, enf.Allow(RoleAuditor, ResourceAudit, ActionDownload))
	require.True(t, enf.Allow(RoleAuditor, ResourceSite, ActionRead))
	// Auditor is read-only elsewhere.
	require.False(t, enf.Allow(RoleAuditor, ResourceSite, ActionCreate))
	require.False(t, enf.Allow(RoleAuditor, ResourceUser, ActionRead))
}

func TestAllowAny(t *testing.T) {
	enf := NewEnforcer()
	// Viewer can read.allow OR audit.read (first one succeeds).
	require.True(t, enf.AllowAny(RoleViewer, "site.read", "audit_log.download"))
	// Viewer cannot create anything.
	require.False(t, enf.AllowAny(RoleViewer, "site.create", "rule.create"))
	// Admin can do any of these.
	require.True(t, enf.AllowAny(RoleAdmin, "site.create", "user.delete", "rule.update"))
}

func TestUnknownRole(t *testing.T) {
	enf := NewEnforcer()
	require.False(t, enf.Allow(Role("bogus"), ResourceSite, ActionRead))
	require.False(t, enf.Allow(Role(""), ResourceSite, ActionRead))
}

func TestMustAllow_PanicsOnDeny(t *testing.T) {
	enf := NewEnforcer()
	require.Panics(t, func() {
		enf.MustAllow(RoleViewer, ResourceSite, ActionCreate)
	})
}

func TestMustAllow_PassesOnAllow(t *testing.T) {
	enf := NewEnforcer()
	require.NotPanics(t, func() {
		enf.MustAllow(RoleAdmin, ResourceSite, ActionCreate)
	})
}

func TestThreatIntelPermissions(t *testing.T) {
	enf := NewEnforcer()
	// Owner + Admin curate the corpus: create/read/delete/list.
	for _, r := range []Role{RoleOwner, RoleAdmin} {
		require.True(t, enf.Allow(r, ResourceThreatIntel, ActionCreate), "%s create", r)
		require.True(t, enf.Allow(r, ResourceThreatIntel, ActionDelete), "%s delete", r)
		require.True(t, enf.Allow(r, ResourceThreatIntel, ActionRead), "%s read", r)
		require.True(t, enf.Allow(r, ResourceThreatIntel, ActionList), "%s list", r)
	}
	// Editor / Viewer / Auditor are read-only: never create or delete IOCs.
	for _, r := range []Role{RoleEditor, RoleViewer, RoleAuditor} {
		require.True(t, enf.Allow(r, ResourceThreatIntel, ActionRead), "%s read", r)
		require.True(t, enf.Allow(r, ResourceThreatIntel, ActionList), "%s list", r)
		require.False(t, enf.Allow(r, ResourceThreatIntel, ActionCreate), "%s must NOT create", r)
		require.False(t, enf.Allow(r, ResourceThreatIntel, ActionDelete), "%s must NOT delete", r)
	}
	// Unknown role denied by default.
	require.False(t, enf.Allow(Role("superuser"), ResourceThreatIntel, ActionRead))
}
