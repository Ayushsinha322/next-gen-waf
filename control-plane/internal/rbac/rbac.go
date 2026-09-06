// Package rbac implements role-based access control for the Sentinel
// control plane, following the roles defined in the database schema:
//
//	owner    — full tenant control (can delete tenant, manage billing)
//	admin    — manage sites, rules, plugins, users within tenant
//	editor   — create/edit rules, sites, plugins (no user management)
//	viewer   — read-only access
//	auditor  — read-only access + audit log download
//
// Permissions are defined as <resource>.<action> pairs and checked against
// the caller's role.  Multi-tenant isolation is enforced at the DB layer via
// RLS; RBAC gates API-level operations.
package rbac

import (
	"fmt"
	"strings"
)

// Role represents a user's authorization level within a tenant.
type Role string

const (
	RoleOwner   Role = "owner"
	RoleAdmin   Role = "admin"
	RoleEditor  Role = "editor"
	RoleViewer  Role = "viewer"
	RoleAuditor Role = "auditor"
)

// IsValid returns true if the role string is a known role.
func (r Role) IsValid() bool {
	switch r {
	case RoleOwner, RoleAdmin, RoleEditor, RoleViewer, RoleAuditor:
		return true
	}
	return false
}

// Resource kinds for permission checks.
const (
	ResourceTenant        = "tenant"
	ResourceUser          = "user"
	ResourceAPIKey        = "apikey"
	ResourceSite          = "site"
	ResourceRule          = "rule"
	ResourcePlugin        = "plugin"
	ResourceMLProfile     = "ml_profile"
	ResourceIPList        = "ip_list"
	ResourceAlert         = "alert"
	ResourceAudit         = "audit_log"
	ResourceNotification  = "notification"   // notification channels (webhook/syslog/cef)
	ResourceManagementTLS = "management_tls" // management-console TLS certificate
	ResourceThreatIntel   = "threat_intel"   // threat-intelligence IOC corpus (node-global)
	ResourceLogProfile    = "log_profile"    // saved log views + bulk log export
	ResourceSettings      = "settings"       // node-wide operator settings (alert thresholds, feeds)
)

// Action verbs.
const (
	ActionCreate   = "create"
	ActionRead     = "read"
	ActionUpdate   = "update"
	ActionDelete   = "delete"
	ActionList     = "list"
	ActionDownload = "download" // auditor-only for audit logs
)

// rolePermissions maps each role to its allowed <resource>.<action> set.
var rolePermissions = map[Role]map[string]struct{}{
	RoleOwner: {
		perm(ResourceTenant, ActionRead):          {},
		perm(ResourceTenant, ActionUpdate):        {},
		perm(ResourceTenant, ActionDelete):        {},
		perm(ResourceUser, ActionCreate):          {},
		perm(ResourceUser, ActionRead):            {},
		perm(ResourceUser, ActionUpdate):          {},
		perm(ResourceUser, ActionDelete):          {},
		perm(ResourceUser, ActionList):            {},
		perm(ResourceAPIKey, ActionCreate):        {},
		perm(ResourceAPIKey, ActionRead):          {},
		perm(ResourceAPIKey, ActionDelete):        {},
		perm(ResourceAPIKey, ActionList):          {},
		perm(ResourceSite, ActionCreate):          {},
		perm(ResourceSite, ActionRead):            {},
		perm(ResourceSite, ActionUpdate):          {},
		perm(ResourceSite, ActionDelete):          {},
		perm(ResourceSite, ActionList):            {},
		perm(ResourceRule, ActionCreate):          {},
		perm(ResourceRule, ActionRead):            {},
		perm(ResourceRule, ActionUpdate):          {},
		perm(ResourceRule, ActionDelete):          {},
		perm(ResourceRule, ActionList):            {},
		perm(ResourcePlugin, ActionCreate):        {},
		perm(ResourcePlugin, ActionRead):          {},
		perm(ResourcePlugin, ActionUpdate):        {},
		perm(ResourcePlugin, ActionDelete):        {},
		perm(ResourcePlugin, ActionList):          {},
		perm(ResourceMLProfile, ActionRead):       {},
		perm(ResourceMLProfile, ActionList):       {},
		perm(ResourceIPList, ActionCreate):        {},
		perm(ResourceIPList, ActionRead):          {},
		perm(ResourceIPList, ActionDelete):        {},
		perm(ResourceIPList, ActionList):          {},
		perm(ResourceAlert, ActionRead):           {},
		perm(ResourceAlert, ActionUpdate):         {},
		perm(ResourceAlert, ActionList):           {},
		perm(ResourceNotification, ActionCreate):  {},
		perm(ResourceNotification, ActionRead):    {},
		perm(ResourceNotification, ActionUpdate):  {},
		perm(ResourceNotification, ActionDelete):  {},
		perm(ResourceNotification, ActionList):    {},
		perm(ResourceSettings, ActionRead):        {},
		perm(ResourceSettings, ActionUpdate):      {},
		perm(ResourceThreatIntel, ActionCreate):   {},
		perm(ResourceThreatIntel, ActionRead):     {},
		perm(ResourceThreatIntel, ActionDelete):   {},
		perm(ResourceThreatIntel, ActionList):     {},
		perm(ResourceAudit, ActionRead):           {},
		perm(ResourceAudit, ActionDownload):       {},
		perm(ResourceManagementTLS, ActionRead):   {},
		perm(ResourceManagementTLS, ActionUpdate): {},
		perm(ResourceLogProfile, ActionCreate):    {},
		perm(ResourceLogProfile, ActionRead):      {},
		perm(ResourceLogProfile, ActionUpdate):    {},
		perm(ResourceLogProfile, ActionDelete):    {},
		perm(ResourceLogProfile, ActionList):      {},
		perm(ResourceLogProfile, ActionDownload):  {},
	},
	RoleAdmin: {
		perm(ResourceUser, ActionCreate):          {},
		perm(ResourceUser, ActionRead):            {},
		perm(ResourceUser, ActionUpdate):          {},
		perm(ResourceUser, ActionDelete):          {},
		perm(ResourceUser, ActionList):            {},
		perm(ResourceAPIKey, ActionCreate):        {},
		perm(ResourceAPIKey, ActionRead):          {},
		perm(ResourceAPIKey, ActionDelete):        {},
		perm(ResourceAPIKey, ActionList):          {},
		perm(ResourceSite, ActionCreate):          {},
		perm(ResourceSite, ActionRead):            {},
		perm(ResourceSite, ActionUpdate):          {},
		perm(ResourceSite, ActionDelete):          {},
		perm(ResourceSite, ActionList):            {},
		perm(ResourceRule, ActionCreate):          {},
		perm(ResourceRule, ActionRead):            {},
		perm(ResourceRule, ActionUpdate):          {},
		perm(ResourceRule, ActionDelete):          {},
		perm(ResourceRule, ActionList):            {},
		perm(ResourcePlugin, ActionCreate):        {},
		perm(ResourcePlugin, ActionRead):          {},
		perm(ResourcePlugin, ActionUpdate):        {},
		perm(ResourcePlugin, ActionDelete):        {},
		perm(ResourcePlugin, ActionList):          {},
		perm(ResourceMLProfile, ActionRead):       {},
		perm(ResourceMLProfile, ActionList):       {},
		perm(ResourceIPList, ActionCreate):        {},
		perm(ResourceIPList, ActionRead):          {},
		perm(ResourceIPList, ActionDelete):        {},
		perm(ResourceIPList, ActionList):          {},
		perm(ResourceAlert, ActionRead):           {},
		perm(ResourceAlert, ActionUpdate):         {},
		perm(ResourceAlert, ActionList):           {},
		perm(ResourceNotification, ActionCreate):  {},
		perm(ResourceNotification, ActionRead):    {},
		perm(ResourceNotification, ActionUpdate):  {},
		perm(ResourceNotification, ActionDelete):  {},
		perm(ResourceNotification, ActionList):    {},
		perm(ResourceSettings, ActionRead):        {},
		perm(ResourceSettings, ActionUpdate):      {},
		perm(ResourceThreatIntel, ActionCreate):   {},
		perm(ResourceThreatIntel, ActionRead):     {},
		perm(ResourceThreatIntel, ActionDelete):   {},
		perm(ResourceThreatIntel, ActionList):     {},
		perm(ResourceAudit, ActionRead):           {},
		perm(ResourceAudit, ActionDownload):       {},
		perm(ResourceManagementTLS, ActionRead):   {},
		perm(ResourceManagementTLS, ActionUpdate): {},
		perm(ResourceLogProfile, ActionCreate):    {},
		perm(ResourceLogProfile, ActionRead):      {},
		perm(ResourceLogProfile, ActionUpdate):    {},
		perm(ResourceLogProfile, ActionDelete):    {},
		perm(ResourceLogProfile, ActionList):      {},
		perm(ResourceLogProfile, ActionDownload):  {},
	},
	RoleEditor: {
		perm(ResourceSite, ActionCreate):        {},
		perm(ResourceSite, ActionRead):          {},
		perm(ResourceSite, ActionUpdate):        {},
		perm(ResourceSite, ActionList):          {},
		perm(ResourceRule, ActionCreate):        {},
		perm(ResourceRule, ActionRead):          {},
		perm(ResourceRule, ActionUpdate):        {},
		perm(ResourceRule, ActionDelete):        {},
		perm(ResourceRule, ActionList):          {},
		perm(ResourcePlugin, ActionCreate):      {},
		perm(ResourcePlugin, ActionRead):        {},
		perm(ResourcePlugin, ActionUpdate):      {},
		perm(ResourcePlugin, ActionDelete):      {},
		perm(ResourcePlugin, ActionList):        {},
		perm(ResourceMLProfile, ActionRead):     {},
		perm(ResourceMLProfile, ActionList):     {},
		perm(ResourceIPList, ActionCreate):      {},
		perm(ResourceIPList, ActionRead):        {},
		perm(ResourceIPList, ActionList):        {},
		perm(ResourceAlert, ActionRead):         {},
		perm(ResourceAlert, ActionUpdate):       {},
		perm(ResourceAlert, ActionList):         {},
		perm(ResourceNotification, ActionRead):  {},
		perm(ResourceNotification, ActionList):  {},
		perm(ResourceSettings, ActionRead):      {},
		perm(ResourceThreatIntel, ActionRead):   {},
		perm(ResourceThreatIntel, ActionList):   {},
		perm(ResourceAudit, ActionRead):         {},
		perm(ResourceManagementTLS, ActionRead): {},
		// Editors run the customer-facing log requests, so they both curate the
		// saved views and produce the export handed over.
		perm(ResourceLogProfile, ActionCreate):   {},
		perm(ResourceLogProfile, ActionRead):     {},
		perm(ResourceLogProfile, ActionUpdate):   {},
		perm(ResourceLogProfile, ActionDelete):   {},
		perm(ResourceLogProfile, ActionList):     {},
		perm(ResourceLogProfile, ActionDownload): {},
	},
	RoleViewer: {
		perm(ResourceSite, ActionRead):          {},
		perm(ResourceSite, ActionList):          {},
		perm(ResourceRule, ActionRead):          {},
		perm(ResourceRule, ActionList):          {},
		perm(ResourcePlugin, ActionRead):        {},
		perm(ResourcePlugin, ActionList):        {},
		perm(ResourceMLProfile, ActionRead):     {},
		perm(ResourceMLProfile, ActionList):     {},
		perm(ResourceIPList, ActionRead):        {},
		perm(ResourceIPList, ActionList):        {},
		perm(ResourceAlert, ActionRead):         {},
		perm(ResourceAlert, ActionList):         {},
		perm(ResourceNotification, ActionRead):  {},
		perm(ResourceNotification, ActionList):  {},
		perm(ResourceSettings, ActionRead):      {},
		perm(ResourceThreatIntel, ActionRead):   {},
		perm(ResourceThreatIntel, ActionList):   {},
		perm(ResourceManagementTLS, ActionRead): {},
		// Viewers may open a saved view on screen but deliberately cannot
		// download one: an export is a bulk extract of customer traffic data
		// leaving the platform, which is a higher bar than reading a page of it.
		perm(ResourceLogProfile, ActionRead): {},
		perm(ResourceLogProfile, ActionList): {},
	},
	RoleAuditor: {
		perm(ResourceSite, ActionRead):          {},
		perm(ResourceSite, ActionList):          {},
		perm(ResourceRule, ActionRead):          {},
		perm(ResourceRule, ActionList):          {},
		perm(ResourcePlugin, ActionRead):        {},
		perm(ResourcePlugin, ActionList):        {},
		perm(ResourceMLProfile, ActionRead):     {},
		perm(ResourceMLProfile, ActionList):     {},
		perm(ResourceIPList, ActionRead):        {},
		perm(ResourceIPList, ActionList):        {},
		perm(ResourceAlert, ActionRead):         {},
		perm(ResourceAlert, ActionList):         {},
		perm(ResourceNotification, ActionRead):  {},
		perm(ResourceNotification, ActionList):  {},
		perm(ResourceSettings, ActionRead):      {},
		perm(ResourceThreatIntel, ActionRead):   {},
		perm(ResourceThreatIntel, ActionList):   {},
		perm(ResourceAudit, ActionRead):         {},
		perm(ResourceAudit, ActionDownload):     {},
		perm(ResourceManagementTLS, ActionRead): {},
		// Auditors already hold audit_log.download; extracting event history for
		// an investigation or a regulator is the same class of read.
		perm(ResourceLogProfile, ActionRead):     {},
		perm(ResourceLogProfile, ActionList):     {},
		perm(ResourceLogProfile, ActionDownload): {},
	},
}

func perm(resource, action string) string {
	return fmt.Sprintf("%s.%s", resource, action)
}

// Enforcer checks whether a role is permitted to perform a given action on a
// resource.
type Enforcer struct{}

// NewEnforcer creates a new RBAC enforcer.
func NewEnforcer() *Enforcer { return &Enforcer{} }

// Allow returns true if the given role may perform the action on the resource.
func (e *Enforcer) Allow(role Role, resource, action string) bool {
	perms, ok := rolePermissions[role]
	if !ok {
		return false
	}
	_, allowed := perms[perm(resource, action)]
	return allowed
}

// AllowAny returns true if the role may perform any of the specified
// resource.action pairs.
func (e *Enforcer) AllowAny(role Role, pairs ...string) bool {
	for _, p := range pairs {
		parts := strings.SplitN(p, ".", 2)
		if len(parts) != 2 {
			continue
		}
		if e.Allow(role, parts[0], parts[1]) {
			return true
		}
	}
	return false
}

// MustAllow is like Allow but panics with a descriptive message when denied.
func (e *Enforcer) MustAllow(role Role, resource, action string) {
	if !e.Allow(role, resource, action) {
		panic(fmt.Sprintf("rbac: role %q denied %s.%s", role, resource, action))
	}
}
