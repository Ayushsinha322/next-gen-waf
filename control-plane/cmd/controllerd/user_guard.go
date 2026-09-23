package main

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/your-org/sentinel-waf/control-plane/internal/db"
)

// isAdminRole: roles that can manage users, and so keep a deployment
// administrable. Losing the last of them locks everyone out of user management
// — and, with no SMTP relay, out of password recovery too.
func isAdminRole(r string) bool { return r == "owner" || r == "admin" }

// userChangeProblem says why an administrator's change to a user must be
// refused, or "" if it may go ahead. newRole/newStatus are "" when unchanged.
//
// These are server rules, not console courtesy: the console only offers what
// they allow, but the API is reachable directly.
func userChangeProblem(actorID, actorRole string, target db.UserRow, users []db.UserRow,
	newRole, newStatus string, deleting bool) string {

	self := target.ID == actorID
	roleChange := newRole != "" && newRole != target.Role
	disabling := newStatus != "" && !strings.EqualFold(newStatus, "active") && newStatus != target.Status

	if self && roleChange {
		return "you cannot change your own role — ask another administrator"
	}
	if self && disabling {
		return "you cannot disable your own account"
	}
	if (newRole == "owner" || (target.Role == "owner" && (roleChange || disabling || deleting))) && actorRole != "owner" {
		return "only an owner can grant, change or remove the owner role"
	}

	// Would this leave no active administrator?
	losesAdmin := isAdminRole(target.Role) && strings.EqualFold(target.Status, "active") &&
		(deleting || disabling || (roleChange && !isAdminRole(newRole)))
	if losesAdmin {
		remaining := 0
		for _, u := range users {
			if u.ID != target.ID && isAdminRole(u.Role) && strings.EqualFold(u.Status, "active") {
				remaining++
			}
		}
		if remaining == 0 {
			return "this is the last active administrator — make someone else an admin first, or no one could manage users again"
		}
	}
	return ""
}

// checkUserChange loads the tenant's users and applies userChangeProblem.
// Returns the refusal and its HTTP status, or "" to proceed.
func checkUserChange(c *gin.Context, store *db.Store, tenantID, actorID, actorRole, targetID,
	newRole, newStatus string, deleting bool) (string, int) {
	users, err := store.ListUsers(c.Request.Context(), tenantID, actorID)
	if err != nil {
		return "could not load users to check this change", http.StatusServiceUnavailable
	}
	for _, t := range users {
		if t.ID == targetID {
			if p := userChangeProblem(actorID, actorRole, t, users, newRole, newStatus, deleting); p != "" {
				return p, http.StatusConflict
			}
			return "", 0
		}
	}
	return "user not found", http.StatusNotFound
}
