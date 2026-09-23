package main

import (
	"strings"
	"testing"

	"github.com/your-org/sentinel-waf/control-plane/internal/db"
)

func u(id, role, status string) db.UserRow { return db.UserRow{ID: id, Role: role, Status: status} }

func TestUserChangeGuards(t *testing.T) {
	admin := u("a1", "admin", "active")
	owner := u("o1", "owner", "active")
	viewer := u("v1", "viewer", "active")
	soleAdmin := []db.UserRow{admin, viewer}
	twoAdmins := []db.UserRow{admin, u("a2", "admin", "active"), viewer}

	cases := []struct {
		name               string
		actorID, actorRole string
		target             db.UserRow
		users              []db.UserRow
		role, status       string
		del                bool
		want               string
	}{
		{"demote yourself", "a1", "admin", admin, twoAdmins, "viewer", "", false, "own role"},
		{"disable yourself", "a1", "admin", admin, twoAdmins, "", "disabled", false, "own account"},
		{"admin grants owner", "a1", "admin", viewer, twoAdmins, "owner", "", false, "only an owner"},
		{"admin removes owner", "a1", "admin", owner, append(twoAdmins, owner), "", "", true, "only an owner"},
		{"last admin demoted", "o9", "owner", admin, soleAdmin, "editor", "", false, "last active administrator"},
		{"last admin deleted", "o9", "owner", admin, soleAdmin, "", "", true, "last active administrator"},
		{"last admin disabled", "o9", "owner", admin, soleAdmin, "", "disabled", false, "last active administrator"},
		// allowed
		{"promote viewer", "a1", "admin", viewer, soleAdmin, "editor", "", false, ""},
		{"demote one of two admins", "a1", "admin", u("a2", "admin", "active"), twoAdmins, "viewer", "", false, ""},
		{"delete a viewer", "a1", "admin", viewer, soleAdmin, "", "", true, ""},
		{"owner grants owner", "o1", "owner", viewer, []db.UserRow{owner, viewer}, "owner", "", false, ""},
		{"re-enable yourself is not a change", "a1", "admin", admin, soleAdmin, "", "active", false, ""},
	}
	for _, c := range cases {
		got := userChangeProblem(c.actorID, c.actorRole, c.target, c.users, c.role, c.status, c.del)
		if c.want == "" && got != "" || c.want != "" && !strings.Contains(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
