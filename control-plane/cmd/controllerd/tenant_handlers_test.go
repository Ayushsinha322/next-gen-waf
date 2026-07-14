package main

import (
	"testing"

	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
)

func TestIsPlatformAdmin(t *testing.T) {
	cases := []struct {
		name   string
		claims *auth.Claims
		want   bool
	}{
		{"platform owner", &auth.Claims{TenantID: db.DevTenantID, Role: "owner"}, true},
		{"platform admin", &auth.Claims{TenantID: db.DevTenantID, Role: "admin"}, true},
		{"platform editor", &auth.Claims{TenantID: db.DevTenantID, Role: "editor"}, false},
		{"other-tenant owner", &auth.Claims{TenantID: "11111111-1111-1111-1111-111111111111", Role: "owner"}, false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		if got := isPlatformAdmin(tc.claims); got != tc.want {
			t.Errorf("%s: isPlatformAdmin = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestValidPlan(t *testing.T) {
	for _, p := range []string{"", "free", "pro", "enterprise"} {
		if !validPlan(p) {
			t.Errorf("validPlan(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"gold", "unlimited", "FREE"} {
		if validPlan(p) {
			t.Errorf("validPlan(%q) = true, want false", p)
		}
	}
}
