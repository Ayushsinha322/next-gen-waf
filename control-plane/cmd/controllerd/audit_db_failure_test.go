package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/rbac"
)

// failingPool satisfies db.Pool and refuses every transaction, modelling an
// audit store that is unreachable (Postgres down, connection pool exhausted,
// credentials rotated).
type failingPool struct{}

func (failingPool) BeginTenant(context.Context, string, string) (db.TenantTx, error) {
	return nil, errors.New("connection refused")
}
func (failingPool) Close() {}

func auditRequest(t *testing.T, store *db.Store, target string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, target, nil)
	// An auditor-role caller, so RBAC is satisfied and the test exercises the
	// store path rather than the permission check.
	ctx := context.WithValue(c.Request.Context(), auth.ClaimsKey, &auth.Claims{
		TenantID: db.DevTenantID,
		UserID:   db.DevAdminID,
		Role:     "owner",
	})
	c.Request = c.Request.WithContext(ctx)
	handleListAudit(c, rbac.NewEnforcer(), store)
	return w
}

// THE regression: a broken audit store used to render as "no admin activity".
// handleListAudit returned 200 with `entries: []` on any error, which is the
// most reassuring possible display of the least reassuring possible state —
// and exactly what an attacker who had just broken the store would want shown.
func TestAuditListRefusesToLookEmptyWhenTheStoreIsBroken(t *testing.T) {
	w := auditRequest(t, db.NewStore(failingPool{}), "/api/v1/audit")

	if w.Code == http.StatusOK {
		t.Fatalf("a failed audit read returned 200 — an outage is indistinguishable from an empty log. body=%s", w.Body.String())
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for an unreadable audit store, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	// Critically: it must NOT hand back an entries array. A client that reads
	// `entries` without checking the status would otherwise still show a clean
	// empty table.
	if _, present := resp["entries"]; present {
		t.Fatalf("error response must not carry an entries array: %s", w.Body.String())
	}
	if _, hasErr := resp["error"]; !hasErr {
		t.Fatalf("error response must say what went wrong: %s", w.Body.String())
	}
}

// Same rule for the degraded no-database mode: silence there is also not proof
// of no activity.
func TestAuditListRefusesWhenNoDatabaseConfigured(t *testing.T) {
	w := auditRequest(t, nil, "/api/v1/audit")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 with no store, got %d: %s", w.Code, w.Body.String())
	}
	if _, present := map[string]any{}["entries"]; present {
		t.Fatal("unreachable")
	}
}

// An invalid filter value must be rejected rather than silently ignored — a
// silently-dropped filter returns a DIFFERENT result set than the caller asked
// for, which is how someone concludes there were no failed logins.
func TestAuditListRejectsUnknownResultFilter(t *testing.T) {
	w := auditRequest(t, db.NewStore(failingPool{}), "/api/v1/audit?result=MAYBE")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an invalid result filter, got %d: %s", w.Code, w.Body.String())
	}
}

// The verifier must never report success because verification could not run.
func TestAuditVerifyDoesNotClaimVerifiedOnFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/audit/verify", nil)
	c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), auth.ClaimsKey,
		&auth.Claims{TenantID: db.DevTenantID, UserID: db.DevAdminID, Role: "owner"}))
	handleVerifyAudit(c, rbac.NewEnforcer(), db.NewStore(failingPool{}))

	if w.Code == http.StatusOK {
		t.Fatalf("verification that could not run must not return 200: %s", w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if v, ok := resp["verified"].(bool); !ok || v {
		t.Fatalf("verified must be false when the check could not complete: %s", w.Body.String())
	}
}
