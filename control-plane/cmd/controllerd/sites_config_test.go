package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/rbac"
)

// countingPool counts every transaction the handler opens and refuses it, so a
// test can tell "refused before touching the store" from "reached the store".
type countingPool struct{ begun atomic.Int32 }

func (p *countingPool) BeginTenant(context.Context, string, string) (db.TenantTx, error) {
	p.begun.Add(1)
	return nil, errors.New("connection refused")
}
func (*countingPool) Close() {}

func importRequest(t *testing.T, pool *countingPool, yamlDoc string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	body, _ := json.Marshal(map[string]string{"yaml": yamlDoc})
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/sites/import", strings.NewReader(string(body)))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), auth.ClaimsKey, &auth.Claims{
		TenantID: db.DevTenantID,
		UserID:   db.DevAdminID,
		Role:     "owner",
	}))
	handleImportSites(c, rbac.NewEnforcer(), db.NewStore(pool), nil, nil)
	return w
}

// The console's YAML import creates and updates sites, and it stored whatever
// the document said: a file:// feed, a feed with no url, a paranoia level of 9.
// It must refuse what create and update refuse, and refuse the whole document
// before writing any of it.
func TestImportRefusesBadPoliciesAndWritesNothing(t *testing.T) {
	const doc = `
sites:
  - name: good
    domains: [good.example.com]
    upstream: {servers: ["10.0.0.5:8080"]}
    waf_policy: {mode: blocking}
  - name: shop
    domains: [shop.example.com]
    upstream: {servers: ["10.0.0.6:8080"]}
    waf_policy:
      mode: blocking
      ip_reputation:
        feeds:
          - url: file:///etc/shadow
          - interval: 1h
          - url: 42
`
	pool := &countingPool{}
	w := importRequest(t, pool, doc)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400: %s", w.Code, w.Body.String())
	}
	if n := pool.begun.Load(); n != 0 {
		t.Fatalf("the store was used %d times; a refused import must write nothing", n)
	}
	var resp struct {
		Error    string              `json:"error"`
		Problems []SiteConfigProblem `json:"problems"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{
		"sites[shop].waf_policy.ip_reputation.feeds[0].url",
		"sites[shop].waf_policy.ip_reputation.feeds[1].url",
		"sites[shop].waf_policy.ip_reputation.feeds[2].url",
	} {
		if !hasField(resp.Problems, f) {
			t.Errorf("no problem reported on %s: %s", f, fields(resp.Problems))
		}
	}
	if !strings.Contains(resp.Error, "nothing was imported") || !strings.Contains(resp.Error, "sites[shop]") {
		t.Errorf("error should say nothing was imported and name the site: %q", resp.Error)
	}
}

// A clean document still goes through: it reaches the store (which this test's
// pool refuses, hence the 500).
func TestImportOfValidPoliciesReachesTheStore(t *testing.T) {
	const doc = `
sites:
  - name: shop
    domains: [shop.example.com]
    upstream: {servers: ["10.0.0.6:8080"]}
    waf_policy:
      mode: blocking
      ip_reputation:
        feeds:
          - {url: "https://iplists.firehol.org/files/firehol_level1.netset", interval: 1h, format: cidr}
`
	pool := &countingPool{}
	w := importRequest(t, pool, doc)
	if w.Code == http.StatusBadRequest {
		t.Fatalf("a valid document was refused: %s", w.Body.String())
	}
	if pool.begun.Load() == 0 {
		t.Fatalf("a valid document never reached the store (status %d)", w.Code)
	}
}
