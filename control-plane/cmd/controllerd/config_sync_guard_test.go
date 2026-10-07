package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"go.uber.org/zap"
)

// fakeSyncReads replaces the three reads a sync is built from and records
// the order they ran in.
func fakeSyncReads(t *testing.T, versionErr, rulesErr error) *[]string {
	t.Helper()
	order := &[]string{}
	v, s, r := syncConfigVersion, syncActiveSites, syncCustomRules
	t.Cleanup(func() { syncConfigVersion, syncActiveSites, syncCustomRules = v, s, r })
	syncConfigVersion = func(context.Context, *db.Store) (int64, error) {
		*order = append(*order, "version")
		return 42, versionErr
	}
	syncActiveSites = func(context.Context, *db.Store) ([]db.SiteRow, error) {
		*order = append(*order, "sites")
		return []db.SiteRow{{
			ID: "00000000-0000-4000-8000-0000000000a1", TenantID: db.DevTenantID,
			Name: "shop", Domains: []string{"shop.example.in"}, Status: "active",
			Upstream:  json.RawMessage(`{"servers":[{"host":"10.0.0.5","port":8080}]}`),
			WafPolicy: json.RawMessage(`{"mode":"learning"}`),
		}}, nil
	}
	syncCustomRules = func(context.Context, *db.Store) (map[string][]db.DeployableRule, error) {
		*order = append(*order, "rules")
		return map[string][]db.DeployableRule{}, rulesErr
	}
	return order
}

func syncRequest(t *testing.T) (int, map[string]any) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	t.Setenv("SENTINEL_INTERNAL_SECRET", "sync-test-secret")
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/internal/config", nil)
	c.Request.Header.Set("x-sentinel-internal", "sync-test-secret")
	handleInternalConfig(c, db.NewStore(failingPool{}), zap.NewNop())
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w.Code, body
}

// A sync without the custom rules carried the real version, so every node
// cached it as current and kept its virtual patches off after the read
// recovered.
func TestConfigSyncIsRefusedWhenTheCustomRulesCannotBeRead(t *testing.T) {
	fakeSyncReads(t, nil, errors.New("relation \"rules\" is locked"))
	code, body := syncRequest(t)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 so nodes keep their config, got %d: %v", code, body)
	}
	if _, shipped := body["sites"]; shipped {
		t.Fatal("a partial config was shipped")
	}
}

// Read after the content, a version could label an older site list.
func TestConfigSyncReadsTheVersionBeforeTheContent(t *testing.T) {
	order := fakeSyncReads(t, nil, nil)
	code, body := syncRequest(t)
	if code != http.StatusOK {
		t.Fatalf("sync failed: %d %v", code, body)
	}
	if len(*order) == 0 || (*order)[0] != "version" {
		t.Fatalf("reads ran in the order %v; the version must come first", *order)
	}
	if body["version_source"] != "generation" || body["version"] != float64(42) {
		t.Fatalf("a counter version must say so: %v", body)
	}
}

func TestConfigSyncSaysWhenItsVersionIsOnlyAFingerprint(t *testing.T) {
	fakeSyncReads(t, errors.New("function sentinel_config_version() does not exist"), nil)
	code, body := syncRequest(t)
	if code != http.StatusOK || body["version_source"] != "fingerprint" {
		t.Fatalf("got %d %v", code, body)
	}
}
