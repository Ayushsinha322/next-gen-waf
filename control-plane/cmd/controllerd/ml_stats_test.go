package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/your-org/sentinel-waf/control-plane/internal/logs"
)

// The ML stats endpoint once returned fabricated accuracy figures — precision
// 0.953, recall 0.891, fp_rate 0.003 — plus three "Active Models" with invented
// versions, per-model precision/recall, latencies and last_updated dates. Two of
// the three models had no model file anywhere in the repo. The dashboard rendered
// all of it as live gauges on a 5-second refresh, so it read as measurement.
//
// These figures are not merely unmeasured, they are UNMEASURABLE from this
// process: precision and recall require labelled ground truth — knowing which
// requests were genuinely attacks — which only a triaged learning-mode pilot can
// produce. A WAF that invents its own accuracy numbers is worse than one that
// says it has not measured them, because a customer or auditor cannot tell the
// difference between the two by looking.
//
// This test fails if any of those keys reappear, whatever value they carry.
func TestMLStatsReportsNoFabricatedAccuracy(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/ml/stats", nil)

	// nil store: no auth claims in this context, so the enablement lookup is
	// skipped. The accuracy keys must be absent regardless of that path.
	handleMLStats(c, logs.NewHub(), nil)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}

	// Top-level keys that must never come back.
	for _, k := range []string{
		"precision", "recall", "f1", "f1_score", "fp_rate",
		"false_positives_today", "true_positives_today", "accuracy",
	} {
		if v, present := body[k]; present {
			t.Errorf("forbidden key %q present in ML stats response (value %v) — "+
				"accuracy is not measurable without labelled ground truth; "+
				"report quality_measured=false instead", k, v)
		}
	}

	// The honest-reporting contract the dashboard depends on.
	if qm, ok := body["quality_measured"].(bool); !ok || qm {
		t.Errorf("quality_measured must be present and false until a real FPR "+
			"pilot has been run; got %v", body["quality_measured"])
	}
	if note, ok := body["quality_note"].(string); !ok || note == "" {
		t.Error("quality_note must explain WHY accuracy is unavailable")
	}

	// Per-model accuracy is the same lie one level down.
	models, ok := body["models"].([]any)
	if !ok {
		t.Fatalf("models must be an array, got %T", body["models"])
	}
	for _, m := range models {
		mm, ok := m.(map[string]any)
		if !ok {
			t.Fatalf("model entry is not an object: %T", m)
		}
		for _, k := range []string{"precision", "recall", "latency_ms", "version", "last_updated"} {
			if v, present := mm[k]; present {
				t.Errorf("forbidden per-model key %q present (value %v) — the shipped "+
					"model file carries weights, not accuracy or provenance metadata", k, v)
			}
		}
		if name, _ := mm["name"].(string); name == "bot-classifier" || name == "anomaly-detector" {
			t.Errorf("model %q is advertised but no such model ships "+
				"(ml-models/%s is an empty directory)", name, name)
		}
	}

	// Exactly one classifier ships. If a second is ever added this test should be
	// updated deliberately, not silently — that is the point of asserting it.
	if len(models) != 1 {
		t.Errorf("expected exactly 1 shipped model, got %d — update this test "+
			"only when a real model file is genuinely added", len(models))
	}
}

// model_status was the constant string "active", which the overview page turned
// into a green "ML Engine" health row. It is false by default: the Rust config
// defaults ml.enable to false and the site wizard creates sites with ML off, so a
// stock install runs rules-only while the console reports the ML engine active.
func TestMLStatsModelStatusIsNotHardcodedActive(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/ml/stats", nil)

	handleMLStats(c, logs.NewHub(), nil)

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}

	status, _ := body["model_status"].(string)
	if status == "active" {
		t.Error(`model_status is the hardcoded "active" again — it must reflect ` +
			`real per-site enablement, because ML ships disabled by default`)
	}
	// With no store and no sites, the honest answer is that none are configured.
	if status != "no sites configured" {
		t.Errorf("expected %q with no sites, got %q", "no sites configured", status)
	}
}
