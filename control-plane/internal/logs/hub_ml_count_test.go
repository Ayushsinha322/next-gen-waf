package logs

import (
	"encoding/json"
	"testing"
)

// The ML card read 0 beside real ML-ANOMALY blocks: its counter only moved on an
// "ml" stream that no data plane emits. It now counts ML-led waf events.
func TestMLLedDetectionsAreCounted(t *testing.T) {
	h := NewHub()
	for _, ev := range []map[string]any{
		{"action": "BLOCK", "rule": "ML-ANOMALY", "site": "s"},
		{"action": "DETECT", "rule": "ML-ANOMALY", "site": "s"},
		{"action": "BLOCK", "rule": "942100", "site": "s"},
		{"action": "PASS", "rule": "ML-ANOMALY", "site": "s"},
	} {
		b, _ := json.Marshal(ev)
		h.updateMetrics(Entry{Kind: "waf", Data: b})
	}
	if got := h.mlAnomalies.Load(); got != 2 {
		t.Fatalf("ml_anomalies = %d, want 2 (one blocked, one would-block; not the CRS block, not a PASS)", got)
	}
	if got := AttackCategory("ML-ANOMALY"); got != "ml" {
		t.Fatalf("AttackCategory(ML-ANOMALY) = %q", got)
	}
}
