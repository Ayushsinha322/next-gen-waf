package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The heartbeat shape the data plane sends (crates/sentinel-proxy ConfigSyncStatus).
const rejectingHeartbeat = `{"config_version_applied":221,"config_sync":{"last_error":null,"failing_since":null,
 "rejected_sites":[{"id":"audit-ui-a","error":"invalid type: null, expected a sequence","kept_previous":true}]}}`

func TestANodeRejectingASiteDegradesTheFleet(t *testing.T) {
	var md nodeMetadata
	if err := json.Unmarshal([]byte(rejectingHeartbeat), &md); err != nil {
		t.Fatal(err)
	}
	rejecting, why := rejectingConfig(md.ConfigSync, time.Now())
	if !rejecting {
		t.Fatal("a node that rejected a site must count as not taking config")
	}
	if !strings.Contains(why, "audit-ui-a") || !strings.Contains(why, "previous config") {
		t.Fatalf("the reason must name the site and what the node did with it: %q", why)
	}
	if got := withConfigSync("healthy", 1); got != "degraded" {
		t.Fatalf("healthy fleet with a rejecting node = %q, want degraded", got)
	}
	if got := withConfigSync("critical", 1); got != "critical" {
		t.Fatalf("must never soften a worse verdict: %q", got)
	}
}

func TestAPollFailureCountsOnlyAfterTheGrace(t *testing.T) {
	now := time.Now()
	errMsg := "fetch: connection refused"
	recent := now.Add(-5 * time.Second).Unix()
	old := now.Add(-2 * time.Minute).Unix()
	if r, _ := rejectingConfig(&nodeConfigSync{LastError: &errMsg, FailingSince: &recent}, now); r {
		t.Fatal("one missed poll is not an incident")
	}
	r, why := rejectingConfig(&nodeConfigSync{LastError: &errMsg, FailingSince: &old}, now)
	if !r || !strings.Contains(why, "connection refused") {
		t.Fatalf("two minutes of failed polls must count, with the error: %v %q", r, why)
	}
}

func TestAHealthyOrOlderNodeIsNotRejecting(t *testing.T) {
	if r, _ := rejectingConfig(nil, time.Now()); r {
		t.Fatal("a node from before config_sync existed must not be flagged")
	}
	var md nodeMetadata
	_ = json.Unmarshal([]byte(`{"config_sync":{"last_error":null,"failing_since":null,"rejected_sites":[]}}`), &md)
	if r, _ := rejectingConfig(md.ConfigSync, time.Now()); r {
		t.Fatal("a clean status must not be flagged")
	}
	if got := withConfigSync("healthy", 0); got != "healthy" {
		t.Fatal(got)
	}
}

// The data plane's /healthz config_sync block (crates/sentinel-proxy
// config_sync_health). The Jobs page drew config.sync as a fixed green
// "running" badge because the block was never passed on.
func TestTheJobsViewCarriesTheDataPlaneConfigSync(t *testing.T) {
	var h map[string]any
	healthz := `{"uptime_secs":12,"version":"1.1.15","threat_intel":{"poller":"failing"},
 "config_sync":{"configured":true,"version_applied":221,"last_error":"timeout: no complete response within 10s",
  "failing_since":1790000000,"rejected_site_count":0}}`
	if err := json.Unmarshal([]byte(healthz), &h); err != nil {
		t.Fatal(err)
	}
	view := dataPlaneJobsView(h)
	cs, ok := view["config_sync"].(map[string]any)
	if !ok {
		t.Fatalf("config_sync must reach the console, got %#v", view["config_sync"])
	}
	if cs["last_error"] != "timeout: no complete response within 10s" {
		t.Fatalf("the failure must arrive as the node reported it: %#v", cs)
	}
	if view["threat_intel"] == nil || view["reachable"] != true {
		t.Fatalf("the existing fields must still be carried: %#v", view)
	}
	// A data plane older than the field: absent, which the console shows as
	// "not reported" rather than as healthy.
	if v := dataPlaneJobsView(map[string]any{})["config_sync"]; v != nil {
		t.Fatalf("an absent block must stay absent, got %#v", v)
	}
}

// The heartbeat shape from crates/sentinel-proxy ti_sync_heartbeat. The cluster
// read carried only the entry count, which reads the same for a node refreshing
// its IOC set and one whose polls have failed for a day.
func TestAThreatIntelSyncFailureReachesTheClusterRead(t *testing.T) {
	var md nodeMetadata
	hb := `{"threat_intel_entries":5000,"threat_intel_sync":{"poller":"failing","last_sync_status":200,
 "last_error":"timeout: no complete response within 30s","failing_since":1790000000}}`
	if err := json.Unmarshal([]byte(hb), &md); err != nil {
		t.Fatal(err)
	}
	why := threatIntelSyncProblem(md.ThreatIntelSync)
	if !strings.Contains(why, "timeout: no complete response within 30s") ||
		!strings.Contains(why, time.Unix(1790000000, 0).UTC().Format(time.RFC3339)) {
		t.Fatalf("the problem must give the error and since when: %q", why)
	}

	refused := &nodeTISync{Poller: "rejected", LastSyncStatus: 403}
	if why := threatIntelSyncProblem(refused); !strings.Contains(why, "HTTP 403") {
		t.Fatalf("a refusal must name the status: %q", why)
	}

	if why := threatIntelSyncProblem(&nodeTISync{Poller: "running", LastSyncStatus: 200}); why != "" {
		t.Fatalf("a running poller has no problem: %q", why)
	}
	var older nodeMetadata
	_ = json.Unmarshal([]byte(`{"threat_intel_entries":5000}`), &older)
	if why := threatIntelSyncProblem(older.ThreatIntelSync); why != "" {
		t.Fatalf("a node from before the field must not be flagged: %q", why)
	}
}
