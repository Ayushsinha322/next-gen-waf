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
