package nodehealth

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/your-org/sentinel-waf/control-plane/internal/db"
)

func meta(t *testing.T, raw string) heartbeatMeta {
	t.Helper()
	var md heartbeatMeta
	if err := json.Unmarshal([]byte(raw), &md); err != nil {
		t.Fatalf("heartbeat fixture: %v", err)
	}
	return md
}

func kinds(fs []finding) string {
	var k []string
	for _, f := range fs {
		k = append(k, f.Kind)
	}
	return strings.Join(k, ",")
}

var dp1 = db.Node{ID: "dp-1", Hostname: "waf1", Role: "data-plane"}

// A healthy heartbeat, as a 1.1.18 data plane sends it, raises nothing.
func TestAHealthyNodeRaisesNothing(t *testing.T) {
	tr := newNodeTrack()
	now := time.Now()
	hb := `{"uptime_secs":100,"sites_refused":[],"history_shed":0,"clickhouse":{"configured":true,"connected":true},
	        "acme_failing":[],"config_version_applied":7,"config_sync":{"last_error":null,"failing_since":null,"rejected_sites":[]},
	        "panics":{"total":0,"restarting":null}}`
	for i := 0; i < 40; i++ {
		on, ev, _ := tr.evaluate(dp1, meta(t, hb), 7, now.Add(time.Duration(i)*10*time.Second))
		if len(on)+len(ev) > 0 {
			t.Fatalf("sweep %d: %s %s", i, kinds(on), kinds(ev))
		}
	}
}

// A site refused for a reload's few seconds is not news; one refused for a
// minute is, and it closes when the site is served again.
func TestARefusedSiteAlertsAfterItsHoldTimeAndClears(t *testing.T) {
	tr := newNodeTrack()
	t0 := time.Now()
	refused := meta(t, `{"uptime_secs":10,"sites_refused":["shop"]}`)
	on, _, present := tr.evaluate(dp1, refused, 0, t0)
	if len(on) != 0 || !present[KindSiteRefused] {
		t.Fatalf("alerted inside the hold time, or did not see it: %s %v", kinds(on), present)
	}
	on, _, _ = tr.evaluate(dp1, refused, 0, t0.Add(30*time.Second))
	if len(on) != 0 {
		t.Fatal("alerted at 30 s")
	}
	on, _, _ = tr.evaluate(dp1, refused, 0, t0.Add(61*time.Second))
	if kinds(on) != KindSiteRefused || on[0].Severity != "critical" || !strings.Contains(on[0].Summary, "shop") {
		t.Fatalf("a site refused for a minute did not alert critically by name: %+v", on)
	}
	_, _, present = tr.evaluate(dp1, meta(t, `{"uptime_secs":80,"sites_refused":[]}`), 0, t0.Add(70*time.Second))
	if present[KindSiteRefused] {
		t.Fatal("still present after the site was served again")
	}
	// And the hold time starts over.
	on, _, _ = tr.evaluate(dp1, refused, 0, t0.Add(80*time.Second))
	if len(on) != 0 {
		t.Fatal("a new refusal skipped its hold time")
	}
}

func TestShedEventsAndPanicsAlertPerIncreaseNotPerReading(t *testing.T) {
	tr := newNodeTrack()
	t0 := time.Now()
	_, ev, _ := tr.evaluate(dp1, meta(t, `{"uptime_secs":10,"history_shed":40,"panics":{"total":2}}`), 0, t0)
	if len(ev) != 0 {
		t.Fatalf("the first reading is a baseline, not news: %s", kinds(ev))
	}
	_, ev, _ = tr.evaluate(dp1, meta(t, `{"uptime_secs":20,"history_shed":40,"panics":{"total":2}}`), 0, t0.Add(10*time.Second))
	if len(ev) != 0 {
		t.Fatalf("an unchanged counter alerted: %s", kinds(ev))
	}
	_, ev, _ = tr.evaluate(dp1, meta(t, `{"uptime_secs":30,"history_shed":55,"panics":{"total":3}}`), 0, t0.Add(20*time.Second))
	if kinds(ev) != KindEventsShed+","+KindPanic || ev[0].Details["shed"] != uint64(15) {
		t.Fatalf("increases: %+v", ev)
	}
	// A restart resets both counters: a new baseline.
	_, ev, _ = tr.evaluate(dp1, meta(t, `{"uptime_secs":5,"history_shed":0,"panics":{"total":0}}`), 0, t0.Add(30*time.Second))
	if len(ev) != 0 {
		t.Fatalf("a counter reset alerted: %s", kinds(ev))
	}
}

func TestThreeRestartsInFifteenMinutesIsARestartLoop(t *testing.T) {
	tr := newNodeTrack()
	t0 := time.Now()
	up := func(secs int, at time.Duration) []finding {
		on, _, _ := tr.evaluate(dp1, meta(t, `{"uptime_secs":`+itoa(secs)+`}`), 0, t0.Add(at))
		return on
	}
	up(300, 0)
	up(5, time.Minute) // restart 1
	up(5+60, 2*time.Minute)
	up(3, 3*time.Minute)                                          // restart 2
	if on := up(2, 4*time.Minute); kinds(on) != KindRestartLoop { // restart 3
		t.Fatalf("three restarts in four minutes: %s", kinds(on))
	}
	// Quiet for longer than the window: no longer a loop.
	if on := up(2+20*60, 24*time.Minute); len(on) != 0 {
		t.Fatalf("still a loop after 20 quiet minutes: %s", kinds(on))
	}
}

func TestACrashLoopingBackgroundLoopIsARestartLoop(t *testing.T) {
	tr := newNodeTrack()
	on, _, _ := tr.evaluate(dp1, meta(t, `{"uptime_secs":500,"panics":{"total":9,"restarting":"config sync"}}`), 0, time.Now())
	if kinds(on) != KindRestartLoop || !strings.Contains(on[0].Summary, "config sync") {
		t.Fatalf("%+v", on)
	}
}

func TestEventStoreACMEAndStaleConfig(t *testing.T) {
	tr := newNodeTrack()
	t0 := time.Now()
	failing := t0.Add(-10 * time.Minute).Unix()
	hb := meta(t, `{"uptime_secs":900,
	  "clickhouse":{"configured":true,"connected":false,"failures_total":12},
	  "acme_failing":[{"domains":["shop.example.in"],"failures":1,"error":"dns"},
	                  {"domains":["api.example.in"],"failures":3,"error":"NXDOMAIN"}],
	  "config_version_applied":5,
	  "config_sync":{"last_error":"503 from control plane","failing_since":`+itoa(int(failing))+`,"rejected_sites":[]}}`)
	on, _, _ := tr.evaluate(dp1, hb, 9, t0)
	// ACME has no hold time of its own (an order is only reported after it
	// failed), a single failure is not yet an alert, and the config poll has
	// already been failing for ten minutes.
	if kinds(on) != KindACMEFailing+","+KindConfigStale {
		t.Fatalf("at t0: %s", kinds(on))
	}
	if s := on[0].Summary; !strings.Contains(s, "api.example.in") || strings.Contains(s, "shop.example.in") {
		t.Fatalf("ACME summary: %s", s)
	}
	if s := on[1].Summary; !strings.Contains(s, "503 from control plane") || strings.Contains(s, "version 5") {
		t.Fatalf("the version lag must wait for its own hold time: %s", s)
	}
	on, _, _ = tr.evaluate(dp1, hb, 9, t0.Add(6*time.Minute))
	if kinds(on) != KindClickHouseDown+","+KindACMEFailing+","+KindConfigStale {
		t.Fatalf("after six minutes: %s", kinds(on))
	}
	if !strings.Contains(on[2].Summary, "serving config version 5, the control plane is on 9") {
		t.Fatalf("version lag: %s", on[2].Summary)
	}
}

// Fields an older data plane does not send must read as "nothing to report",
// never as a fault: a fleet mid-upgrade would otherwise page for every node.
func TestAPre118HeartbeatRaisesNothing(t *testing.T) {
	tr := newNodeTrack()
	hb := meta(t, `{"uptime_secs":100,"config_version_applied":3,"panics":{"total":0}}`)
	for i := 0; i < 5; i++ {
		on, ev, _ := tr.evaluate(dp1, hb, 3, time.Now().Add(time.Duration(i)*time.Minute))
		if len(on)+len(ev) > 0 {
			t.Fatalf("%s %s", kinds(on), kinds(ev))
		}
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }
