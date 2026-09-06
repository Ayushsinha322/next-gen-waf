package settings

import (
	"encoding/json"
	"testing"
	"time"
)

func TestResolutionOrderDBOverEnvOverDefault(t *testing.T) {
	t.Setenv("SENTINEL_ALERT_SPIKE_THRESHOLD", "40")
	t.Setenv("SENTINEL_THREATINTEL_INTERVAL", "2h") // legacy Go-duration form
	eff := Resolve(map[string]Override{
		"alerting.offender_threshold": {Value: json.RawMessage(`7`), UpdatedAt: time.Now()},
	})
	got := map[string]Effective{}
	for _, e := range eff {
		got[e.Name] = e
	}
	if e := got["alerting.spike_threshold"]; e.Value != int64(40) || e.Source != "env" {
		t.Fatalf("env should win over default: %+v", e)
	}
	if e := got["alerting.offender_threshold"]; e.Value != int64(7) || e.Source != "db" {
		t.Fatalf("db should win: %+v", e)
	}
	if e := got["alerting.window_secs"]; e.Value != 60 || e.Source != "default" {
		t.Fatalf("default expected: %+v", e)
	}
	if e := got["threat_intel.interval_secs"]; e.Value != int64(7200) || e.Source != "env" {
		t.Fatalf("duration env must convert to seconds: %+v", e)
	}
}

func TestCoerceRejectsBadValues(t *testing.T) {
	k, _ := Lookup("alerting.auto_resolve_secs")
	if _, err := Coerce(k, json.RawMessage(`30`)); err == nil {
		t.Fatal("30s auto-resolve must be rejected (below 60 and not -1)")
	}
	if v, err := Coerce(k, json.RawMessage(`-1`)); err != nil || v != int64(-1) {
		t.Fatalf("-1 must be accepted as 'disabled': %v %v", v, err)
	}
	f, _ := Lookup("threat_intel.feed.tor")
	if _, err := Coerce(f, json.RawMessage(`"ftp://x"`)); err == nil {
		t.Fatal("non-http feed URL must be rejected")
	}
	if v, err := Coerce(f, json.RawMessage(`"off"`)); err != nil || v != "off" {
		t.Fatalf("'off' must be accepted: %v %v", v, err)
	}
	b, _ := Lookup("threat_intel.enabled")
	if _, err := Coerce(b, json.RawMessage(`"yes"`)); err == nil {
		t.Fatal("bool key must reject a string")
	}
	if _, ok := Lookup("nope.key"); ok {
		t.Fatal("unknown key must not resolve")
	}
}

func TestSnapshotAccessors(t *testing.T) {
	v := Snapshot(nil)
	if v.Duration("alerting.throttle_secs") != 5*time.Minute {
		t.Fatalf("default throttle: %v", v.Duration("alerting.throttle_secs"))
	}
	if !v.Bool("threat_intel.enabled") {
		t.Fatal("threat intel defaults on")
	}
}
