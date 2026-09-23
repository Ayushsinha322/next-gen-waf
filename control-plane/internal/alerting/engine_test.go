package alerting

import (
	"testing"

	"go.uber.org/zap"
)

func zapNop() *zap.Logger { return zap.NewNop() }

// Every kind onWaf can produce must be auto-resolvable, or an attack alert
// would pile up forever the way 562 of them did on the demo box.
func TestAttackKindsAreAllEventDriven(t *testing.T) {
	set := map[string]bool{}
	for _, k := range EventDrivenKinds {
		set[k] = true
	}
	cases := [][2]string{
		{"SQL Injection Attack", "942100"}, {"XSS Attack", "941100"}, {"Remote Command Execution", "932100"},
		{"Path Traversal", "930100"}, {"Scanner Detection", "913100"}, {"", "999999"}, {"", ""},
	}
	for _, c := range cases {
		k := attackKind(c[0], c[1])
		if !set[k] {
			t.Fatalf("attackKind(%q,%q)=%q is not in EventDrivenKinds", c[0], c[1], k)
		}
	}
	if set["node_down"] || set["cp_node_down"] || set["quorum_at_risk"] || set["cert_expiring"] || set["disk_pressure"] {
		t.Fatal("operational kinds must never auto-resolve on quiet")
	}
	// Every kind that has EVER been written to the alerts table must be owned by
	// EventDrivenKinds or by nodehealth.orphanedInfraKinds. This list is the
	// record of the ones no current code path raises. cmdinj was missing from
	// it and from the sweep, so 78 acknowledged "Command injection attempt"
	// rows survived the July cleanup that closed all three of its siblings and
	// were still sitting there 48 days later.
	for _, legacy := range []string{"rate_limit", "path_traversal", "log4shell", "cmdinj", "node_recovered"} {
		if !set[legacy] {
			t.Fatalf("%s is raised by nothing and swept by nothing: its rows can never close", legacy)
		}
	}
}

func TestAutoResolveDefaultAndDisable(t *testing.T) {
	e := New(nil, nil, "t", "u", Config{}, zapNop())
	if e.cfg.AutoResolveAfter <= 0 {
		t.Fatalf("default auto-resolve window must be positive, got %v", e.cfg.AutoResolveAfter)
	}
	e2 := New(nil, nil, "t", "u", Config{AutoResolveAfter: -1}, zapNop())
	if e2.cfg.AutoResolveAfter >= 0 {
		t.Fatal("negative must be preserved as 'disabled'")
	}
}

// An ongoing condition re-notifies channels only when it gets WORSE; the same
// reading every throttle interval is a dashboard refresh, not a page to on-call.
func TestOngoingAlertsNotifyOnlyOnEscalation(t *testing.T) {
	for _, c := range []struct {
		prev, next string
		want       bool
	}{
		{"warning", "high", true}, {"high", "critical", true}, {"warning", "critical", true},
		{"warning", "warning", false}, {"critical", "high", false}, {"high", "warning", false},
	} {
		if got := escalates(c.prev, c.next); got != c.want {
			t.Errorf("escalates(%q,%q)=%v want %v", c.prev, c.next, got, c.want)
		}
	}
}
