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
	if set["node_down"] || set["cert_expiring"] || set["disk_pressure"] {
		t.Fatal("operational kinds must never auto-resolve on quiet")
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
