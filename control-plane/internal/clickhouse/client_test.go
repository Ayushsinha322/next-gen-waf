package clickhouse

import (
	"strings"
	"testing"
)

// The tenant predicate is the cross-tenant isolation boundary for Threat
// Search: it must be present on every query, regardless of other filters, and
// the tenant value must be escaped.
func TestSearchWhereAlwaysScopesTenant(t *testing.T) {
	c := &Client{}

	// No other filters — tenant scoping still applied.
	w := strings.Join(c.searchWhere(SearchFilter{Tenant: "tenant-A"}), " AND ")
	if !strings.Contains(w, "tenant = 'tenant-A'") {
		t.Fatalf("tenant predicate missing with no other filters: %q", w)
	}

	// Other filters set — tenant scoping is not dropped.
	w2 := strings.Join(c.searchWhere(SearchFilter{
		Tenant: "tenant-A", Site: "s1", IP: "1.2.3.4", Rule: "942100",
	}), " AND ")
	if !strings.Contains(w2, "tenant = 'tenant-A'") {
		t.Fatalf("tenant predicate dropped when other filters present: %q", w2)
	}

	// A malicious tenant value is escaped (no SQL injection into the literal).
	w3 := strings.Join(c.searchWhere(SearchFilter{Tenant: "x' OR '1'='1"}), " AND ")
	if !strings.Contains(w3, `\'`) {
		t.Fatalf("tenant value not escaped: %q", w3)
	}
}
