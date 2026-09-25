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

// Threat Search's "Top Attack Types" groups by attack, and "Top Rules" names
// each rule. Both are facet queries; neither may drop the tenant predicate, and
// a column outside the whitelist must still be refused.
func TestFacetSQL(t *testing.T) {
	c := &Client{db: "sentinel"}

	sql, err := c.facetSQL("attack", "tenant-A", 100, 200, 8)
	if err != nil {
		t.Fatalf("attack facet refused: %v", err)
	}
	for _, want := range []string{"SELECT attack AS key", "tenant = 'tenant-A'", "attack != ''", "LIMIT 8"} {
		if !strings.Contains(sql, want) {
			t.Errorf("attack facet SQL lacks %q: %s", want, sql)
		}
	}
	if strings.Contains(sql, "AS label") {
		t.Errorf("only the rule facet carries a label: %s", sql)
	}

	sql, err = c.facetSQL("rule", "tenant-A", 100, 200, 8)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sql, "argMax(attack, ts) AS label") {
		t.Errorf("rule facet does not name its rules: %s", sql)
	}
	if !strings.Contains(sql, "tenant = 'tenant-A'") {
		t.Errorf("rule facet dropped the tenant predicate: %s", sql)
	}

	if _, err := c.facetSQL("attack; DROP TABLE waf_events", "t", 0, 0, 5); err == nil {
		t.Error("a non-whitelisted facet column was accepted")
	}
}
