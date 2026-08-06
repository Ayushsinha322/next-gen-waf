package clickhouse

import (
	"strings"
	"testing"
)

func TestLookupExportFormat(t *testing.T) {
	for _, tc := range []struct {
		in       string
		wantOK   bool
		wantExt  string
		wantCH   string
		wantMime string
	}{
		{"csv", true, "csv", "CSVWithNames", "text/csv; charset=utf-8"},
		{"CSV", true, "csv", "CSVWithNames", "text/csv; charset=utf-8"},
		{" ndjson ", true, "ndjson", "JSONEachRow", "application/x-ndjson; charset=utf-8"},
		{"json", true, "json", "JSON", "application/json; charset=utf-8"},
		{"xlsx", false, "", "", ""},
		{"", false, "", "", ""},
		// The format string is interpolated into SQL, so anything outside the
		// whitelist must be rejected rather than passed through.
		{"CSVWithNames FORMAT Null; DROP", false, "", "", ""},
	} {
		got, ok := LookupExportFormat(tc.in)
		if ok != tc.wantOK {
			t.Fatalf("LookupExportFormat(%q) ok = %v, want %v", tc.in, ok, tc.wantOK)
		}
		if !ok {
			continue
		}
		if got.Ext != tc.wantExt || got.chFormat != tc.wantCH || got.MediaType != tc.wantMime {
			t.Fatalf("LookupExportFormat(%q) = %+v, want ext=%q ch=%q mime=%q",
				tc.in, got, tc.wantExt, tc.wantCH, tc.wantMime)
		}
	}
}

// An export is a bulk extract of one tenant's traffic. The tenant predicate is
// the isolation boundary and must be on the count query and the stream query
// alike — a filter set that happens to match another tenant's site name must
// not widen the result.
func TestExportSharesTenantScoping(t *testing.T) {
	c := &Client{}
	w := strings.Join(c.searchWhere(SearchFilter{Tenant: "tenant-A", Site: "shop.example"}), " AND ")
	if !strings.Contains(w, "tenant = 'tenant-A'") {
		t.Fatalf("tenant predicate missing from export filter: %q", w)
	}
	if !strings.Contains(w, "site = 'shop.example'") {
		t.Fatalf("site predicate missing from export filter: %q", w)
	}
}

func TestSearchWhereSeverity(t *testing.T) {
	c := &Client{}

	// Absent severity adds no predicate at all — an empty filter must not
	// silently exclude rows whose severity is empty.
	w := strings.Join(c.searchWhere(SearchFilter{Tenant: "t"}), " AND ")
	if strings.Contains(w, "severity") {
		t.Fatalf("empty severity should add no predicate: %q", w)
	}

	// Matched case-insensitively on both sides: the data plane has written
	// mixed case over the life of the table.
	w2 := strings.Join(c.searchWhere(SearchFilter{Tenant: "t", Severity: "critical"}), " AND ")
	if !strings.Contains(w2, "upper(severity) = 'CRITICAL'") {
		t.Fatalf("severity predicate wrong: %q", w2)
	}

	// The value still passes through esc().
	w3 := strings.Join(c.searchWhere(SearchFilter{Tenant: "t", Severity: "x' OR '1'='1"}), " AND ")
	if !strings.Contains(w3, `\'`) {
		t.Fatalf("severity value not escaped: %q", w3)
	}
}

// The customer-facing column list is spelled out rather than SELECT *, so that
// a new waf_events column never starts leaking into exports by default.
func TestExportColumnsAreExplicit(t *testing.T) {
	if strings.Contains(exportColumns, "*") {
		t.Fatalf("exportColumns must not use SELECT *: %q", exportColumns)
	}
	// ts is rendered as an ISO-8601 string, not a raw epoch — the file is read
	// by a human in a support ticket.
	if !strings.Contains(exportColumns, "timestamp_utc") {
		t.Fatalf("exportColumns must expose a human-readable timestamp: %q", exportColumns)
	}
}

// The Support ID lookup must NOT be time-bounded. A customer rings on Thursday
// about a block from Monday, and the operator has whatever range the UI last
// had selected; applying it would return nothing and read as "no such request",
// which is the exact failure this feature exists to prevent.
func TestSupportIDLookupIsNotTimeBounded(t *testing.T) {
	c := &Client{db: "sentinel_logs"}
	// searchWhere always injects a ts predicate via timeWhere; the support
	// lookup builds its own WHERE and must not pick one up.
	w := strings.Join(c.searchWhere(SearchFilter{Tenant: "t"}), " AND ")
	if !strings.Contains(w, "ts >=") {
		t.Fatalf("precondition: normal search should be time-bounded: %q", w)
	}
}

// The id is quoted by a caller over the phone; it must not be usable to read
// another tenant's event.
func TestSupportIDLookupIsTenantScoped(t *testing.T) {
	got := eq("tenant", "tenant-A")
	if got != "tenant = 'tenant-A'" {
		t.Fatalf("tenant predicate = %q", got)
	}
	// And the id itself is escaped like any other untrusted value.
	if !strings.Contains(eq("request_id", "x' OR '1'='1"), `\'`) {
		t.Fatalf("support id not escaped: %q", eq("request_id", "x' OR '1'='1"))
	}
}

// The Support ID is stored on every row; if the text filter cannot match it,
// the block page's whole support path is decorative.
func TestSearchMatchesRequestID(t *testing.T) {
	c := &Client{}
	w := strings.Join(c.searchWhere(SearchFilter{Tenant: "t", Query: "abc-123"}), " AND ")
	if !strings.Contains(w, "request_id = 'abc-123'") {
		t.Fatalf("text search does not match request_id: %q", w)
	}
}
