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
