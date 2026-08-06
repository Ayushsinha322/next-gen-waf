package main

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/rbac"
)

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("bad fixture time %q: %v", s, err)
	}
	return ts
}

func TestResolveExportWindow(t *testing.T) {
	now := mustTime(t, "2026-08-06T12:00:00Z")
	day := 24 * time.Hour

	// The headline case: the customer asks for one specific date. Both bounds
	// explicit, nothing inferred.
	from := mustTime(t, "2026-08-03T00:00:00Z")
	to := mustTime(t, "2026-08-04T00:00:00Z")
	gotFrom, gotTo, err := resolveExportWindow(
		unixStr(from.Unix()), unixStr(to.Unix()), day, now)
	if err != nil {
		t.Fatalf("explicit range rejected: %v", err)
	}
	if !gotFrom.Equal(from) || !gotTo.Equal(to) {
		t.Fatalf("explicit range = %v..%v, want %v..%v", gotFrom, gotTo, from, to)
	}

	// Neither bound given: the profile's default window ending now, so "open the
	// profile and hit download" answers "what happened today".
	gotFrom, gotTo, err = resolveExportWindow("", "", day, now)
	if err != nil {
		t.Fatalf("default range rejected: %v", err)
	}
	if !gotTo.Equal(now) || !gotFrom.Equal(now.Add(-day)) {
		t.Fatalf("default range = %v..%v, want %v..%v", gotFrom, gotTo, now.Add(-day), now)
	}

	// Only `to` given: the window is the default ending at that instant, not
	// ending now — otherwise asking for an old date silently returns today.
	anchor := mustTime(t, "2026-08-04T00:00:00Z")
	gotFrom, gotTo, err = resolveExportWindow("", unixStr(anchor.Unix()), day, now)
	if err != nil {
		t.Fatalf("to-only range rejected: %v", err)
	}
	if !gotTo.Equal(anchor) || !gotFrom.Equal(anchor.Add(-day)) {
		t.Fatalf("to-only range = %v..%v, want %v..%v", gotFrom, gotTo, anchor.Add(-day), anchor)
	}

	// A zero-length or inverted window is a typo, not a query.
	if _, _, err := resolveExportWindow(unixStr(to.Unix()), unixStr(from.Unix()), day, now); err == nil {
		t.Fatal("inverted range accepted, want error")
	}
	if _, _, err := resolveExportWindow(unixStr(from.Unix()), unixStr(from.Unix()), day, now); err == nil {
		t.Fatal("zero-length range accepted, want error")
	}

	// Beyond the maximum window: far likelier a mistyped year than an intent to
	// pull a decade of traffic, and it would pin the event store either way.
	old := now.Add(-2 * maxExportWindow)
	_, _, err = resolveExportWindow(unixStr(old.Unix()), unixStr(now.Unix()), day, now)
	if err == nil {
		t.Fatal("over-long range accepted, want error")
	}
	if !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("over-long range error should name the limit, got %q", err)
	}

	// Exactly at the limit is allowed — the boundary is inclusive.
	edge := now.Add(-maxExportWindow)
	if _, _, err := resolveExportWindow(unixStr(edge.Unix()), unixStr(now.Unix()), day, now); err != nil {
		t.Fatalf("range exactly at the limit rejected: %v", err)
	}

	// Garbage parses as absent rather than as epoch 0, which would otherwise
	// silently become a 56-year window and trip the maximum.
	if _, _, err := resolveExportWindow("not-a-number", "", day, now); err != nil {
		t.Fatalf("unparseable from should fall back to the default window, got %v", err)
	}
}

func TestExportFilename(t *testing.T) {
	from := mustTime(t, "2026-08-03T00:00:00Z")
	to := mustTime(t, "2026-08-04T00:00:00Z")

	got := exportFilename("shop.example.com", from, to, "csv")
	want := "shop.example.com_20260803-0000_to_20260804-0000_waf-events.csv"
	if got != want {
		t.Fatalf("exportFilename = %q, want %q", got, want)
	}

	// No site means the profile spans every application in the tenant; the name
	// has to say so rather than starting with a bare underscore.
	if got := exportFilename("", from, to, "ndjson"); !strings.HasPrefix(got, "all-sites_") {
		t.Fatalf("empty site filename = %q, want all-sites prefix", got)
	}
}

// The site name reaches a Content-Disposition header. Quotes, CR/LF and path
// separators are the header-injection and traversal vectors on that path.
func TestSanitizeFilenamePart(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"shop.example.com", "shop.example.com"},
		{"my site", "my-site"},
		{`ev"il`, "ev-il"},
		{"a\r\nX-Injected: 1", "a--X-Injected--1"},
		{"../../etc/passwd", "etc-passwd"},
		{"", ""},
	} {
		if got := sanitizeFilenamePart(tc.in); got != tc.want {
			t.Fatalf("sanitizeFilenamePart(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	// No unescaped quote can survive, whatever the input.
	for _, in := range []string{`"`, `a"b"c`, "\"; rm -rf /"} {
		if strings.ContainsAny(sanitizeFilenamePart(in), "\"\\\r\n/") {
			t.Fatalf("sanitizeFilenamePart(%q) left a dangerous character: %q", in, sanitizeFilenamePart(in))
		}
	}

	// Long names are truncated so the header stays bounded.
	if got := sanitizeFilenamePart(strings.Repeat("a", 200)); len(got) != 64 {
		t.Fatalf("long site name not truncated: len = %d", len(got))
	}
}

func TestValidateProfileRequest(t *testing.T) {
	s := func(v string) *string { return &v }
	i := func(v int) *int { return &v }

	if err := validateProfileRequest(&db.LogProfileRequest{}); err != nil {
		t.Fatalf("empty request should be valid (all fields optional on update): %v", err)
	}
	if err := validateProfileRequest(&db.LogProfileRequest{DefaultFormat: s("csv")}); err != nil {
		t.Fatalf("csv rejected: %v", err)
	}
	if err := validateProfileRequest(&db.LogProfileRequest{DefaultFormat: s("pdf")}); err == nil {
		t.Fatal("unknown format accepted, want error")
	}
	if err := validateProfileRequest(&db.LogProfileRequest{DefaultRangeSecs: i(0)}); err == nil {
		t.Fatal("zero default_range_secs accepted, want error")
	}
	if err := validateProfileRequest(&db.LogProfileRequest{DefaultRangeSecs: i(31536001)}); err == nil {
		t.Fatal("over-long default_range_secs accepted, want error")
	}
	if err := validateProfileRequest(&db.LogProfileRequest{DefaultRangeSecs: i(86400)}); err != nil {
		t.Fatalf("one-day default_range_secs rejected: %v", err)
	}
}

// Downloading is a bulk extract of customer traffic leaving the platform, so it
// sits a rung above reading a page of it on screen.
func TestLogProfileRBAC(t *testing.T) {
	e := rbac.NewEnforcer()

	for _, role := range []rbac.Role{rbac.RoleOwner, rbac.RoleAdmin, rbac.RoleEditor} {
		for _, action := range []string{rbac.ActionCreate, rbac.ActionRead, rbac.ActionUpdate,
			rbac.ActionDelete, rbac.ActionList, rbac.ActionDownload} {
			if !e.Allow(role, rbac.ResourceLogProfile, action) {
				t.Fatalf("%s should be allowed log_profile.%s", role, action)
			}
		}
	}

	// Viewer: may open a saved view, may not export it.
	if !e.Allow(rbac.RoleViewer, rbac.ResourceLogProfile, rbac.ActionList) {
		t.Fatal("viewer should be able to list log profiles")
	}
	if e.Allow(rbac.RoleViewer, rbac.ResourceLogProfile, rbac.ActionDownload) {
		t.Fatal("viewer must NOT be able to export logs")
	}
	for _, action := range []string{rbac.ActionCreate, rbac.ActionUpdate, rbac.ActionDelete} {
		if e.Allow(rbac.RoleViewer, rbac.ResourceLogProfile, action) {
			t.Fatalf("viewer must NOT be allowed log_profile.%s", action)
		}
	}

	// Auditor: read-only, but download is in scope — same class of read as the
	// audit-log download they already hold.
	if !e.Allow(rbac.RoleAuditor, rbac.ResourceLogProfile, rbac.ActionDownload) {
		t.Fatal("auditor should be able to export logs")
	}
	if e.Allow(rbac.RoleAuditor, rbac.ResourceLogProfile, rbac.ActionCreate) {
		t.Fatal("auditor must NOT be able to create log profiles")
	}
}

func TestExportRowCap(t *testing.T) {
	if got := exportRowCap(); got != defaultMaxExportRows {
		t.Fatalf("default row cap = %d, want %d", got, defaultMaxExportRows)
	}
	t.Setenv("SENTINEL_EXPORT_MAX_ROWS", "5000")
	if got := exportRowCap(); got != 5000 {
		t.Fatalf("env override row cap = %d, want 5000", got)
	}
	// Nonsense values fall back to the default rather than disabling the cap.
	for _, bad := range []string{"0", "-1", "lots"} {
		t.Setenv("SENTINEL_EXPORT_MAX_ROWS", bad)
		if got := exportRowCap(); got != defaultMaxExportRows {
			t.Fatalf("row cap with %q = %d, want default %d", bad, got, defaultMaxExportRows)
		}
	}
}

func unixStr(n int64) string { return strconv.FormatInt(n, 10) }
