package main

// Log profiles — named, saved log views scoped to one web application, plus the
// export that turns a view into a file an operator can hand to a customer.
//
// The workflow this serves: a customer calls, says "send me the WAF logs for my
// app for 3 August", and the operator opens that application's profile, sets the
// date, and downloads. Everything here exists to make that path fast, repeatable
// between operators, and accountable after the fact.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	"github.com/your-org/sentinel-waf/control-plane/internal/clickhouse"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/logs"
	"github.com/your-org/sentinel-waf/control-plane/internal/rbac"
)

// maxExportWindow bounds a single export request. A year covers any realistic
// customer or regulator ask; beyond it the request is far more likely to be a
// mistyped date than an intent to pull a decade of traffic.
const maxExportWindow = 366 * 24 * time.Hour

// defaultMaxExportRows caps rows in one export. Override with
// SENTINEL_EXPORT_MAX_ROWS. See exportRowCap for why the cap refuses rather
// than truncates.
const defaultMaxExportRows = 1_000_000

func exportRowCap() int64 {
	if v := strings.TrimSpace(os.Getenv("SENTINEL_EXPORT_MAX_ROWS")); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return defaultMaxExportRows
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

func handleListLogProfiles(c *gin.Context, enf *rbac.Enforcer, store *db.Store) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceLogProfile, rbac.ActionList) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusOK, gin.H{"profiles": []any{}})
		return
	}
	profiles, err := store.ListLogProfiles(c.Request.Context(), claims.TenantID, claims.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
		return
	}
	if profiles == nil {
		profiles = []db.LogProfileRow{}
	}
	c.JSON(http.StatusOK, gin.H{"profiles": profiles})
}

func handleCreateLogProfile(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceLogProfile, rbac.ActionCreate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	var req db.LogProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if err := validateProfileRequest(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": clientError(err)})
		return
	}
	p, err := store.CreateLogProfile(c.Request.Context(), claims.TenantID, claims.UserID, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
		return
	}
	auditLogProfile(c, store, hub, claims, "log_profile.create", p.ID, nil)
	c.JSON(http.StatusOK, gin.H{"profile": p})
}

func handleUpdateLogProfile(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceLogProfile, rbac.ActionUpdate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	var req db.LogProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if err := validateProfileRequest(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": clientError(err)})
		return
	}
	id := c.Param("id")
	p, err := store.UpdateLogProfile(c.Request.Context(), claims.TenantID, claims.UserID, id, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
		return
	}
	auditLogProfile(c, store, hub, claims, "log_profile.update", p.ID, nil)
	c.JSON(http.StatusOK, gin.H{"profile": p})
}

func handleDeleteLogProfile(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceLogProfile, rbac.ActionDelete) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	id := c.Param("id")
	if err := store.DeleteLogProfile(c.Request.Context(), claims.TenantID, claims.UserID, id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
		return
	}
	auditLogProfile(c, store, hub, claims, "log_profile.delete", id, nil)
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// validateProfileRequest rejects values the DB CHECK constraints would reject
// anyway, so the operator gets a readable message instead of a driver error.
func validateProfileRequest(req *db.LogProfileRequest) error {
	if req.DefaultFormat != nil && *req.DefaultFormat != "" {
		if _, ok := clickhouse.LookupExportFormat(*req.DefaultFormat); !ok {
			return fmt.Errorf("default_format must be one of csv, ndjson, json")
		}
	}
	if req.DefaultRangeSecs != nil {
		if *req.DefaultRangeSecs <= 0 || *req.DefaultRangeSecs > 31536000 {
			return fmt.Errorf("default_range_secs must be between 1 and 31536000")
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

// handleExportLogProfile exports a saved profile's view over an explicit time
// range: GET /logs/profiles/:id/export?from=&to=&format=
//
// The profile supplies WHICH events; the query string supplies WHEN. That split
// is the whole point — the customer's filters are saved once, and the date
// changes on every call.
func handleExportLogProfile(c *gin.Context, enf *rbac.Enforcer, store *db.Store, ch *clickhouse.Client, hub *logs.Hub) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceLogProfile, rbac.ActionDownload) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	id := c.Param("id")
	p, err := store.GetLogProfile(c.Request.Context(), claims.TenantID, claims.UserID, id)
	if err != nil {
		// A database outage must not be reported as "no such profile" — the
		// operator would go looking for a deleted saved view instead of an
		// incident.
		if errors.Is(err, db.ErrLogProfileNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "log profile not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
		}
		return
	}
	f := clickhouse.SearchFilter{
		Tenant:   claims.TenantID, // isolation boundary — never from client input
		Site:     p.Site,
		Country:  p.Country,
		Rule:     p.Rule,
		Action:   p.Action,
		IP:       p.IP,
		Protocol: p.Protocol,
		Severity: p.Severity,
		Query:    p.Q,
	}
	format := p.DefaultFormat
	if q := c.Query("format"); q != "" {
		format = q
	}
	runExport(c, store, ch, hub, claims, f, format, p.Site,
		time.Duration(p.DefaultRangeSecs)*time.Second, p.Name, &p.ID)
}

// handleExportEvents exports an ad-hoc Threat Search view — the same file, for
// the case where the operator has not saved (or does not want) a profile.
func handleExportEvents(c *gin.Context, enf *rbac.Enforcer, store *db.Store, ch *clickhouse.Client, hub *logs.Hub) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceLogProfile, rbac.ActionDownload) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	f := clickhouse.SearchFilter{
		Tenant:   claims.TenantID, // isolation boundary — never from client input
		Site:     c.Query("site"),
		Country:  c.Query("country"),
		Rule:     c.Query("rule"),
		Action:   c.Query("action"),
		IP:       c.Query("ip"),
		Protocol: c.Query("protocol"),
		Severity: c.Query("severity"),
		Query:    c.Query("q"),
	}
	runExport(c, store, ch, hub, claims, f, c.Query("format"), f.Site,
		24*time.Hour, "", nil)
}

// runExport is the shared body of both export endpoints.
//
// Order of operations matters and is deliberate:
//  1. resolve and validate the window,
//  2. count the matches,
//  3. refuse if the result would be truncated,
//  4. write the audit entry — the data access is authorized and about to happen,
//  5. only then start streaming.
//
// Auditing before the stream means a transfer that dies halfway is still on the
// record. Auditing after would leave the most interesting failure invisible.
func runExport(c *gin.Context, store *db.Store, ch *clickhouse.Client, hub *logs.Hub,
	claims *auth.Claims, f clickhouse.SearchFilter, formatName, site string,
	defaultWindow time.Duration, profileName string, profileID *string) {

	if ch == nil || !ch.Enabled() {
		// Never answer with an empty file: a 0-byte CSV looks like "no attacks
		// on your app that day" when it actually means "we have no event store".
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "event store not configured — cannot export logs (set SENTINEL_CLICKHOUSE_URL)"})
		return
	}
	format, ok := clickhouse.LookupExportFormat(formatName)
	if !ok {
		if formatName == "" {
			format, _ = clickhouse.LookupExportFormat("csv")
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "format must be one of csv, ndjson, json"})
			return
		}
	}

	from, to, err := resolveExportWindow(c.Query("from"), c.Query("to"), defaultWindow, time.Now())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": clientError(err)})
		return
	}
	f.From, f.To = from.Unix(), to.Unix()

	rows, err := ch.ExportCount(c.Request.Context(), f)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": clientError(err)})
		return
	}
	if maxRows := exportRowCap(); rows > maxRows {
		// Refuse rather than truncate — see clickhouse.ExportCount. The operator
		// gets the real number and the levers to narrow it.
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{
			"error": fmt.Sprintf(
				"export would contain %d events, above the %d-row limit — narrow the date range or add a filter",
				rows, maxRows),
			"rows":     rows,
			"max_rows": maxRows,
		})
		return
	}

	body, err := ch.ExportStream(c.Request.Context(), f, format)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": clientError(err)})
		return
	}
	defer body.Close()

	filename := exportFilename(site, from, to, format.Ext)
	auditExport(c, store, hub, claims, profileID, map[string]any{
		"profile":  profileName,
		"site":     site,
		"from":     from.UTC().Format(time.RFC3339),
		"to":       to.UTC().Format(time.RFC3339),
		"format":   format.Name,
		"rows":     rows,
		"filename": filename,
	})

	c.Header("Content-Type", format.MediaType)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	// Row count as a header so the UI can tell the operator what they just
	// handed over without parsing the file.
	c.Header("X-Sentinel-Export-Rows", strconv.FormatInt(rows, 10))
	c.Header("X-Content-Type-Options", "nosniff")
	c.Status(http.StatusOK)

	if _, err := io.Copy(c.Writer, body); err != nil {
		// Headers are already on the wire, so this cannot become an error
		// response. Log it; the audit entry above records that the export began.
		fmt.Fprintf(os.Stderr, "[sentinel] log export %s aborted mid-stream: %v\n", filename, err)
	}
}

// resolveExportWindow turns the from/to query parameters into a validated
// [from, to) window. Both are unix seconds; when both are absent the window is
// the profile's default ending now, which is what makes "just open it and hit
// download" work for the common "what happened today" ask.
func resolveExportWindow(fromQ, toQ string, defaultWindow time.Duration, now time.Time) (time.Time, time.Time, error) {
	if defaultWindow <= 0 {
		defaultWindow = 24 * time.Hour
	}
	parse := func(s string) (int64, bool) {
		n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		if err != nil || n <= 0 {
			return 0, false
		}
		return n, true
	}
	toSec, hasTo := parse(toQ)
	fromSec, hasFrom := parse(fromQ)

	to := now
	if hasTo {
		to = time.Unix(toSec, 0)
	}
	from := to.Add(-defaultWindow)
	if hasFrom {
		from = time.Unix(fromSec, 0)
	}
	if !to.After(from) {
		return time.Time{}, time.Time{}, fmt.Errorf("'to' must be after 'from'")
	}
	if to.Sub(from) > maxExportWindow {
		return time.Time{}, time.Time{}, fmt.Errorf(
			"date range spans %d days, above the %d-day maximum for one export",
			int(to.Sub(from).Hours()/24), int(maxExportWindow.Hours()/24))
	}
	return from, to, nil
}

// exportFilename builds the name the customer receives. It states the
// application and the exact window, because the single most common support
// failure with exported logs is nobody being able to tell, a week later, what
// period a file actually covered.
func exportFilename(site string, from, to time.Time, ext string) string {
	name := sanitizeFilenamePart(site)
	if name == "" {
		name = "all-sites"
	}
	return fmt.Sprintf("%s_%s_to_%s_waf-events.%s",
		name,
		from.UTC().Format("20060102-1504"),
		to.UTC().Format("20060102-1504"),
		ext)
}

// sanitizeFilenamePart reduces a site name to characters that are safe in a
// filename and in a Content-Disposition header — notably dropping quotes,
// backslashes, path separators and CR/LF, which are the header-injection and
// path-traversal vectors on this path.
func sanitizeFilenamePart(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			// Everything else collapses to '-' rather than being dropped, so two
			// different sites cannot sanitize to the same filename.
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-.")
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

func auditLogProfile(c *gin.Context, store *db.Store, hub *logs.Hub, claims *auth.Claims,
	action, id string, detail map[string]any) {
	var diff json.RawMessage
	if detail != nil {
		diff, _ = json.Marshal(detail)
	}
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &claims.UserID,
		Action:      action,
		TargetKind:  "log_profile",
		TargetID:    &id,
		Diff:        diff,
	})
}

// auditExport records a bulk read of customer traffic data. This is the entry
// that answers "who sent this customer their logs, when, and for what window" —
// the question that gets asked after a disclosure dispute, so the parameters go
// in the record, not just the fact that an export happened.
func auditExport(c *gin.Context, store *db.Store, hub *logs.Hub, claims *auth.Claims,
	profileID *string, detail map[string]any) {
	diff, _ := json.Marshal(detail)
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &claims.UserID,
		Action:      "log_profile.export",
		TargetKind:  "log_export",
		TargetID:    profileID,
		Diff:        diff,
	})
}
