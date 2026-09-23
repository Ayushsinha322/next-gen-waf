package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	chreader "github.com/your-org/sentinel-waf/control-plane/internal/clickhouse"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/leader"
	"github.com/your-org/sentinel-waf/control-plane/internal/logs"
	"github.com/your-org/sentinel-waf/control-plane/internal/rbac"
	"github.com/your-org/sentinel-waf/control-plane/internal/reports"
)

// ---------------------------------------------------------------------------
// Scheduled reports.
//
//   GET    /api/v1/reports/schedules              list
//   POST   /api/v1/reports/schedules              create
//   PUT    /api/v1/reports/schedules/:id          update
//   DELETE /api/v1/reports/schedules/:id          delete
//   POST   /api/v1/reports/schedules/:id/run      build for the last period and deliver now
//   GET    /api/v1/reports/preview?site=&days=&format=html|csv|json   build now, download
//
// The deck claimed scheduled reports in August 2026 and nothing produced one.
// Everything a report needs was already in ClickHouse; this is the missing
// schedule + render + deliver.
// ---------------------------------------------------------------------------

type reportScheduleBody struct {
	Name       string   `json:"name"`
	Site       string   `json:"site"`
	Cadence    string   `json:"cadence"`
	DayOfWeek  *int     `json:"day_of_week"`
	HourUTC    *int     `json:"hour_utc"`
	Format     string   `json:"format"`
	ChannelID  *string  `json:"channel_id"`
	Recipients []string `json:"recipients"`
	Enabled    *bool    `json:"enabled"`
}

func (b reportScheduleBody) toInput(c *gin.Context, store *db.Store, claims *auth.Claims) (db.ReportScheduleInput, []string) {
	var problems []string
	in := db.ReportScheduleInput{
		Name: strings.TrimSpace(b.Name), Site: strings.TrimSpace(b.Site), Cadence: strings.ToLower(strings.TrimSpace(b.Cadence)),
		Format: strings.ToLower(strings.TrimSpace(b.Format)), DayOfWeek: 1, HourUTC: 6, Enabled: true, Recipients: []string{},
	}
	if in.Name == "" || len(in.Name) > 120 {
		problems = append(problems, "name is required (max 120 chars)")
	}
	if in.Cadence == "" {
		in.Cadence = "weekly"
	}
	if in.Cadence != "daily" && in.Cadence != "weekly" {
		problems = append(problems, "cadence must be daily or weekly")
	}
	if in.Format == "" {
		in.Format = "html"
	}
	if in.Format != "html" && in.Format != "csv" {
		problems = append(problems, "format must be html or csv")
	}
	if b.DayOfWeek != nil {
		in.DayOfWeek = *b.DayOfWeek
	}
	if in.DayOfWeek < 0 || in.DayOfWeek > 6 {
		problems = append(problems, "day_of_week must be 0 (Sunday) to 6 (Saturday)")
	}
	if b.HourUTC != nil {
		in.HourUTC = *b.HourUTC
	}
	if in.HourUTC < 0 || in.HourUTC > 23 {
		problems = append(problems, "hour_utc must be 0 to 23")
	}
	if b.Enabled != nil {
		in.Enabled = *b.Enabled
	}
	if b.ChannelID != nil && strings.TrimSpace(*b.ChannelID) != "" {
		id := strings.TrimSpace(*b.ChannelID)
		if store != nil {
			row, err := store.GetChannel(c.Request.Context(), claims.TenantID, claims.UserID, id)
			switch {
			case err != nil:
				problems = append(problems, "channel_id does not name a notification channel of this tenant")
			case row.Type != "webhook" && row.Type != "slack":
				problems = append(problems, fmt.Sprintf("channel %q is a %s sink; reports can be delivered to webhook or slack channels", row.Name, row.Type))
			}
		}
		in.ChannelID = &id
	}
	for _, r := range b.Recipients {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if a, err := mail.ParseAddress(r); err != nil || a.Address != r {
			problems = append(problems, fmt.Sprintf("recipient %q is not a plain e-mail address", r))
			continue
		}
		in.Recipients = append(in.Recipients, r)
	}
	if len(in.Recipients) > 20 {
		problems = append(problems, "at most 20 recipients")
	}
	if in.Site != "" && store != nil {
		sites, err := store.ListSites(c.Request.Context(), claims.TenantID, claims.UserID)
		if err == nil {
			found := false
			for _, s := range sites {
				if s.Name == in.Site {
					found = true
					break
				}
			}
			if !found {
				problems = append(problems, fmt.Sprintf("site %q is not a site of this tenant (use the site NAME, or empty for all sites)", in.Site))
			}
		}
	}
	if in.Enabled && in.ChannelID == nil && len(in.Recipients) == 0 {
		problems = append(problems, "an enabled schedule needs a delivery target: a webhook/slack channel or at least one recipient")
	}
	return in, problems
}

func handleListReportSchedules(c *gin.Context, enf *rbac.Enforcer, store *db.Store, mailConfigured bool) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceReport, rbac.ActionList) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	rows, err := store.ListReportSchedules(c.Request.Context(), claims.TenantID, claims.UserID)
	if err != nil {
		respondStoreError(c, err)
		return
	}
	now := time.Now().UTC()
	type withNext struct {
		db.ReportScheduleRow
		NextRunAt time.Time `json:"next_run_at"`
		Due       bool      `json:"due"`
	}
	out := make([]withNext, 0, len(rows))
	for _, r := range rows {
		last := reports.ScheduledAt(r, now)
		next := last.AddDate(0, 0, 1)
		if r.Cadence == "weekly" {
			next = last.AddDate(0, 0, 7)
		}
		out = append(out, withNext{ReportScheduleRow: r, NextRunAt: next, Due: reports.IsDue(r, now)})
	}
	c.JSON(http.StatusOK, gin.H{
		"schedules":       out,
		"mail_configured": mailConfigured,
		"formats":         []string{"html", "csv"},
		"note":            "PDF is not offered: the HTML report prints to PDF from any browser. E-mail delivery needs SMTP (Settings → Notifications).",
	})
}

func handleCreateReportSchedule(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *leader.Elector) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceReport, rbac.ActionCreate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	if !requireLeader(c, cl) {
		return
	}
	var body reportScheduleBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}
	in, problems := body.toInput(c, store, claims)
	if len(problems) > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid schedule", "problems": problems})
		return
	}
	row, err := store.CreateReportSchedule(c.Request.Context(), claims.TenantID, claims.UserID, in)
	if err != nil {
		respondStoreError(c, err)
		return
	}
	auditReport(c, store, hub, claims, "report.schedule.create", row)
	c.JSON(http.StatusCreated, gin.H{"schedule": row})
}

func handleUpdateReportSchedule(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *leader.Elector) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceReport, rbac.ActionUpdate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	if !requireLeader(c, cl) {
		return
	}
	var body reportScheduleBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}
	in, problems := body.toInput(c, store, claims)
	if len(problems) > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid schedule", "problems": problems})
		return
	}
	row, err := store.UpdateReportSchedule(c.Request.Context(), claims.TenantID, claims.UserID, c.Param("id"), in)
	if err != nil {
		respondStoreError(c, err)
		return
	}
	auditReport(c, store, hub, claims, "report.schedule.update", row)
	c.JSON(http.StatusOK, gin.H{"schedule": row})
}

func handleDeleteReportSchedule(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *leader.Elector) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceReport, rbac.ActionDelete) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	if !requireLeader(c, cl) {
		return
	}
	row, err := store.GetReportSchedule(c.Request.Context(), claims.TenantID, claims.UserID, c.Param("id"))
	if err != nil {
		respondStoreError(c, err)
		return
	}
	if err := store.DeleteReportSchedule(c.Request.Context(), claims.TenantID, claims.UserID, row.ID); err != nil {
		respondStoreError(c, err)
		return
	}
	auditReport(c, store, hub, claims, "report.schedule.delete", row)
	c.JSON(http.StatusOK, gin.H{"deleted": row.ID})
}

// handleRunReportSchedule builds the report for the most recent period and
// delivers it now — the "does it actually arrive" button.
func handleRunReportSchedule(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *leader.Elector, deliverer *reports.Deliverer) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceReport, rbac.ActionUpdate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil || deliverer == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "report delivery runs on the cluster leader; this node has no deliverer"})
		return
	}
	if !requireLeader(c, cl) {
		return
	}
	row, err := store.GetReportSchedule(c.Request.Context(), claims.TenantID, claims.UserID, c.Param("id"))
	if err != nil {
		respondStoreError(c, err)
		return
	}
	results, runErr := deliverer.Run(c.Request.Context(), *row, reports.ScheduledAt(*row, time.Now().UTC()))
	auditReport(c, store, hub, claims, "report.schedule.run", row)
	resp := gin.H{"ok": runErr == nil, "results": results}
	if runErr != nil {
		resp["error"] = runErr.Error()
	}
	c.JSON(http.StatusOK, resp)
}

// handlePreviewReport builds a report on demand and returns it for download.
func handlePreviewReport(c *gin.Context, enf *rbac.Enforcer, ch *chreader.Client) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceReport, rbac.ActionDownload) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	days, _ := strconv.Atoi(c.DefaultQuery("days", "7"))
	if days < 1 || days > 90 {
		days = 7
	}
	site := strings.TrimSpace(c.Query("site"))
	to := time.Now().UTC()
	from := to.AddDate(0, 0, -days)
	rep, err := reports.Build(c.Request.Context(), ch, claims.TenantID, site, from, to)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": clientError(err)})
		return
	}
	name := "waf-report-" + to.Format("2006-01-02")
	if site != "" {
		name += "-" + strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.' {
				return r
			}
			return '_'
		}, site)
	}
	switch strings.ToLower(c.DefaultQuery("format", "html")) {
	case "csv":
		c.Header("Content-Disposition", `attachment; filename="`+name+`.csv"`)
		c.Data(http.StatusOK, "text/csv; charset=utf-8", rep.CSV())
	case "json":
		c.JSON(http.StatusOK, rep)
	default:
		if c.Query("download") == "1" {
			c.Header("Content-Disposition", `attachment; filename="`+name+`.html"`)
		}
		c.Data(http.StatusOK, "text/html; charset=utf-8", rep.HTML())
	}
}

func auditReport(c *gin.Context, store *db.Store, hub *logs.Hub, claims *auth.Claims, action string, row *db.ReportScheduleRow) {
	diff, _ := json.Marshal(gin.H{"name": row.Name, "site": row.Site, "cadence": row.Cadence, "format": row.Format,
		"channel_id": row.ChannelID, "recipients": len(row.Recipients), "enabled": row.Enabled})
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID: claims.TenantID, ActorUserID: &claims.UserID, Action: action,
		TargetKind: "report_schedule", TargetID: &row.ID, Diff: diff,
	})
}
