package main

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/leader"
	"github.com/your-org/sentinel-waf/control-plane/internal/logs"
	"github.com/your-org/sentinel-waf/control-plane/internal/rbac"
	"github.com/your-org/sentinel-waf/control-plane/internal/settings"
)

// ---------------------------------------------------------------------------
// Global settings — node-wide values, edited from the console.
//
//   GET    /api/v1/settings/global          every editable key with its effective
//                                           value and source, plus the data
//                                           plane's read-only global config
//   PUT    /api/v1/settings/global          {"values": {key: value, ...}}
//   DELETE /api/v1/settings/global/:key     drop the operator override
//
// Before this, none of these could be changed from the console: alert
// thresholds and threat-intel feeds lived only in the control plane's .env
// (edit, recreate the container, no audit row), and the data plane's
// listeners, TLS floor, logging and limits were visible nowhere at all.
// ---------------------------------------------------------------------------

var dataPlaneSettingsClient = &http.Client{Timeout: 6 * time.Second}

func settingsOverrides(rows map[string]db.SettingRow) map[string]settings.Override {
	out := make(map[string]settings.Override, len(rows))
	for k, r := range rows {
		out[k] = settings.Override{Value: r.Value, UpdatedAt: r.UpdatedAt, UpdatedBy: r.UpdatedBy}
	}
	return out
}

func handleGetGlobalSettings(c *gin.Context, enf *rbac.Enforcer, store *db.Store) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceSettings, rbac.ActionRead) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	var rows map[string]db.SettingRow
	dbAvailable := store != nil
	if store != nil {
		var err error
		rows, err = store.ListSettings(c.Request.Context(), claims.TenantID, claims.UserID)
		if err != nil {
			// Still answer: env/default resolution is useful without the DB, but
			// say plainly that overrides could not be read.
			dbAvailable = false
		}
	}
	resp := gin.H{
		"editable":     settings.Resolve(settingsOverrides(rows)),
		"groups":       settings.Groups(),
		"db_available": dbAvailable,
	}

	// The data plane's own global config, read-only. It is the node's YAML —
	// listeners, TLS, logging, storage, eBPF, limits — and changing it means
	// editing that file and restarting the node. Showing it here is the point:
	// the console used to have no page where these values existed at all.
	req, _ := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, dataPlaneBaseURL()+"/api/v1/internal/settings", nil)
	setInternalAuth(req)
	if r, err := dataPlaneSettingsClient.Do(req); err == nil {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		r.Body.Close()
		var dp map[string]any
		if r.StatusCode == http.StatusOK && json.Unmarshal(body, &dp) == nil {
			// The config above is the node's FILE. Several controls are switched on
			// by environment variable at run time instead, so the file alone
			// misreports them: the console showed "eBPF / XDP: off" on a node
			// reporting mode kernel-xdp with 11 million packets passed, because
			// SENTINEL_XDP_ENABLE=1 never appears in the YAML. Carry the runtime
			// view alongside it so the page can show effective state and say which
			// source it came from.
			resp["dataplane"] = gin.H{
				"reachable": true,
				"config":    dp,
				"runtime":   dataPlaneRuntime(c),
			}
		} else {
			resp["dataplane"] = gin.H{"reachable": false, "error": "data plane returned " + r.Status}
		}
	} else {
		resp["dataplane"] = gin.H{"reachable": false, "error": err.Error()}
	}
	c.JSON(http.StatusOK, resp)
}

// dataPlaneRuntime returns the parts of the data plane's /healthz that describe
// what is actually running, as opposed to what its config file asks for. Returns
// nil when the node cannot be reached; the caller renders that as "unknown"
// rather than as "off", which is the whole point of the distinction.
func dataPlaneRuntime(c *gin.Context) map[string]any {
	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodGet,
		dataPlaneBaseURL()+"/healthz", nil)
	if err != nil {
		return nil
	}
	r, err := (&http.Client{Timeout: 4 * time.Second}).Do(req)
	if err != nil {
		return nil
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil
	}
	var h map[string]any
	if json.Unmarshal(body, &h) != nil {
		return nil
	}
	out := map[string]any{}
	// Only the blocks the page needs. Copying the whole document here would put
	// the node's site list and counters behind a settings call, which is not what
	// this endpoint is for.
	for _, k := range []string{"ebpf", "http3", "geoip", "threat_intel", "version"} {
		if v, ok := h[k]; ok {
			out[k] = v
		}
	}
	return out
}

type putGlobalSettingsRequest struct {
	Values map[string]json.RawMessage `json:"values"`
}

func handlePutGlobalSettings(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *leader.Elector) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceSettings, rbac.ActionUpdate) {
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
	var req putGlobalSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil || len(req.Values) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "body must be {\"values\": {key: value}} with at least one key"})
		return
	}
	// Validate everything before writing anything: a bad key in a batch must
	// not leave half the batch applied.
	normalised := make(map[string]json.RawMessage, len(req.Values))
	for name, raw := range req.Values {
		k, ok := settings.Lookup(name)
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "unknown setting: " + name})
			return
		}
		v, err := settings.Coerce(k, raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": clientError(err)})
			return
		}
		b, _ := json.Marshal(v)
		normalised[name] = b
	}

	before, _ := store.ListSettings(c.Request.Context(), claims.TenantID, claims.UserID)
	if err := store.PutSettings(c.Request.Context(), claims.TenantID, claims.UserID, normalised); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
		return
	}
	after, _ := store.ListSettings(c.Request.Context(), claims.TenantID, claims.UserID)

	keys := make([]string, 0, len(normalised))
	for k := range normalised {
		keys = append(keys, k)
	}
	diff, _ := json.Marshal(map[string]any{
		"keys":   keys,
		"before": pickSettings(before, keys),
		"after":  pickSettings(after, keys),
	})
	// audit_logs.target_id is a UUID column; settings are keyed by name, so the
	// keys travel in the diff and target_id stays null.
	actor := claims.UserID
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &actor,
		Action:      "settings.global.update",
		TargetKind:  "settings",
		Diff:        diff,
	})
	c.JSON(http.StatusOK, gin.H{
		"editable": settings.Resolve(settingsOverrides(after)),
		"applied":  "live — subsystems pick the change up within a minute",
	})
}

func handleDeleteGlobalSetting(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *leader.Elector) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceSettings, rbac.ActionUpdate) {
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
	key := c.Param("key")
	if _, ok := settings.Lookup(key); !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown setting: " + key})
		return
	}
	if err := store.DeleteSetting(c.Request.Context(), claims.TenantID, claims.UserID, key); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
		return
	}
	actor := claims.UserID
	resetDiff, _ := json.Marshal(map[string]any{"keys": []string{key}, "reset_to": "env or default"})
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &actor,
		Action:      "settings.global.reset",
		TargetKind:  "settings",
		Diff:        resetDiff,
	})
	rows, _ := store.ListSettings(c.Request.Context(), claims.TenantID, claims.UserID)
	c.JSON(http.StatusOK, gin.H{"editable": settings.Resolve(settingsOverrides(rows))})
}

func pickSettings(rows map[string]db.SettingRow, keys []string) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	for _, k := range keys {
		if r, ok := rows[k]; ok {
			out[k] = r.Value
		}
	}
	return out
}
