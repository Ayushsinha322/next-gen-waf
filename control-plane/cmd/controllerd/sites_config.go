package main

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	"github.com/your-org/sentinel-waf/control-plane/internal/cluster"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/logs"
	"github.com/your-org/sentinel-waf/control-plane/internal/rbac"
	"gopkg.in/yaml.v3"
)

// yamlSite is the operator-friendly representation of a protected site used for
// the Config-as-Code import/export feature. It mirrors what the dashboard
// stores so admins get a clean round-trip between the UI and a YAML file.
type yamlSite struct {
	Name      string                 `yaml:"name" json:"name"`
	Domains   []string               `yaml:"domains" json:"domains"`
	Status    string                 `yaml:"status,omitempty" json:"status,omitempty"`
	Upstream  map[string]interface{} `yaml:"upstream" json:"upstream"`
	WafPolicy map[string]interface{} `yaml:"waf_policy" json:"waf_policy"`
}

type yamlSiteDoc struct {
	Sites []yamlSite `yaml:"sites" json:"sites"`
}

// handleExportSites returns the full site catalogue for the tenant as a single
// YAML document so it can be version-controlled or edited by hand and
// re-imported. Equivalent to "sentinel.yaml" but generated from the live store.
func handleExportSites(c *gin.Context, enf *rbac.Enforcer, store *db.Store) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceSite, rbac.ActionList) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	sites, err := store.ListSites(c.Request.Context(), claims.TenantID, claims.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	doc := yamlSiteDoc{Sites: make([]yamlSite, 0, len(sites))}
	for _, s := range sites {
		var up map[string]interface{}
		_ = json.Unmarshal(s.Upstream, &up)
		var waf map[string]interface{}
		_ = json.Unmarshal(s.WafPolicy, &waf)
		doc.Sites = append(doc.Sites, yamlSite{
			Name:      s.Name,
			Domains:   s.Domains,
			Status:    s.Status,
			Upstream:  up,
			WafPolicy: waf,
		})
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Header("Content-Disposition", "attachment; filename=sentinel-sites.yaml")
	c.Data(http.StatusOK, "application/x-yaml; charset=utf-8", out)
}

// importSitesRequest accepts either a raw YAML string ({"yaml": "..."}) or a
// structured JSON body with the same shape as the export document.
type importSitesRequest struct {
	YAML  string     `json:"yaml"`
	Sites []yamlSite `json:"sites"`
}

// handleImportSites upserts sites from a YAML/JSON document. Existing sites are
// matched by name and updated; new names are created. This is the write-side of
// Config-as-Code, giving admins full parity between the UI and a config file.
func handleImportSites(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *cluster.Cluster) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceSite, rbac.ActionUpdate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}

	var req importSitesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var doc yamlSiteDoc
	if req.YAML != "" {
		if err := yaml.Unmarshal([]byte(req.YAML), &doc); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid YAML: " + err.Error()})
			return
		}
	} else {
		doc.Sites = req.Sites
	}
	if len(doc.Sites) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no sites found in document"})
		return
	}

	existing, err := store.ListSites(c.Request.Context(), claims.TenantID, claims.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	byName := make(map[string]db.SiteRow, len(existing))
	for _, s := range existing {
		byName[s.Name] = s
	}

	created, updated := 0, 0
	for _, ys := range doc.Sites {
		if ys.Name == "" {
			continue
		}
		upJSON, _ := json.Marshal(ys.Upstream)
		wafJSON, _ := json.Marshal(ys.WafPolicy)
		if len(ys.Upstream) == 0 {
			upJSON = json.RawMessage(`{"servers":[],"lb":"round_robin"}`)
		}
		if len(ys.WafPolicy) == 0 {
			wafJSON = json.RawMessage(`{"mode":"blocking","paranoia_level":2,"anomaly_threshold":5}`)
		}

		if cur, ok := byName[ys.Name]; ok {
			name := ys.Name
			ureq := db.UpdateSiteRequest{
				Name:      &name,
				Domains:   ys.Domains,
				Upstream:  upJSON,
				WafPolicy: wafJSON,
			}
			if !proposeBest(c, cl, cluster.CmdSiteUpdate, gin.H{"tenant_id": claims.TenantID, "site_id": cur.ID, "req": ureq}) {
				return
			}
			if _, err := store.UpdateSite(c.Request.Context(), claims.TenantID, claims.UserID, cur.ID, ureq); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "update " + ys.Name + ": " + err.Error()})
				return
			}
			updated++
		} else {
			creq := db.CreateSiteRequest{
				Name:      ys.Name,
				Domains:   ys.Domains,
				Upstream:  upJSON,
				WafPolicy: wafJSON,
			}
			if !proposeBest(c, cl, cluster.CmdSiteCreate, gin.H{"tenant_id": claims.TenantID, "req": creq}) {
				return
			}
			site, err := store.CreateSite(c.Request.Context(), claims.TenantID, claims.UserID, creq)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "create " + ys.Name + ": " + err.Error()})
				return
			}
			_ = site
			created++
		}
	}

	configVersion.Add(1)
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &claims.UserID,
		Action:      "site.import",
		TargetKind:  "site",
	})
	c.JSON(http.StatusOK, gin.H{"ok": true, "created": created, "updated": updated, "total": created + updated})
}
