package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/leader"
	"github.com/your-org/sentinel-waf/control-plane/internal/logs"
	"github.com/your-org/sentinel-waf/control-plane/internal/rbac"
	"go.uber.org/zap"
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
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
func handleImportSites(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, cl *leader.Elector) {
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
		c.JSON(http.StatusBadRequest, gin.H{"error": clientError(err)})
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

	// The document's own policy values first, before the store is read: a bad
	// document is refused without touching the database.
	var problems []SiteConfigProblem
	for _, ys := range doc.Sites {
		if ys.Name == "" || len(ys.WafPolicy) == 0 {
			continue
		}
		wafJSON, _ := json.Marshal(ys.WafPolicy)
		for _, p := range validateWafPolicyValues(wafJSON) {
			p.Field = fmt.Sprintf("sites[%s].%s", ys.Name, p.Field)
			problems = append(problems, p)
		}
	}
	if len(problems) > 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":    fmt.Sprintf("nothing was imported — %s", importProblemSummary(problems)),
			"problems": problems,
		})
		return
	}

	existing, err := store.ListSites(c.Request.Context(), claims.TenantID, claims.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": clientError(err)})
		return
	}
	sites, problems := planImport(doc.Sites, existing)
	for _, is := range sites {
		for _, p := range validateSitePluginNames(c, store, claims.TenantID, claims.UserID, is.wafJSON) {
			p.Field = fmt.Sprintf("sites[%s].%s", is.Name, p.Field)
			problems = append(problems, p)
		}
	}

	// An import creates and updates sites, so every site gets the checks create
	// and update apply — the whole site, plugin names, and domains no other site
	// claims. It used to run only the policy-value check, so a document could
	// store an origin or domain the console refuses. Every site is checked before
	// any is written: a refused document changes nothing.
	//
	// An existing site is MERGED, not replaced: keys the document gives replace
	// the stored ones, keys it leaves out keep their stored values. Replacing it
	// wholesale turned a document naming only `waf_policy: {mode: blocking}` —
	// the import box's own example — into a site with no exclusions, overrides,
	// TLS or rate limits, and one with no upstream into a site with no servers.
	if len(problems) > 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":    fmt.Sprintf("nothing was imported — %s", importProblemSummary(problems)),
			"problems": problems,
		})
		return
	}
	if !requireLeader(c, cl) {
		return
	}

	// A rollback point for the whole import, taken before the first write: the
	// sites are written one by one, so a failure part-way is undone from Config
	// History rather than left half-applied.
	snapshotBeforeMutation(c, store, zap.L(), "site.import")

	created, updated := 0, 0
	for _, is := range sites {
		ys := is.yamlSite
		var siteID, op string
		if is.cur != nil {
			name := ys.Name
			ureq := db.UpdateSiteRequest{Name: &name, Domains: is.domains, Upstream: is.upJSON, WafPolicy: is.wafJSON}
			if _, err := store.UpdateSite(c.Request.Context(), claims.TenantID, claims.UserID, is.cur.ID, ureq); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": fmt.Sprintf("update %s: %s — %d created and %d updated before it; restore the site.import point in Config History to undo them", ys.Name, clientError(err), created, updated),
				})
				return
			}
			siteID, op = is.cur.ID, "update"
			updated++
		} else {
			creq := db.CreateSiteRequest{Name: ys.Name, Domains: is.domains, Upstream: is.upJSON, WafPolicy: is.wafJSON}
			site, err := store.CreateSite(c.Request.Context(), claims.TenantID, claims.UserID, creq)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": fmt.Sprintf("create %s: %s — %d created and %d updated before it; restore the site.import point in Config History to undo them", ys.Name, clientError(err), created, updated),
				})
				return
			}
			siteID, op = site.ID, "create"
			created++
		}
		// One audit row per site, naming what the document set: an import
		// used to leave a single row with no site and no change.
		id := siteID
		writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
			TenantID:    claims.TenantID,
			ActorUserID: &claims.UserID,
			Action:      "site.import",
			TargetKind:  "site",
			TargetID:    &id,
			Diff:        importAuditDiff(op, ys),
		})
	}

	configVersion.Add(1)
	c.JSON(http.StatusOK, gin.H{"ok": true, "created": created, "updated": updated, "total": created + updated})
}

// importSite is one document site resolved against the catalogue: merged onto
// the stored site when the name exists, defaulted when it is new.
type importSite struct {
	yamlSite
	cur             *db.SiteRow
	domains         []string
	upJSON, wafJSON json.RawMessage
}

// planImport resolves and checks every document site against the existing
// catalogue without writing anything (plugin names are checked by the caller,
// which needs the store). See handleImportSites for why sites are merged.
func planImport(docSites []yamlSite, existing []db.SiteRow) ([]importSite, []SiteConfigProblem) {
	byName := make(map[string]db.SiteRow, len(existing))
	for _, s := range existing {
		byName[s.Name] = s
	}
	var sites []importSite
	var problems []SiteConfigProblem
	claimed := map[string]string{} // domain → the site in this document that claims it
	for _, ys := range docSites {
		if ys.Name == "" {
			continue
		}
		is := importSite{yamlSite: ys, domains: ys.Domains}
		if cur, ok := byName[ys.Name]; ok {
			is.cur = &cur
			if ys.Domains == nil {
				is.domains = cur.Domains
			}
			is.upJSON = mergeTopLevel(cur.Upstream, ys.Upstream)
			is.wafJSON = mergeTopLevel(cur.WafPolicy, ys.WafPolicy)
		} else {
			is.upJSON, _ = json.Marshal(ys.Upstream)
			if len(ys.Upstream) == 0 {
				is.upJSON = json.RawMessage(`{"servers":[],"lb":"round_robin"}`)
			}
			is.wafJSON, _ = json.Marshal(ys.WafPolicy)
			if len(ys.WafPolicy) == 0 {
				is.wafJSON = json.RawMessage(defaultWafPolicyJSON)
			}
		}
		add := func(ps []SiteConfigProblem) {
			for _, p := range ps {
				p.Field = fmt.Sprintf("sites[%s].%s", ys.Name, p.Field)
				problems = append(problems, p)
			}
		}
		add(validateSiteConfig(ys.Name, is.domains, is.upJSON, is.wafJSON))
		exclude := ""
		if is.cur != nil {
			exclude = is.cur.ID
		}
		add(domainConflicts(existing, is.domains, exclude))
		for _, d := range is.domains {
			key := strings.ToLower(strings.TrimSpace(d))
			if other, dup := claimed[key]; dup && other != ys.Name {
				add([]SiteConfigProblem{{Field: "domains", Problem: fmt.Sprintf("%q is also claimed by %q in this document", d, other)}})
			}
			claimed[key] = ys.Name
		}
		sites = append(sites, is)
	}
	return sites, problems
}

// mergeTopLevel lays the document's keys over the stored object: keys present
// replace, keys absent keep the stored value. An absent or empty document
// object keeps the stored one as it is.
func mergeTopLevel(stored json.RawMessage, doc map[string]interface{}) json.RawMessage {
	if len(doc) == 0 {
		return stored
	}
	merged := map[string]interface{}{}
	if len(stored) > 0 {
		_ = json.Unmarshal(stored, &merged)
	}
	for k, v := range doc {
		merged[k] = v
	}
	out, err := json.Marshal(merged)
	if err != nil {
		return stored
	}
	return out
}

// importAuditDiff records which top-level keys an import set on a site.
func importAuditDiff(op string, ys yamlSite) json.RawMessage {
	keys := func(m map[string]interface{}) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	b, _ := json.Marshal(map[string]interface{}{
		"op":         op,
		"name":       ys.Name,
		"domains":    ys.Domains,
		"upstream":   keys(ys.Upstream),
		"waf_policy": keys(ys.WafPolicy),
	})
	return b
}

// importProblemSummary names the first problem and counts the rest, for the
// one-line error the console shows.
func importProblemSummary(problems []SiteConfigProblem) string {
	first := problems[0].String()
	if n := len(problems) - 1; n > 0 {
		return fmt.Sprintf("%s (and %d more)", first, n)
	}
	return first
}
