package main

import (
	"embed"
	"encoding/json"
	"net/http"
	"path"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/rbac"
	"github.com/your-org/sentinel-waf/control-plane/internal/version"
)

// ---------------------------------------------------------------------------
// Bundled plugin catalogue.
//
//   GET  /api/v1/plugins/catalog                 what ships with this build
//   POST /api/v1/plugins/catalog/:name/install   install one (same path as an upload)
//
// Zero plugins were installed on any deployment because nothing shipped to
// install: the WebAssembly sandbox was a differentiator nobody could see. The
// examples under plugins/examples are now built by plugins/build-catalog.sh
// into plugincatalog/*.zip, embedded here, and offered on the Plugins page as
// one-click installs. Each entry goes through parsePluginZip exactly like an
// operator upload — same validation, same size ceilings, same audit row — and
// arrives DISABLED, like an upload.
// ---------------------------------------------------------------------------

//go:embed plugincatalog/*.zip
var pluginCatalogFS embed.FS

type catalogEntry struct {
	Name        string          `json:"name"`
	Version     string          `json:"version"`
	Description string          `json:"description"`
	Author      string          `json:"author"`
	Hooks       json.RawMessage `json:"hooks"`
	Permissions json.RawMessage `json:"permissions"`
	SHA256      string          `json:"sha256"`
	SizeBytes   int             `json:"size_bytes"`
	// Set from the tenant's installed plugins so the UI can say "installed
	// v0.1.0" / "update to v1.0.0" instead of offering a blind install.
	Installed        bool   `json:"installed"`
	InstalledVersion string `json:"installed_version,omitempty"`
	InstalledEnabled bool   `json:"installed_enabled,omitempty"`
	UpToDate         bool   `json:"up_to_date"`
}

// loadCatalog parses every embedded archive. Parsing is cheap (a few KB each)
// and the FS is immutable, so this is recomputed per request rather than cached
// — it also means a corrupt bundled zip is reported, never silently skipped.
func loadCatalog() ([]catalogEntry, map[string]*parsedPlugin, []string) {
	var (
		entries []catalogEntry
		parsed  = map[string]*parsedPlugin{}
		bad     []string
	)
	files, _ := pluginCatalogFS.ReadDir("plugincatalog")
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".zip") {
			continue
		}
		data, err := pluginCatalogFS.ReadFile(path.Join("plugincatalog", f.Name()))
		if err != nil {
			bad = append(bad, f.Name()+": "+err.Error())
			continue
		}
		p, err := parsePluginZip(data)
		if err != nil {
			bad = append(bad, f.Name()+": "+err.Error())
			continue
		}
		hooks, _ := json.Marshal(p.manifest.Plugin.Hooks)
		perms, _ := json.Marshal(p.manifest.Plugin.Permissions)
		entries = append(entries, catalogEntry{
			Name: p.manifest.Plugin.Name, Version: p.manifest.Plugin.Version,
			Description: p.manifest.Plugin.Description, Author: p.manifest.Plugin.Author,
			Hooks: hooks, Permissions: perms, SHA256: p.sha256, SizeBytes: len(p.wasm),
		})
		parsed[p.manifest.Plugin.Name] = p
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, parsed, bad
}

func handleListPluginCatalog(c *gin.Context, enf *rbac.Enforcer, store *db.Store) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourcePlugin, rbac.ActionList) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	entries, _, bad := loadCatalog()
	if store != nil {
		if rows, err := store.ListPlugins(c.Request.Context(), claims.TenantID, claims.UserID); err == nil {
			byName := map[string]db.PluginRow{}
			for _, r := range rows {
				byName[r.Name] = r
			}
			for i := range entries {
				if r, ok := byName[entries[i].Name]; ok {
					entries[i].Installed = true
					entries[i].InstalledVersion = r.Version
					entries[i].InstalledEnabled = r.Enabled
					entries[i].UpToDate = r.SHA256 == entries[i].SHA256
				}
			}
		}
	}
	// LinkedCommit, not Commit: these archives are embedded in THIS binary, so
	// the honest provenance is what the binary was compiled from, even when the
	// image was retagged into a newer deployment version.
	resp := gin.H{"catalog": entries, "source": "bundled with control plane " + version.LinkedCommit()}
	if len(bad) > 0 {
		resp["errors"] = bad
	}
	c.JSON(http.StatusOK, resp)
}

func handleInstallCatalogPlugin(c *gin.Context, enf *rbac.Enforcer, store *db.Store) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourcePlugin, rbac.ActionCreate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	_, parsed, _ := loadCatalog()
	p, ok := parsed[c.Param("name")]
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "no bundled plugin with that name"})
		return
	}
	hooks, _ := json.Marshal(p.manifest.Plugin.Hooks)
	perms, _ := json.Marshal(p.manifest.Plugin.Permissions)
	row, err := store.InstallPlugin(c.Request.Context(), claims.TenantID, claims.UserID, db.InstallPluginRequest{
		Name: p.manifest.Plugin.Name, Version: p.manifest.Plugin.Version,
		Description: p.manifest.Plugin.Description, Author: p.manifest.Plugin.Author,
		Hooks: hooks, Permissions: perms, SHA256: p.sha256, Wasm: p.wasm, UploadedBy: claims.UserID,
	})
	if err != nil {
		zap.L().Warn("install catalog plugin failed", zap.Error(err))
		respondStoreError(c, err)
		return
	}
	auditPlugin(store, claims.TenantID, claims.UserID, c, "plugin.install", row.ID, gin.H{
		"name": row.Name, "version": row.Version, "sha256": row.SHA256, "size": row.SizeBytes,
		"source": "catalog", "hooks": json.RawMessage(hooks), "permissions": json.RawMessage(perms),
	})
	c.JSON(http.StatusCreated, gin.H{
		"plugin": row,
		"note": "Installed from the bundled catalogue but NOT active. Enable it to put it in the request path — " +
			"an install alone never changes how traffic is judged.",
	})
}
