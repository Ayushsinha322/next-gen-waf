package main

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pelletier/go-toml/v2"
	"go.uber.org/zap"

	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/rbac"
)

// Upload limits. A WASM plugin is tens of KB to a couple of MB; these bounds are
// generous for real plugins and hostile to abuse. Every one is enforced BEFORE
// any allocation proportional to the attacker-declared size.
const (
	// maxPluginZipBytes caps the uploaded archive itself.
	maxPluginZipBytes = 10 << 20 // 10 MiB
	// maxPluginZipEntries caps the number of files in the archive. A zip can
	// declare millions of tiny entries to exhaust the parser.
	maxPluginZipEntries = 64
	// maxPluginWasmBytes caps the extracted module.
	maxPluginWasmBytes = 10 << 20 // 10 MiB
	// maxPluginManifestBytes caps the extracted manifest.
	maxPluginManifestBytes = 64 << 10 // 64 KiB
	// pluginManifestName is the file a plugin archive must contain.
	pluginManifestName = "sentinel-plugin.toml"
)

// pluginNameRe constrains a plugin name to something safe to use as an
// identifier, a log field, a filesystem-free lookup key and a URL path segment.
// The data plane loads plugins BY NAME, so an unconstrained name would be both a
// path-traversal and a log-injection vector.
var pluginNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// pluginManifest mirrors crates/sentinel-plugins/src/manifest.rs. The field names
// must stay in lockstep with the Rust struct: the data plane re-parses the same
// manifest, so a divergence here means the control plane advertises hooks or
// permissions the runtime will not honour.
type pluginManifest struct {
	Plugin struct {
		Name        string `toml:"name"`
		Version     string `toml:"version"`
		Description string `toml:"description"`
		Author      string `toml:"author"`
		Wasm        string `toml:"wasm"`
		Hooks       struct {
			RequestHeaders  bool `toml:"request_headers"  json:"request_headers"`
			RequestBody     bool `toml:"request_body"     json:"request_body"`
			ResponseHeaders bool `toml:"response_headers" json:"response_headers"`
			ResponseBody    bool `toml:"response_body"    json:"response_body"`
		} `toml:"hooks"`
		Permissions struct {
			HostLog          bool `toml:"host_log"            json:"host_log"`
			HostGetReqHeader bool `toml:"host_get_req_header" json:"host_get_req_header"`
			HostSetDecision  bool `toml:"host_set_decision"   json:"host_set_decision"`
			HostAddScore     bool `toml:"host_add_score"      json:"host_add_score"`
			HostSetHeader    bool `toml:"host_set_header"     json:"host_set_header"`
			HostKvGet        bool `toml:"host_kv_get"         json:"host_kv_get"`
			HostKvSet        bool `toml:"host_kv_set"         json:"host_kv_set"`
			HostHTTPCallout  bool `toml:"host_http_callout"   json:"host_http_callout"`
		} `toml:"permissions"`
	} `toml:"plugin"`
}

// parsedPlugin is the validated result of reading an uploaded archive.
type parsedPlugin struct {
	manifest pluginManifest
	wasm     []byte
	sha256   string
}

// readZipEntry reads one archive entry with a hard ceiling, without trusting the
// declared uncompressed size. io.LimitReader bounds what a decompression bomb can
// actually make us allocate: a 10 KB entry can claim to expand to 10 GB, and
// io.ReadAll on the raw reader would happily try.
func readZipEntry(f *zip.File, limit int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("opening %q: %w", f.Name, err)
	}
	defer rc.Close()
	// limit+1 so a file exactly at the ceiling is accepted but one byte over is
	// detectable rather than silently truncated.
	data, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, fmt.Errorf("reading %q: %w", f.Name, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%q exceeds the %d byte limit", f.Name, limit)
	}
	return data, nil
}

// safeZipName rejects entry names that try to escape, and normalises the single
// level of nesting that real-world archives have (zipping a directory yields
// "my-plugin/sentinel-plugin.toml", which is what a user will actually upload).
//
// Nothing is ever written to disk from an archive, so this is not the classic
// zip-slip write primitive — but the names are matched against and logged, and
// an entry called "../../etc/passwd" must never be treated as a manifest.
func safeZipName(name string) (string, bool) {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, `\`) {
		return "", false
	}
	clean := path.Clean(name)
	if clean == "." || strings.HasPrefix(clean, "../") || clean == ".." || path.IsAbs(clean) {
		return "", false
	}
	return clean, true
}

// parsePluginZip validates an uploaded archive and returns the manifest plus the
// module bytes. It is deliberately strict: anything it cannot fully understand is
// rejected, because a partially-understood manifest could advertise different
// permissions than the runtime will enforce.
func parsePluginZip(data []byte) (*parsedPlugin, error) {
	zr, err := zip.NewReader(newByteReaderAt(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("not a readable .zip archive: %w", err)
	}
	if len(zr.File) == 0 {
		return nil, errors.New("archive is empty")
	}
	if len(zr.File) > maxPluginZipEntries {
		return nil, fmt.Errorf("archive has %d entries, limit is %d", len(zr.File), maxPluginZipEntries)
	}

	// Locate the manifest, allowing at most one level of directory nesting so
	// that both `zip -r p.zip .` and `zip -r p.zip my-plugin/` work.
	var manifestFile *zip.File
	prefix := ""
	for _, f := range zr.File {
		clean, ok := safeZipName(f.Name)
		if !ok {
			return nil, fmt.Errorf("archive contains an unsafe path: %q", f.Name)
		}
		if path.Base(clean) != pluginManifestName {
			continue
		}
		dir := path.Dir(clean)
		if dir != "." && strings.Contains(dir, "/") {
			// Nested more than one level — ambiguous, refuse rather than guess.
			continue
		}
		if manifestFile != nil {
			return nil, fmt.Errorf("archive contains more than one %s", pluginManifestName)
		}
		manifestFile = f
		if dir != "." {
			prefix = dir + "/"
		}
	}
	if manifestFile == nil {
		return nil, fmt.Errorf(
			"archive must contain %s (at the root, or inside a single top-level directory)",
			pluginManifestName)
	}

	raw, err := readZipEntry(manifestFile, maxPluginManifestBytes)
	if err != nil {
		return nil, err
	}
	var m pluginManifest
	dec := toml.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields() // an unrecognised key may mean a newer manifest format
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%s is not valid: %w", pluginManifestName, err)
	}

	if m.Plugin.Name == "" || m.Plugin.Version == "" {
		return nil, fmt.Errorf("%s must set both plugin.name and plugin.version", pluginManifestName)
	}
	if !pluginNameRe.MatchString(m.Plugin.Name) {
		return nil, fmt.Errorf(
			"plugin.name %q is invalid: use lower-case letters, digits, dot, underscore or hyphen "+
				"(max 64 chars, must start alphanumeric)", m.Plugin.Name)
	}
	if len(m.Plugin.Version) > 64 {
		return nil, errors.New("plugin.version is too long (max 64 chars)")
	}

	// Default matches the Rust manifest's default_wasm_path().
	wasmRel := m.Plugin.Wasm
	if wasmRel == "" {
		wasmRel = "plugin.wasm"
	}
	if clean, ok := safeZipName(wasmRel); !ok {
		return nil, fmt.Errorf("plugin.wasm path %q is unsafe", wasmRel)
	} else {
		wasmRel = clean
	}

	want := prefix + wasmRel
	var wasmFile *zip.File
	for _, f := range zr.File {
		if clean, ok := safeZipName(f.Name); ok && clean == want {
			wasmFile = f
			break
		}
	}
	if wasmFile == nil {
		return nil, fmt.Errorf("archive does not contain the module %q named by plugin.wasm", want)
	}

	wasm, err := readZipEntry(wasmFile, maxPluginWasmBytes)
	if err != nil {
		return nil, err
	}
	// WebAssembly binary preamble: "\0asm" then a little-endian u32 version.
	// Checked here so a mislabelled file is rejected at upload with a clear
	// message, instead of failing later inside the data plane's wasmtime load
	// where the operator would only see a generic reload warning.
	if len(wasm) < 8 || string(wasm[0:4]) != "\x00asm" {
		return nil, fmt.Errorf("%q is not a WebAssembly module (missing the \\0asm preamble)", want)
	}

	sum := sha256.Sum256(wasm)
	return &parsedPlugin{manifest: m, wasm: wasm, sha256: hex.EncodeToString(sum[:])}, nil
}

// byteReaderAt adapts a []byte to io.ReaderAt for archive/zip without pulling in
// bytes.Reader's other behaviour or copying the buffer.
type byteReaderAt struct{ b []byte }

func newByteReaderAt(b []byte) *byteReaderAt { return &byteReaderAt{b: b} }

func (r *byteReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(r.b)) {
		return 0, io.EOF
	}
	n := copy(p, r.b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// handleListPluginsReal replaces the stub that returned a hardcoded empty list,
// which made the Plugins page permanently and misleadingly empty even after a
// plugin had been installed.
func handleListPluginsReal(c *gin.Context, enf *rbac.Enforcer, store *db.Store) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourcePlugin, rbac.ActionList) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusOK, gin.H{"plugins": []any{}, "database": false})
		return
	}
	plugins, err := store.ListPlugins(c.Request.Context(), claims.TenantID, claims.UserID)
	if err != nil {
		zap.L().Warn("list plugins failed", zap.Error(err))
		respondStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"plugins": plugins, "tenant_id": claims.TenantID, "database": true})
}

// handleUploadPlugin installs a plugin from a multipart .zip upload.
func handleUploadPlugin(c *gin.Context, enf *rbac.Enforcer, store *db.Store) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourcePlugin, rbac.ActionCreate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}

	// Bound the request body before reading it. Without this a client could
	// stream an unbounded upload and gin would buffer it.
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxPluginZipBytes)

	fh, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "expected a multipart form with a 'file' field containing a .zip archive",
		})
		return
	}
	if fh.Size > maxPluginZipBytes {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{
			"error": fmt.Sprintf("archive is %d bytes; the limit is %d", fh.Size, maxPluginZipBytes),
		})
		return
	}

	f, err := fh.Open()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "could not read the uploaded file"})
		return
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxPluginZipBytes+1))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "could not read the uploaded file"})
		return
	}
	if len(data) > maxPluginZipBytes {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "archive exceeds the upload limit"})
		return
	}

	parsed, err := parsePluginZip(data)
	if err != nil {
		// Validation messages are intentionally specific: the uploader needs to
		// know exactly what is wrong with their archive. They describe the
		// submitted file only, never server state.
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hooks, _ := json.Marshal(parsed.manifest.Plugin.Hooks)
	perms, _ := json.Marshal(parsed.manifest.Plugin.Permissions)

	row, err := store.InstallPlugin(c.Request.Context(), claims.TenantID, claims.UserID,
		db.InstallPluginRequest{
			Name:        parsed.manifest.Plugin.Name,
			Version:     parsed.manifest.Plugin.Version,
			Description: parsed.manifest.Plugin.Description,
			Author:      parsed.manifest.Plugin.Author,
			Hooks:       hooks,
			Permissions: perms,
			SHA256:      parsed.sha256,
			Wasm:        parsed.wasm,
			// The JWT carries no email (Subject is the user UUID), so record the
			// user id. The audit chain resolves it to a person; inventing a
			// display name here would be a guess.
			UploadedBy: claims.UserID,
		})
	if err != nil {
		zap.L().Warn("install plugin failed", zap.Error(err))
		respondStoreError(c, err)
		return
	}

	auditPlugin(store, claims.TenantID, claims.UserID, c, "plugin.install", row.Name, gin.H{
		"version": row.Version,
		"sha256":  row.SHA256,
		"size":    row.SizeBytes,
		"hooks":   json.RawMessage(hooks),
		// The requested host permissions are recorded in the audit trail: a
		// plugin that can set the WAF decision is as privileged as a rule change.
		"permissions": json.RawMessage(perms),
	})

	c.JSON(http.StatusCreated, gin.H{
		"plugin": row,
		"note": "Installed but NOT active. Enable it to put it in the request path — " +
			"an upload alone never changes how traffic is judged.",
	})
}

// handleSetPluginEnabled puts a plugin into, or takes it out of, the request path.
func handleSetPluginEnabled(c *gin.Context, enf *rbac.Enforcer, store *db.Store) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourcePlugin, rbac.ActionUpdate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	name := c.Param("name")
	if !pluginNameRe.MatchString(name) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid plugin name"})
		return
	}
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Enabled == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "body must be {\"enabled\": true|false}"})
		return
	}

	err := store.SetPluginEnabled(c.Request.Context(), claims.TenantID, claims.UserID, name, *body.Enabled)
	if errors.Is(err, db.ErrPluginNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "plugin not found"})
		return
	}
	if err != nil {
		zap.L().Warn("set plugin enabled failed", zap.Error(err))
		respondStoreError(c, err)
		return
	}

	action := "plugin.disable"
	if *body.Enabled {
		action = "plugin.enable"
	}
	auditPlugin(store, claims.TenantID, claims.UserID, c, action, name, gin.H{"enabled": *body.Enabled})

	c.JSON(http.StatusOK, gin.H{
		"name":    name,
		"enabled": *body.Enabled,
		"note":    "WAF nodes pick this up on their next config sync (within ~5s).",
	})
}

// handleDeletePlugin removes a plugin.
func handleDeletePlugin(c *gin.Context, enf *rbac.Enforcer, store *db.Store) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourcePlugin, rbac.ActionDelete) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	name := c.Param("name")
	if !pluginNameRe.MatchString(name) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid plugin name"})
		return
	}

	err := store.DeletePlugin(c.Request.Context(), claims.TenantID, claims.UserID, name)
	if errors.Is(err, db.ErrPluginNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "plugin not found"})
		return
	}
	if err != nil {
		zap.L().Warn("delete plugin failed", zap.Error(err))
		respondStoreError(c, err)
		return
	}
	auditPlugin(store, claims.TenantID, claims.UserID, c, "plugin.delete", name, nil)
	c.JSON(http.StatusOK, gin.H{"deleted": name})
}

// ---------------------------------------------------------------------------
// Internal endpoints — consumed by the data plane, not by the dashboard
// ---------------------------------------------------------------------------

// handleInternalPluginList returns the digest of every enabled plugin so a WAF
// node can decide what it needs to fetch. Node-global, like /internal/config.
func handleInternalPluginList(c *gin.Context, store *db.Store) {
	if !internalSecretOK(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	if store == nil {
		c.JSON(http.StatusOK, gin.H{"plugins": []any{}})
		return
	}
	plugins, err := store.ListEnabledPluginsGlobal(c.Request.Context())
	if err != nil {
		zap.L().Warn("internal plugin list failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"plugins": plugins})
}

// handleInternalPluginWasm streams one enabled plugin's module bytes to a WAF
// node. Serves only ENABLED plugins, so disabling a plugin is sufficient to stop
// it being loadable even if a node asks for it by name.
func handleInternalPluginWasm(c *gin.Context, store *db.Store) {
	if !internalSecretOK(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	name := c.Param("name")
	if !pluginNameRe.MatchString(name) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid plugin name"})
		return
	}
	wasm, sha, err := store.GetEnabledPluginWasmGlobal(c.Request.Context(), name)
	if errors.Is(err, db.ErrPluginNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "plugin not found or not enabled"})
		return
	}
	if err != nil {
		zap.L().Warn("internal plugin wasm failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	// The digest lets the node verify what it received matches what the listing
	// advertised, so a truncated or swapped body cannot be loaded silently.
	c.Header("X-Sentinel-Plugin-SHA256", sha)
	c.Data(http.StatusOK, "application/wasm", wasm)
}

// auditPlugin records a plugin mutation on the tamper-evident audit chain.
// Detached from the request context for the same reason as the other audit
// writers: the HTTP response usually returns first, which would cancel the
// context and silently drop the row.
func auditPlugin(store *db.Store, tenantID, userID string, c *gin.Context, action, name string, diff any) {
	if store == nil {
		return
	}
	var raw json.RawMessage
	if diff != nil {
		if b, err := json.Marshal(diff); err == nil {
			raw = b
		}
	}
	ip := c.ClientIP()
	ua := c.Request.UserAgent()
	target := name
	actor := userID
	req := db.WriteAuditRequest{
		TenantID:    tenantID,
		ActorUserID: &actor,
		Action:      action,
		TargetKind:  "plugin",
		TargetID:    &target,
		IP:          &ip,
		UserAgent:   &ua,
		Diff:        raw,
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := store.WriteAuditLog(ctx, req, auditHMACKey()); err != nil {
			zap.L().Warn("plugin audit write failed",
				zap.String("action", req.Action), zap.Error(err))
		}
	}()
}
