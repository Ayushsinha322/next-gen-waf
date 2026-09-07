"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import { api, type Plugin, type CatalogPlugin, type PluginHooks, type PluginPermissions } from "@/lib/api";
import { staggerContainer, fadeUp } from "@/lib/animations";

/**
 * This page once rendered a six-entry "WASM Plugin Marketplace" that did not
 * exist — invented plugins with invented authors and star ratings, KPIs reading
 * "3 installed / 14 available", and Install buttons whose entire implementation
 * was a toast. That was removed, leaving an honest read-only page that said
 * plugin upload was "on the roadmap, not in this build", because it wasn't:
 * handleListPlugins returned a hardcoded empty array and no upload endpoint
 * existed.
 *
 * It exists now. Upload a .zip containing sentinel-plugin.toml plus the WASM
 * module; the control plane validates and stores it, and every WAF node fetches
 * it on its next sync. Nothing here is decorative — each control maps to an
 * endpoint that does what it says.
 */

const HOOK_LABELS: Array<[keyof PluginHooks, string]> = [
  ["request_headers", "Request headers"],
  ["request_body", "Request body"],
  ["response_headers", "Response headers"],
  ["response_body", "Response body"],
];

const PERM_LABELS: Array<[keyof PluginPermissions, string]> = [
  ["host_set_decision", "Set WAF decision"],
  ["host_add_score", "Add anomaly score"],
  ["host_get_req_header", "Read request headers"],
  ["host_set_header", "Set response headers"],
  ["host_log", "Write to log"],
  ["host_kv_get", "Read shared KV"],
  ["host_kv_set", "Write shared KV"],
  ["host_http_callout", "Outbound HTTP"],
];

/** Permissions that let a plugin change what happens to traffic. Flagged amber. */
const HIGH_IMPACT: Array<keyof PluginPermissions> = ["host_set_decision", "host_add_score"];

function formatBytes(n: number): string {
  if (!n) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

function formatWhen(iso: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString();
}

export default function PluginsPage() {
  const [plugins, setPlugins] = useState<Plugin[] | null>(null);
  const [catalog, setCatalog] = useState<CatalogPlugin[] | null>(null);
  const [catalogErr, setCatalogErr] = useState<string | null>(null);
  const [installing, setInstalling] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [dragging, setDragging] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);

  const load = useCallback(async () => {
    try {
      const r = await api.plugins.list();
      setPlugins(r.plugins ?? []);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "request failed");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const upload = useCallback(
    async (file: File) => {
      setUploading(true);
      setUploadError(null);
      setNotice(null);
      try {
        const r = await api.plugins.upload(file);
        setNotice(
          `Installed ${r.plugin.name} ${r.plugin.version}. It is INACTIVE until you enable it.`,
        );
        await load();
      } catch (e) {
        // The server's validation text IS the useful part — surface it verbatim.
        setUploadError(e instanceof Error ? e.message : "upload failed");
      } finally {
        setUploading(false);
      }
    },
    [load],
  );

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      const file = e.dataTransfer.files?.[0];
      if (file) void upload(file);
    },
    [upload],
  );

  const loadCatalog = useCallback(async () => {
    try {
      const r = await api.plugins.catalog();
      setCatalog(r.catalog);
      setCatalogErr(r.errors?.length ? r.errors.join("; ") : null);
    } catch (e) {
      setCatalog([]);
      setCatalogErr(e instanceof Error ? e.message : "catalogue unavailable");
    }
  }, []);
  useEffect(() => { void loadCatalog(); }, [loadCatalog]);

  const installFromCatalog = useCallback(
    async (entry: CatalogPlugin) => {
      setInstalling(entry.name);
      setNotice(null);
      try {
        const r = await api.plugins.installFromCatalog(entry.name);
        setNotice(`${r.plugin.name} v${r.plugin.version} installed. ${r.note ?? ""}`.trim());
        await Promise.all([load(), loadCatalog()]);
      } catch (e) {
        setError(e instanceof Error ? e.message : "install failed");
      } finally {
        setInstalling(null);
      }
    },
    [load, loadCatalog],
  );

  const toggle = useCallback(
    async (p: Plugin) => {
      setBusy(p.name);
      setNotice(null);
      try {
        const r = await api.plugins.setEnabled(p.name, !p.enabled);
        setNotice(`${p.name} ${r.enabled ? "enabled" : "disabled"}. ${r.note ?? ""}`.trim());
        await load();
      } catch (e) {
        setError(e instanceof Error ? e.message : "request failed");
      } finally {
        setBusy(null);
      }
    },
    [load],
  );

  const remove = useCallback(
    async (p: Plugin) => {
      if (
        !window.confirm(
          `Delete plugin "${p.name}"? It will be removed from every WAF node on the next sync. ` +
            `You will need the original .zip to reinstall it.`,
        )
      ) {
        return;
      }
      setBusy(p.name);
      try {
        await api.plugins.remove(p.name);
        setNotice(`${p.name} deleted.`);
        await load();
      } catch (e) {
        setError(e instanceof Error ? e.message : "request failed");
      } finally {
        setBusy(null);
      }
    },
    [load],
  );

  const active = plugins?.filter(p => p.enabled).length ?? 0;

  return (
    <motion.div className="sec" variants={staggerContainer} initial="hidden" animate="visible">
      <motion.div variants={fadeUp}>
        <div className="sec-title">WASM Plugins</div>
        <div className="sec-sub">
          Custom request and response processing, sandboxed in WebAssembly. Upload a{" "}
          <code>.zip</code> containing <code>sentinel-plugin.toml</code> and the module.
        </div>
      </motion.div>

      {/* Upload */}
      <motion.div variants={fadeUp} className="pc">
        <div
          onDragOver={e => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          onClick={() => fileInput.current?.click()}
          role="button"
          tabIndex={0}
          onKeyDown={e => {
            if (e.key === "Enter" || e.key === " ") fileInput.current?.click();
          }}
          style={{
            border: `2px dashed ${dragging ? "var(--blue)" : "var(--border2)"}`,
            borderRadius: 10,
            padding: "28px 20px",
            textAlign: "center",
            cursor: uploading ? "wait" : "pointer",
            background: dragging ? "var(--bg3)" : "transparent",
            transition: "border-color .15s, background .15s",
          }}
        >
          <div style={{ fontSize: 26, marginBottom: 8 }}>{uploading ? "⏳" : "📦"}</div>
          <div style={{ fontWeight: 600, color: "var(--text)" }}>
            {uploading
              ? "Validating and installing…"
              : "Drop a plugin .zip here, or click to choose"}
          </div>
          <div style={{ fontSize: "var(--fs-sm)", color: "var(--text2)", marginTop: 6 }}>
            Maximum 10 MB. Re-uploading an existing name upgrades it in place.
          </div>
          <input
            ref={fileInput}
            type="file"
            accept=".zip,application/zip"
            style={{ display: "none" }}
            onChange={e => {
              const f = e.target.files?.[0];
              if (f) void upload(f);
              e.target.value = "";
            }}
          />
        </div>

        {uploadError && (
          <div
            style={{
              marginTop: 12,
              padding: "10px 12px",
              borderRadius: 8,
              border: "1px solid var(--red)",
              color: "var(--red)",
              fontSize: "var(--fs-sm)",
            }}
          >
            <strong>Rejected:</strong> {uploadError}
          </div>
        )}
        {notice && (
          <div
            style={{
              marginTop: 12,
              padding: "10px 12px",
              borderRadius: 8,
              border: "1px solid var(--border2)",
              color: "var(--text2)",
              fontSize: "var(--fs-sm)",
            }}
          >
            {notice}
          </div>
        )}
      </motion.div>

      {error && (
        <motion.div variants={fadeUp} className="pc" style={{ borderColor: "var(--red)" }}>
          <div style={{ fontSize: "var(--fs-h3)", fontWeight: 600, color: "var(--red)" }}>
            Could not load plugins
          </div>
          <div style={{ fontSize: "var(--fs-sm)", color: "var(--text2)", marginTop: 6 }}>
            {error}
          </div>
        </motion.div>
      )}

      {!error && plugins === null && (
        <motion.div variants={fadeUp} className="pc">
          <div style={{ fontSize: "var(--fs-sm)", color: "var(--text3)" }}>Loading…</div>
        </motion.div>
      )}

      {catalog !== null && (
        <motion.div variants={fadeUp} className="pc">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", gap: 12, flexWrap: "wrap", marginBottom: 6 }}>
            <div style={{ fontSize: "var(--fs-h3)", fontWeight: 600, color: "var(--text)" }}>Catalogue</div>
            <div style={{ fontSize: "var(--fs-sm)", color: "var(--text2)" }}>{catalog.length} bundled with this build · install is one click, enabling is a second</div>
          </div>
          <div style={{ fontSize: "var(--fs-sm)", color: "var(--text2)", lineHeight: 1.6, marginBottom: 14 }}>
            Each entry runs in the WebAssembly sandbox and can call only the host functions its manifest declares — shown
            per plugin below. Source for every entry is in <code>plugins/examples/</code>; the archives are rebuilt by{" "}
            <code>plugins/build-catalog.sh</code>.
          </div>
          {catalogErr && <div style={{ color: "var(--amber)", fontSize: "var(--fs-sm)", marginBottom: 10 }}>⚠ {catalogErr}</div>}
          <div style={{ display: "grid", gap: 12 }}>
            {catalog.map(entry => {
              const hooks = HOOK_LABELS.filter(([k]) => entry.hooks?.[k]);
              const perms = PERM_LABELS.filter(([k]) => entry.permissions?.[k]);
              const busyNow = installing === entry.name;
              const label = !entry.installed ? "Install" : entry.up_to_date ? "Installed" : `Update to v${entry.version}`;
              return (
                <div key={entry.name} style={{ border: "1px solid var(--border2)", borderRadius: 10, padding: 14, display: "grid", gap: 10 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap", alignItems: "flex-start" }}>
                    <div style={{ minWidth: 0 }}>
                      <div style={{ fontWeight: 700, color: "var(--text)", display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                        📦 {entry.name}
                        <span className="bdg bgr">v{entry.version}</span>
                        {entry.installed && <span className={`bdg ${entry.installed_enabled ? "bgg" : "ba"}`}>{entry.installed_enabled ? "ACTIVE" : `INSTALLED v${entry.installed_version}`}</span>}
                      </div>
                      <div style={{ fontSize: "var(--fs-sm)", color: "var(--text2)", marginTop: 4, lineHeight: 1.6, maxWidth: 760 }}>{entry.description}</div>
                      <div style={{ fontSize: 11, color: "var(--text3)", fontFamily: "var(--font-mono)", marginTop: 6 }}>
                        {entry.author} · {formatBytes(entry.size_bytes)} · sha256 {entry.sha256.slice(0, 12)}…
                      </div>
                    </div>
                    <button className={`btn ${entry.installed && entry.up_to_date ? "bg-btn" : "bp"} btn-sm`} disabled={busyNow || (entry.installed && entry.up_to_date)}
                      title={entry.installed && entry.up_to_date ? "This exact build is already installed" : "Install into this tenant (arrives disabled)"}
                      onClick={() => void installFromCatalog(entry)}>
                      {busyNow ? "Installing…" : label}
                    </button>
                  </div>
                  <div style={{ display: "flex", gap: 18, flexWrap: "wrap", fontSize: "var(--fs-sm)" }}>
                    <div><span style={{ color: "var(--text3)" }}>Hooks: </span>{hooks.length ? hooks.map(([, l]) => l).join(", ") : "none"}</div>
                    <div><span style={{ color: "var(--text3)" }}>Host calls: </span>
                      {perms.length ? perms.map(([k, l]) => (
                        <span key={k} className={`bdg ${HIGH_IMPACT.includes(k) ? "ba" : "bgr"}`} style={{ marginRight: 4 }} title={HIGH_IMPACT.includes(k) ? "Changes what happens to traffic" : undefined}>{l}</span>
                      )) : "none"}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </motion.div>
      )}

      {!error && plugins !== null && (
        <motion.div variants={fadeUp} className="pc">
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "baseline",
              gap: 12,
              flexWrap: "wrap",
              marginBottom: 14,
            }}
          >
            <div style={{ fontSize: "var(--fs-h3)", fontWeight: 600, color: "var(--text)" }}>
              Installed
            </div>
            <div style={{ fontSize: "var(--fs-sm)", color: "var(--text2)" }}>
              {plugins.length} installed · {active} active in the request path
            </div>
          </div>

          {plugins.length === 0 ? (
            <div style={{ color: "var(--text2)", fontSize: "var(--fs-sm)", lineHeight: 1.7 }}>
              No plugins installed. The WebAssembly runtime is loaded and idle.
              <br />
              Install <strong>scanner-guard</strong> from the catalogue above to see one run on real traffic, or upload your own archive.
            </div>
          ) : (
            <div style={{ display: "grid", gap: 12 }}>
              {plugins.map(p => {
                const hooks = HOOK_LABELS.filter(([k]) => p.hooks?.[k]);
                const perms = PERM_LABELS.filter(([k]) => p.permissions?.[k]);
                return (
                  <div
                    key={p.id || p.name}
                    style={{
                      border: "1px solid var(--border2)",
                      borderRadius: 10,
                      padding: 14,
                      display: "grid",
                      gap: 10,
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        gap: 12,
                        flexWrap: "wrap",
                        alignItems: "center",
                      }}
                    >
                      <div>
                        <div
                          style={{
                            fontWeight: 600,
                            color: "var(--text)",
                            display: "flex",
                            alignItems: "center",
                            gap: 8,
                            flexWrap: "wrap",
                          }}
                        >
                          {p.name}
                          <span style={{ color: "var(--text2)", fontWeight: 400 }}>
                            v{p.version}
                          </span>
                          <span
                            style={{
                              fontSize: 11,
                              padding: "2px 8px",
                              borderRadius: 999,
                              border: `1px solid ${p.enabled ? "var(--green)" : "var(--border2)"}`,
                              color: p.enabled ? "var(--green)" : "var(--text2)",
                            }}
                          >
                            {p.enabled ? "ACTIVE" : "INACTIVE"}
                          </span>
                        </div>
                        {p.description && (
                          <div
                            style={{
                              fontSize: "var(--fs-sm)",
                              color: "var(--text2)",
                              marginTop: 4,
                            }}
                          >
                            {p.description}
                          </div>
                        )}
                      </div>
                      <div style={{ display: "flex", gap: 8 }}>
                        <button
                          className="btn"
                          disabled={busy === p.name}
                          onClick={() => void toggle(p)}
                        >
                          {busy === p.name ? "…" : p.enabled ? "Disable" : "Enable"}
                        </button>
                        <button
                          className="btn"
                          disabled={busy === p.name}
                          onClick={() => void remove(p)}
                        >
                          Delete
                        </button>
                      </div>
                    </div>

                    <div
                      style={{
                        display: "grid",
                        gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))",
                        gap: 10,
                        fontSize: "var(--fs-sm)",
                      }}
                    >
                      <div>
                        <div style={{ color: "var(--text3)" }}>Runs in</div>
                        <div style={{ color: "var(--text2)" }}>
                          {hooks.length ? hooks.map(([, l]) => l).join(", ") : "no phases"}
                        </div>
                      </div>
                      <div>
                        <div style={{ color: "var(--text3)" }}>Module</div>
                        <div style={{ color: "var(--text2)" }}>
                          {formatBytes(p.size_bytes)}
                          <span
                            title={p.sha256}
                            style={{
                              color: "var(--text3)",
                              marginLeft: 6,
                              fontFamily: "var(--font-mono)",
                            }}
                          >
                            {p.sha256 ? p.sha256.slice(0, 12) : ""}
                          </span>
                        </div>
                      </div>
                      <div>
                        <div style={{ color: "var(--text3)" }}>Author</div>
                        <div style={{ color: "var(--text2)" }}>{p.author || "—"}</div>
                      </div>
                      <div>
                        <div style={{ color: "var(--text3)" }}>Updated</div>
                        <div style={{ color: "var(--text2)" }}>{formatWhen(p.updated_at)}</div>
                      </div>
                    </div>

                    <div style={{ fontSize: "var(--fs-sm)" }}>
                      <div style={{ color: "var(--text3)", marginBottom: 4 }}>
                        Declared permissions
                      </div>
                      {perms.length === 0 ? (
                        <span style={{ color: "var(--text2)" }}>none</span>
                      ) : (
                        <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                          {perms.map(([k, label]) => {
                            const high = HIGH_IMPACT.includes(k);
                            return (
                              <span
                                key={k}
                                style={{
                                  fontSize: 11,
                                  padding: "2px 8px",
                                  borderRadius: 999,
                                  border: `1px solid ${high ? "var(--amber)" : "var(--border2)"}`,
                                  color: high ? "var(--amber)" : "var(--text2)",
                                }}
                              >
                                {label}
                              </span>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </motion.div>
      )}

      {/* What the sandbox does and does not guarantee. An operator deciding
          whether to enable a third-party module needs this, and it is exactly the
          kind of claim that must not be overstated. */}
      <motion.div variants={fadeUp} className="pc">
        <div
          style={{
            fontSize: "var(--fs-h3)",
            fontWeight: 600,
            color: "var(--text)",
            marginBottom: 8,
          }}
        >
          Before you enable a plugin
        </div>
        <div style={{ fontSize: "var(--fs-sm)", color: "var(--text2)", lineHeight: 1.7 }}>
          Enabling a plugin runs its code on every matching request. The runtime enforces
          WebAssembly isolation, an instruction (fuel) limit, epoch interruption and a per-plugin
          memory cap, so a plugin cannot escape its memory or hang the proxy.
          <br />
          <strong style={{ color: "var(--text)" }}>
            The permissions above are declared intent, not enforcement.
          </strong>{" "}
          The runtime does not yet gate host calls on them, so a loaded plugin can call any host
          function the ABI exposes regardless of what its manifest lists. Treat enabling a plugin as
          running trusted code, and review the module source first.
          <br />
          Uploading never changes traffic on its own — a new plugin is inactive until you enable it,
          and every install, enable, disable and delete is written to the audit log.
        </div>
      </motion.div>
    </motion.div>
  );
}
