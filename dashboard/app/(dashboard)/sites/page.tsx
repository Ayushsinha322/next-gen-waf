"use client";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { motion, AnimatePresence } from "framer-motion";
import { showToast } from "@/components/ui/Toast";
import { openModal } from "@/components/ui/Modal";
import { api, type Site } from "@/lib/api";
import { staggerContainer, cardVariants, fadeUp, spring } from "@/lib/animations";
import SiteWizard from "@/components/sites/SiteWizard";
import { siteToForm, normalizeDomain, type SiteForm } from "@/lib/siteConfig";

/* ── Lab-site metadata ────────────────────────────────────────── */
const LAB_META: Record<string, { icon: string; full: string; port: string; desc: string; color: string; accent: string }> = {
  "dvwa.local": {
    icon: "🩸", full: "DVWA", port: "80",
    desc: "Damn Vulnerable Web Application — SQLi, XSS, CSRF, File Inclusion training target",
    color: "rgba(200,0,30,.15)", accent: "rgba(200,0,30,.45)",
  },
  "juice.local": {
    icon: "🧃", full: "OWASP Juice Shop", port: "3000",
    desc: "Intentionally insecure Node.js app — covers OWASP Top 10 + advanced vulnerabilities",
    color: "rgba(0,200,240,.12)", accent: "rgba(0,200,240,.38)",
  },
};

export default function SitesPage() {
  const router = useRouter();
  const [sites, setSites]         = useState<Site[]>([]);
  const [loading, setLoading]     = useState(true);
  const [search, setSearch]       = useState("");
  const [modeFilter, setModeFilter] = useState("");
  const [wizard, setWizard]       = useState<{ mode: "create" | "edit"; siteId?: string; initial?: SiteForm } | null>(null);

  async function loadSites() {
    setLoading(true);
    try {
      const res = await api.sites.list();
      setSites(res.sites ?? []);
    } catch {
      showToast("Failed to load sites", "e", "⚠️");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { loadSites(); }, []);

  const filtered = sites.filter(s => {
    const q         = search.toLowerCase();
    const matchSearch = !q || s.name.toLowerCase().includes(q) || s.domains.join(" ").includes(q);
    const matchMode   = !modeFilter || s.waf_policy?.mode?.toUpperCase() === modeFilter;
    return matchSearch && matchMode;
  });

  const online   = sites.filter(s => s.status === "active").length;
  const learning = sites.filter(s => s.waf_policy?.mode === "learning").length;
  const offline  = sites.filter(s => s.status === "paused").length;

  const labSites = sites.filter(s => LAB_META[s.name]);

  function openDeployInstructions(domain: string, upHost: string, upPort: string) {
    const host       = normalizeDomain(domain) || domain;
    const upstream   = upHost ? `${upHost}${upPort ? `:${upPort}` : ""}` : "the upstream";
    const hostsEntry = `127.0.0.1  ${host}`;
    const browseURL  = `http://${host}:9080/`;
    openModal({
      title: "🚀 Site Deployed — Next Steps",
      body: (
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <div style={{ padding: "10px 14px", background: "rgba(0,212,255,.08)", border: "1px solid rgba(0,212,255,.25)", borderRadius: "var(--r2)", fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--cyan)" }}>
            ✅ Site saved and WAF protection active in ~5 seconds
          </div>
          <div>
            <div style={{ fontSize: 14, color: "var(--text2)", marginBottom: 6, fontFamily: "var(--font-mono)", letterSpacing: 1 }}>STEP 1 — Add to /etc/hosts (run once as root)</div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <code style={{ flex: 1, padding: "8px 12px", background: "rgba(0,0,0,.35)", border: "1px solid rgba(255,255,255,.08)", borderRadius: "var(--r2)", fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--text)", userSelect: "all" }}>
                {hostsEntry}
              </code>
              <button className="btn bg-btn btn-sm" onClick={() => { navigator.clipboard.writeText(`echo '${hostsEntry}' | sudo tee -a /etc/hosts`); showToast("Copied!", "s", "📋"); }}>📋 Copy cmd</button>
            </div>
            <div style={{ marginTop: 6, fontFamily: "var(--font-mono)", fontSize: 14, color: "var(--text3)" }}>
              echo &apos;{hostsEntry}&apos; | sudo tee -a /etc/hosts
            </div>
          </div>
          <div>
            <div style={{ fontSize: 14, color: "var(--text2)", marginBottom: 6, fontFamily: "var(--font-mono)", letterSpacing: 1 }}>STEP 2 — Browse through the WAF proxy (port 9080)</div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <code style={{ flex: 1, padding: "8px 12px", background: "rgba(0,0,0,.35)", border: "1px solid rgba(255,255,255,.08)", borderRadius: "var(--r2)", fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--green)" }}>
                {browseURL}
              </code>
              <button className="btn bg-btn btn-sm" onClick={() => { navigator.clipboard.writeText(browseURL); showToast("Copied!", "s", "📋"); }}>📋 Copy</button>
              <a className="btn bp btn-sm" href={browseURL} target="_blank" rel="noreferrer">↗ Open</a>
            </div>
          </div>
          <div style={{ padding: "10px 14px", background: "rgba(255,165,0,.07)", border: "1px solid rgba(255,165,0,.2)", borderRadius: "var(--r2)", fontFamily: "var(--font-mono)", fontSize: 14, color: "rgba(255,200,80,1)", lineHeight: 1.7 }}>
            ⚠️ Do NOT browse <span style={{ color: "var(--red-b)" }}>{upstream}</span> directly — that bypasses the WAF and generates no logs.
            <br />Always use <span style={{ color: "var(--green)" }}>{browseURL}</span> to route traffic through the WAF.
          </div>
        </div>
      ),
      footer: (
        <button className="btn bp" onClick={() => document.querySelector<HTMLElement>(".modal-bg")?.remove()}>Got it</button>
      ),
    });
  }

  function openCreate() { setWizard({ mode: "create" }); }

  async function openEdit(s: Site) {
    // Use the freshest copy from the API so edits start from server truth.
    try {
      const res = await api.sites.get(s.id);
      setWizard({ mode: "edit", siteId: s.id, initial: siteToForm(res.site) });
    } catch {
      setWizard({ mode: "edit", siteId: s.id, initial: siteToForm(s) });
    }
  }

  async function onWizardSaved(domain?: string) {
    const created = wizard?.mode === "create";
    setWizard(null);
    let fresh: Site[] | null = null;
    try {
      const res = await api.sites.list();
      fresh = res.sites ?? [];
      setSites(fresh);
    } catch {
      loadSites();
    }
    if (created && domain) {
      const host = normalizeDomain(domain) || domain;
      const s = fresh?.find(x => x.domains?.some(d => normalizeDomain(d) === host));
      const srv = (s?.upstream as { servers?: Array<{ host: string; port: number }> })?.servers?.[0];
      openDeployInstructions(domain, srv?.host ?? "", srv ? String(srv.port) : "");
    }
  }

  async function exportYaml() {
    try {
      const yaml = await api.sites.exportYaml();
      const blob = new Blob([yaml], { type: "application/x-yaml" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = "sentinel-sites.yaml"; a.click();
      URL.revokeObjectURL(url);
      showToast("Exported sites to YAML", "s", "📤");
    } catch { showToast("Export failed", "e", "⚠️"); }
  }

  function openImport() {
    let yamlText = "";
    openModal({
      title: "📥 Import Sites (Config-as-Code)",
      body: (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <div style={{ fontSize: 13, color: "var(--text3)", lineHeight: 1.6 }}>
            Paste a YAML document (same shape as Export). Sites are matched by <strong>name</strong> — existing ones are updated, new ones created.
          </div>
          <input type="file" accept=".yaml,.yml" style={{ fontSize: 13, color: "var(--text3)" }}
            onChange={async e => {
              const file = e.target.files?.[0]; if (!file) return;
              yamlText = await file.text();
              const ta = document.getElementById("yaml-import-area") as HTMLTextAreaElement | null;
              if (ta) ta.value = yamlText;
            }} />
          <textarea id="yaml-import-area" className="fin2" style={{ minHeight: 220, fontFamily: "var(--font-mono)", fontSize: 13 }}
            placeholder={"sites:\n  - name: app\n    domains: [app.example.com]\n    upstream:\n      servers: [{host: 127.0.0.1, port: 8080}]\n    waf_policy:\n      mode: blocking"}
            onChange={e => { yamlText = e.target.value; }} />
        </div>
      ),
      footer: (
        <>
          <button className="btn bg-btn" onClick={() => document.querySelector<HTMLElement>(".modal-bg")?.remove()}>Cancel</button>
          <button className="btn bp" onClick={async () => {
            if (!yamlText.trim()) { showToast("Paste or upload a YAML file", "e", "⚠️"); return; }
            try {
              const res = await api.sites.importYaml(yamlText);
              document.querySelector<HTMLElement>(".modal-bg")?.remove();
              showToast(`Imported: ${res.created} created, ${res.updated} updated`, "s", "✅");
              loadSites();
            } catch (err) {
              showToast(err instanceof Error ? err.message : "Import failed", "e", "⚠️");
            }
          }}>Import</button>
        </>
      ),
    });
  }

  return (
    <motion.div className="sec" variants={staggerContainer} initial="hidden" animate="visible">

      {/* ── Header ──────────────────────────────────────────────── */}
      <motion.div variants={fadeUp} style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 14 }}>
        <div>
          <div className="sec-title">Protected Sites</div>
          <div className="sec-sub">Manage reverse proxy targets — WAF enforcement per site</div>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <motion.button className="btn bg-btn btn-sm" onClick={loadSites} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>⟳ Refresh</motion.button>
          <motion.button className="btn bg-btn btn-sm" onClick={exportYaml} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }} title="Download all sites as YAML">📤 Export</motion.button>
          <motion.button className="btn bg-btn btn-sm" onClick={openImport} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }} title="Import sites from YAML">📥 Import</motion.button>
          <motion.button className="btn bp btn-sm" onClick={openCreate} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>＋ Add Site</motion.button>
        </div>
      </motion.div>

      {/* ── Summary KPIs ──────────────────────────────────────── */}
      <motion.div variants={staggerContainer} initial="hidden" animate="visible" style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 12 }}>
        {[
          { cls: "kg", ico: "✅", lbl: "Online",     val: String(online),           valCls: "g" },
          { cls: "ka", ico: "📚", lbl: "Learning",   val: String(learning),          valCls: "a" },
          { cls: "",   ico: "⛔", lbl: "Offline",    val: String(offline),           valCls: "" },
          { cls: "kc", ico: "🌐", lbl: "Total Sites", val: String(sites.length),     valCls: "c" },
        ].map((k, i) => (
          <motion.div key={i} className={`kpi ${k.cls}`} variants={cardVariants}>
            <span className="kpi-ico">{k.ico}</span>
            <div className="kpi-lbl">{k.lbl}</div>
            <div className={`kpi-val ${k.valCls}`} style={k.valCls === "" ? { color: "var(--text2)" } : {}}>{k.val}</div>
          </motion.div>
        ))}
      </motion.div>

      {/* ── Security Lab Sites ────────────────────────────────── */}
      {/* Only render lab targets that actually exist in the site list. The guard
          used to be `labSites.length > 0 || !loading`, which rendered the panel
          whenever loading finished — and the body mapped a hardcoded
          ["dvwa.local","juice.local"] array rather than real rows, defaulting a
          missing site to status ACTIVE / mode BLOCKING. So a fresh install with
          no lab sites showed two protected applications that did not exist. */}
      {labSites.length > 0 && (
        <motion.div variants={fadeUp}>
          <div style={{ fontSize: 11, fontFamily: "var(--font-mono)", color: "var(--text3)", letterSpacing: 1.5, textTransform: "uppercase", marginBottom: 10, display: "flex", alignItems: "center", gap: 8 }}>
            <span>🧪 Security Lab Targets</span>
            <div style={{ flex: 1, height: 1, background: "rgba(255,255,255,.06)" }} />
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            {labSites.map(site => {
              const name = site.name;
              const meta = LAB_META[name];
              const mode = site.waf_policy?.mode?.toUpperCase() ?? "—";
              const isActive = site.status === "active";
              return (
                <motion.div key={name} className="panel" style={{ border: `1px solid ${meta.accent}` }} variants={cardVariants}>
                  <div className="ph" style={{ background: meta.color }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                      <motion.div
                        style={{
                          width: 44, height: 44, borderRadius: 10,
                          background: meta.color, border: `1px solid ${meta.accent}`,
                          display: "flex", alignItems: "center", justifyContent: "center",
                          fontSize: 27, flexShrink: 0,
                        }}
                        whileHover={{ scale: 1.1, rotate: 5 }}
                        transition={spring}
                      >{meta.icon}</motion.div>
                      <div>
                        <div style={{ fontFamily: "var(--font-display)", fontSize: 14, fontWeight: 700, color: "var(--text)", letterSpacing: 1 }}>{meta.full}</div>
                        <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text3)", marginTop: 2 }}>
                          {name} · port {meta.port}
                        </div>
                      </div>
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", gap: 4, alignItems: "flex-end", flexShrink: 0 }}>
                      <div style={{ display: "flex", gap: 5, alignItems: "center" }}>
                        <div className={`sd ${isActive ? "g" : "r"}`} />
                        <span className={`bdg ${isActive ? "bgg" : "bgr"}`}>{isActive ? "active" : "paused"}</span>
                      </div>
                      <span className={`bdg ${mode === "BLOCKING" ? "br" : mode === "LEARNING" ? "ba blink" : "bgr"}`}>
                        <span className="bdr" />{mode}
                      </span>
                    </div>
                  </div>
                  <div className="pb">
                    <div style={{ fontSize: 14, color: "var(--text2)", lineHeight: 1.6, marginBottom: 12, fontFamily: "var(--font-mono)" }}>
                      {meta.desc}
                    </div>
                    <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                      <motion.button className="btn bp btn-sm" disabled={!site} onClick={() => site && router.push(`/sites/${site.id}`)} whileHover={{ scale: 1.04 }} whileTap={{ scale: 0.96 }} style={!site ? { opacity: 0.5 } : undefined}>📂 Open Dashboard</motion.button>
                      <motion.button className="btn bc btn-sm" onClick={() => router.push(`/logs?site=${name}&tab=waf`)} whileHover={{ scale: 1.04 }} whileTap={{ scale: 0.96 }}>🛡️ WAF Logs</motion.button>
                      <button className="btn bg-btn btn-sm" onClick={() => router.push(`/logs?site=${name}&tab=access`)}>📡 Access Logs</button>
                      <button className="btn bg-btn btn-sm" disabled={!site} onClick={() => site && openEdit(site)} style={!site ? { opacity: 0.5 } : undefined}>✏️ Edit</button>
                    </div>
                    <div style={{ marginTop: 10, padding: "8px 10px", background: "rgba(0,0,0,.2)", borderRadius: "var(--r2)", fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text3)", display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 6 }}>
                      <div><div style={{ color: "var(--text2)", marginBottom: 2 }}>Upstream</div>127.0.0.1:{meta.port}</div>
                      <div><div style={{ color: "var(--text2)", marginBottom: 2 }}>Paranoia</div>Level {site?.waf_policy?.paranoia_level ?? 2}</div>
                      <div><div style={{ color: "var(--text2)", marginBottom: 2 }}>Threshold</div>{site?.waf_policy?.anomaly_threshold ?? 5} score</div>
                    </div>
                  </div>
                </motion.div>
              );
            })}
          </div>
        </motion.div>
      )}

      {/* ── All Sites Table ───────────────────────────────────── */}
      <motion.div className="panel" variants={fadeUp}>
        <div className="ph">
          <div className="ptitle">All Sites ({filtered.length})</div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <div style={{ position: "relative" }}>
              <span style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)", color: "var(--text3)", fontSize: 14, pointerEvents: "none" }}>🔍</span>
              <input className="fi2" type="text" placeholder="Search sites..." value={search} onChange={e => setSearch(e.target.value)} />
            </div>
            <select className="fsel" value={modeFilter} onChange={e => setModeFilter(e.target.value)}>
              <option value="">All Modes</option><option>BLOCKING</option><option>LEARNING</option><option>OFF</option>
            </select>
          </div>
        </div>
        <div className="tw">
          {loading ? (
            <div style={{ padding: "24px", textAlign: "center", fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--text3)" }}>Loading sites…</div>
          ) : filtered.length === 0 ? (
            <div style={{ padding: "24px", textAlign: "center", fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--text3)" }}>No sites found</div>
          ) : (
            <table>
              <thead><tr><th>Status</th><th>Name</th><th>Domains</th><th>Mode</th><th>WAF Policy</th><th>State</th><th>Actions</th></tr></thead>
              <tbody>
                {filtered.map((s, idx) => {
                  const mode  = s.waf_policy?.mode?.toUpperCase() ?? "—";
                  const stDot = s.status === "active" ? "g" : "r";
                  const meta  = LAB_META[s.name];
                  return (
                    <motion.tr key={s.id} initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: idx * 0.02 }}>
                      <td><div className={`sd ${stDot}`} /></td>
                      <td>
                        <span style={{ color: meta ? (s.name === "dvwa.local" ? "var(--red-b)" : "var(--cyan)") : "var(--cyan)", fontWeight: meta ? 700 : 400 }}>
                          {meta ? `${meta.icon} ` : ""}{s.name}
                        </span>
                      </td>
                      <td style={{ maxWidth: 240, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={s.domains.join(", ")}>{s.domains.join(", ")}</td>
                      <td><span className={`bdg ${mode === "BLOCKING" ? "br" : mode === "LEARNING" ? "ba blink" : "bgr"}`}><span className="bdr" />{mode}</span></td>
                      <td className="td3">paranoia {s.waf_policy?.paranoia_level ?? "—"}</td>
                      <td><span className={`bdg ${s.status === "active" ? "bgg" : "bgr"}`}>{s.status}</span></td>
                      <td>
                        <div style={{ display: "flex", gap: 4 }}>
                          <motion.button className="btn bc btn-xs" title="Open site dashboard" onClick={() => router.push(`/sites/${s.id}`)} whileHover={{ scale: 1.08 }} whileTap={{ scale: 0.94 }}>📂 Open</motion.button>
                          <motion.button className="btn bg-btn btn-xs" onClick={() => router.push(`/logs?site=${s.name}&tab=waf`)} whileHover={{ scale: 1.08 }} whileTap={{ scale: 0.94 }}>🛡️</motion.button>
                          <motion.button className="btn bg-btn btn-xs" onClick={() => router.push(`/logs?site=${s.name}`)} whileHover={{ scale: 1.08 }} whileTap={{ scale: 0.94 }}>📜 Logs</motion.button>
                          <motion.button className="btn bc btn-xs" title="Edit site" onClick={() => openEdit(s)} whileHover={{ scale: 1.08 }} whileTap={{ scale: 0.94 }}>✏️</motion.button>
                          <motion.button
                            className="btn bg-btn btn-xs"
                            title={s.status === "active" ? "Pause site" : "Activate site"}
                            onClick={async () => {
                              const next = s.status === "active" ? "paused" : "active";
                              try {
                                await api.sites.updateStatus(s.id, next);
                                showToast(`Site ${next}`, "s", next === "active" ? "✅" : "⏸️");
                                loadSites();
                              } catch { showToast("Failed", "e", "⚠️"); }
                            }}
                            whileHover={{ scale: 1.08 }}
                            whileTap={{ scale: 0.94 }}
                          >{s.status === "active" ? "⏸️" : "▶️"}</motion.button>
                          <motion.button
                            className="btn bg-btn btn-xs"
                            title="Delete site"
                            onClick={async () => {
                              if (!confirm(`Delete site "${s.name}"? This cannot be undone.`)) return;
                              try {
                                await api.sites.delete(s.id);
                                showToast("Site deleted", "s", "🗑️");
                                loadSites();
                              } catch { showToast("Failed to delete", "e", "⚠️"); }
                            }}
                            whileHover={{ scale: 1.08 }}
                            whileTap={{ scale: 0.94 }}
                          >🗑️</motion.button>
                        </div>
                      </td>
                    </motion.tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </motion.div>

      {/* ── Add / Edit Site Wizard ──────────────────────────────── */}
      <AnimatePresence>
        {wizard && (
          <SiteWizard
            mode={wizard.mode}
            siteId={wizard.siteId}
            initial={wizard.initial}
            onClose={() => setWizard(null)}
            onSaved={onWizardSaved}
          />
        )}
      </AnimatePresence>
    </motion.div>
  );
}