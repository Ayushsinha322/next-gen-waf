"use client";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { showToast } from "@/components/ui/Toast";
import { openModal } from "@/components/ui/Modal";
import { api, type Site } from "@/lib/api";

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

  /* Lab sites (DVWA + JuiceShop) extracted from the full list */
  const labSites = sites.filter(s => LAB_META[s.name]);

  function openAddModal() {
    let newName = ""; let newDomain = ""; let newUpHost = "127.0.0.1";
    let newUpPort = "8080"; let newMode = "BLOCKING";
    openModal({
      title: "🌐 Add Protected Site",
      body: (
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <div className="fg2"><label className="flbl2">Site Name</label><input className="fin2" placeholder="mysite" onChange={e => { newName = e.target.value; }} /></div>
            <div className="fg2"><label className="flbl2">Domain</label><input className="fin2" placeholder="mysite.example.com" onChange={e => { newDomain = e.target.value; }} /></div>
            <div className="fg2"><label className="flbl2">Upstream Host</label><input className="fin2" placeholder="127.0.0.1" onChange={e => { newUpHost = e.target.value; }} /></div>
            <div className="fg2"><label className="flbl2">Upstream Port</label><input className="fin2" placeholder="8080" type="number" onChange={e => { newUpPort = e.target.value; }} /></div>
            <div className="fg2"><label className="flbl2">WAF Mode</label><select className="fin2 fsel2" onChange={e => { newMode = e.target.value; }}><option>BLOCKING</option><option>LEARNING</option><option>OFF</option></select></div>
          </div>
        </div>
      ),
      footer: (
        <>
          <button className="btn bg-btn" onClick={() => document.querySelector<HTMLElement>(".modal-bg")?.remove()}>Cancel</button>
          <button className="btn bp" onClick={async () => {
            if (!newName || !newDomain) { showToast("Name and domain required", "e", "⚠️"); return; }
            try {
              await api.sites.create({
                name: newName,
                domains: [newDomain],
                upstream:   { servers: [`${newUpHost}:${newUpPort}`], lb: "round_robin" },
                waf_policy: { mode: newMode.toLowerCase(), paranoia_level: 2, anomaly_threshold: 5 },
              });
              showToast("Site added", "s", "🌐");
              document.querySelector<HTMLElement>(".modal-bg")?.remove();
              loadSites();
            } catch (err: unknown) {
              showToast(err instanceof Error ? err.message : "Failed", "e", "⚠️");
            }
          }}>Add Site</button>
        </>
      ),
    });
  }

  return (
    <div className="sec">

      {/* ── Header ──────────────────────────────────────────────── */}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 14 }}>
        <div>
          <div className="sec-title">Protected Sites</div>
          <div className="sec-sub">Manage reverse proxy targets — WAF enforcement per site</div>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button className="btn bg-btn btn-sm" onClick={loadSites}>⟳ Refresh</button>
          <button className="btn bp btn-sm" onClick={openAddModal}>＋ Add Site</button>
        </div>
      </div>

      {/* ── Summary KPIs ──────────────────────────────────────── */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 12 }}>
        {[
          { cls: "kg", ico: "✅", lbl: "Online",     val: String(online),           valCls: "g" },
          { cls: "ka", ico: "📚", lbl: "Learning",   val: String(learning),          valCls: "a" },
          { cls: "",   ico: "⛔", lbl: "Offline",    val: String(offline),           valCls: "" },
          { cls: "kc", ico: "🌐", lbl: "Total Sites", val: String(sites.length),     valCls: "c" },
        ].map((k, i) => (
          <div key={i} className={`kpi ${k.cls}`}>
            <span className="kpi-ico">{k.ico}</span>
            <div className="kpi-lbl">{k.lbl}</div>
            <div className={`kpi-val ${k.valCls}`} style={k.valCls === "" ? { color: "var(--text2)" } : {}}>{k.val}</div>
          </div>
        ))}
      </div>

      {/* ── Security Lab Sites ────────────────────────────────── */}
      {(labSites.length > 0 || !loading) && (
        <div>
          <div style={{ fontSize: 9, fontFamily: "'Share Tech Mono',monospace", color: "var(--text3)", letterSpacing: 1.5, textTransform: "uppercase", marginBottom: 10, display: "flex", alignItems: "center", gap: 8 }}>
            <span>🧪 Security Lab Targets</span>
            <div style={{ flex: 1, height: 1, background: "rgba(255,255,255,.06)" }} />
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            {(["dvwa.local", "juice.local"] as const).map(name => {
              const meta = LAB_META[name];
              const site = sites.find(s => s.name === name);
              const mode = site?.waf_policy?.mode?.toUpperCase() ?? "BLOCKING";
              const isActive = !site || site.status === "active";
              return (
                <div key={name} className="panel" style={{ border: `1px solid ${meta.accent}` }}>
                  <div className="ph" style={{ background: meta.color }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                      <div style={{
                        width: 44, height: 44, borderRadius: 10,
                        background: meta.color, border: `1px solid ${meta.accent}`,
                        display: "flex", alignItems: "center", justifyContent: "center",
                        fontSize: 24, flexShrink: 0,
                      }}>{meta.icon}</div>
                      <div>
                        <div style={{ fontFamily: "'Orbitron',sans-serif", fontSize: 12, fontWeight: 700, color: "var(--text)", letterSpacing: 1 }}>{meta.full}</div>
                        <div style={{ fontFamily: "'Share Tech Mono',monospace", fontSize: 9, color: "var(--text3)", marginTop: 2 }}>
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
                    <div style={{ fontSize: 10, color: "var(--text2)", lineHeight: 1.6, marginBottom: 12, fontFamily: "'Share Tech Mono',monospace" }}>
                      {meta.desc}
                    </div>
                    <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                      <button
                        className="btn bp btn-sm"
                        onClick={() => router.push(`/logs?site=${name}&tab=waf`)}
                      >🛡️ WAF Logs</button>
                      <button
                        className="btn bc btn-sm"
                        onClick={() => router.push(`/logs?site=${name}&tab=access`)}
                      >📡 Access Logs</button>
                      <button
                        className="btn bg-btn btn-sm"
                        onClick={() => router.push(`/logs?site=${name}&tab=ml`)}
                      >🤖 ML Intel</button>
                      <button
                        className="btn bg-btn btn-sm"
                        onClick={() => showToast(`Editing ${name}`, "i", "✏️")}
                      >✏️ Edit</button>
                    </div>
                    <div style={{ marginTop: 10, padding: "8px 10px", background: "rgba(0,0,0,.2)", borderRadius: "var(--r2)", fontFamily: "'Share Tech Mono',monospace", fontSize: 9, color: "var(--text3)", display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 6 }}>
                      <div><div style={{ color: "var(--text2)", marginBottom: 2 }}>Upstream</div>127.0.0.1:{meta.port}</div>
                      <div><div style={{ color: "var(--text2)", marginBottom: 2 }}>Paranoia</div>Level {site?.waf_policy?.paranoia_level ?? 2}</div>
                      <div><div style={{ color: "var(--text2)", marginBottom: 2 }}>Threshold</div>{site?.waf_policy?.anomaly_threshold ?? 5} score</div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ── All Sites Table ───────────────────────────────────── */}
      <div className="panel">
        <div className="ph">
          <div className="ptitle">All Sites ({filtered.length})</div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <div style={{ position: "relative" }}>
              <span style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)", color: "var(--text3)", fontSize: 12, pointerEvents: "none" }}>🔍</span>
              <input className="fi2" type="text" placeholder="Search sites..." value={search} onChange={e => setSearch(e.target.value)} />
            </div>
            <select className="fsel" value={modeFilter} onChange={e => setModeFilter(e.target.value)}>
              <option value="">All Modes</option><option>BLOCKING</option><option>LEARNING</option><option>OFF</option>
            </select>
          </div>
        </div>
        <div className="tw">
          {loading ? (
            <div style={{ padding: "24px", textAlign: "center", fontFamily: "'Share Tech Mono',monospace", fontSize: 11, color: "var(--text3)" }}>Loading sites…</div>
          ) : filtered.length === 0 ? (
            <div style={{ padding: "24px", textAlign: "center", fontFamily: "'Share Tech Mono',monospace", fontSize: 11, color: "var(--text3)" }}>No sites found</div>
          ) : (
            <table>
              <thead><tr><th>Status</th><th>Name</th><th>Domains</th><th>Mode</th><th>WAF Policy</th><th>State</th><th>Actions</th></tr></thead>
              <tbody>
                {filtered.map(s => {
                  const mode  = s.waf_policy?.mode?.toUpperCase() ?? "—";
                  const stDot = s.status === "active" ? "g" : "r";
                  const meta  = LAB_META[s.name];
                  return (
                    <tr key={s.id}>
                      <td><div className={`sd ${stDot}`} /></td>
                      <td>
                        <span style={{ color: meta ? (s.name === "dvwa.local" ? "var(--red-b)" : "var(--cyan)") : "var(--cyan)", fontWeight: meta ? 700 : 400 }}>
                          {meta ? `${meta.icon} ` : ""}{s.name}
                        </span>
                      </td>
                      <td>{s.domains.join(", ")}</td>
                      <td><span className={`bdg ${mode === "BLOCKING" ? "br" : mode === "LEARNING" ? "ba blink" : "bgr"}`}><span className="bdr" />{mode}</span></td>
                      <td className="td3">paranoia {s.waf_policy?.paranoia_level ?? "—"}</td>
                      <td><span className={`bdg ${s.status === "active" ? "bgg" : "bgr"}`}>{s.status}</span></td>
                      <td>
                        <div style={{ display: "flex", gap: 4 }}>
                          <button className="btn bg-btn btn-xs" onClick={() => router.push(`/logs?site=${s.name}&tab=waf`)}>🛡️</button>
                          <button className="btn bg-btn btn-xs" onClick={() => router.push(`/logs?site=${s.name}`)}>📜 Logs</button>
                          <button
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
                          >{s.status === "active" ? "⏸️" : "▶️"}</button>
                          <button
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
                          >🗑️</button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
