"use client";
import { useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import { showToast } from "@/components/ui/Toast";
import { api, type GlobalSetting, type GlobalSettingsResponse } from "@/lib/api";
import { staggerContainer, fadeUp } from "@/lib/animations";

// ---------------------------------------------------------------------------
// Global Settings — node-wide values, in one place, each with its provenance.
//
// Two halves. The top half is EDITABLE: alert thresholds and threat-intel
// feeds, stored in the control plane and picked up live by the subsystems.
// Until this page existed they were environment variables — change one and you
// edited .env, recreated the container, and left no audit row. The bottom half
// is READ-ONLY: the data plane's own configuration (listeners, TLS floor,
// HTTP/3, logging, storage, eBPF, admission limits). That is the node's YAML
// file; it changes with a restart, and this page is the first place it has
// ever been visible from the console.
// ---------------------------------------------------------------------------

const GROUP_META: Record<string, { title: string; blurb: string }> = {
  alerting:     { title: "Alerting",            blurb: "When the event stream becomes an alert, and when an alert closes itself." },
  threat_intel: { title: "Threat intelligence", blurb: "External indicator feeds merged into the corpus the data plane enforces." },
  geoip:        { title: "GeoIP database",      blurb: "The country database behind GeoIP rules, fetched monthly. IP Geolocation by DB-IP (CC BY 4.0)." },
};

function SourcePill({ s }: { s: GlobalSetting["source"] }) {
  const map = {
    db:      { label: "set here",   bg: "var(--green-t)",  fg: "var(--green)",  tip: "Operator override stored in the control plane" },
    env:     { label: "from env",   bg: "var(--amber-t)",  fg: "var(--amber)",  tip: "Comes from the control plane's environment variable" },
    default: { label: "default",    bg: "var(--gray-t)", fg: "var(--text3)",  tip: "Built-in default" },
  }[s];
  return <span className="bdg" title={map.tip} style={{ textTransform: "none", background: map.bg, color: map.fg }}>{map.label}</span>;
}

function fmtVal(v: unknown, unit?: string): string {
  if (v === null || v === undefined || v === "") return "—";
  if (typeof v === "boolean") return v ? "on" : "off";
  if (unit === "seconds" && typeof v === "number") {
    if (v < 0) return "disabled";
    if (v % 3600 === 0) return `${v / 3600} h`;
    if (v % 60 === 0) return `${v / 60} min`;
    return `${v} s`;
  }
  return String(v);
}

export default function GlobalSettingsPage() {
  const [data, setData]       = useState<GlobalSettingsResponse | null>(null);
  const [err, setErr]         = useState<string | null>(null);
  const [draft, setDraft]     = useState<Record<string, unknown>>({});
  const [saving, setSaving]   = useState(false);
  const [showRaw, setShowRaw] = useState(false);

  async function load() {
    try { setData(await api.globalSettings.get()); setErr(null); }
    catch (e) { setErr(e instanceof Error ? e.message : String(e)); }
  }
  useEffect(() => { load(); }, []);

  const byGroup = useMemo(() => {
    const m = new Map<string, GlobalSetting[]>();
    for (const s of data?.editable ?? []) m.set(s.group, [...(m.get(s.group) ?? []), s]);
    return m;
  }, [data]);

  const dirty = Object.keys(draft).length > 0;

  function setField(k: GlobalSetting, raw: string | boolean) {
    let v: unknown = raw;
    if (k.type === "int") {
      if (raw === "" ) { const n = { ...draft }; delete n[k.key]; setDraft(n); return; }
      const n = Number(raw);
      if (!Number.isFinite(n)) return;
      v = Math.trunc(n);
    }
    // Unchanged from effective → drop from the draft.
    if (v === k.value) { const n = { ...draft }; delete n[k.key]; setDraft(n); return; }
    setDraft(d => ({ ...d, [k.key]: v }));
  }

  async function save() {
    if (!dirty) return;
    setSaving(true);
    try {
      const r = await api.globalSettings.put(draft);
      setData(d => d ? { ...d, editable: r.editable } : d);
      setDraft({});
      showToast(`Saved ${Object.keys(draft).length} setting${Object.keys(draft).length === 1 ? "" : "s"} · ${r.applied}`, "s");
    } catch (e) {
      showToast(`Not saved: ${e instanceof Error ? e.message : String(e)}`, "e");
    } finally { setSaving(false); }
  }

  async function reset(k: GlobalSetting) {
    try {
      const r = await api.globalSettings.reset(k.key);
      setData(d => d ? { ...d, editable: r.editable } : d);
      const n = { ...draft }; delete n[k.key]; setDraft(n);
      showToast(`${k.key} reset to its ${k.env ? "environment or default" : "default"} value`, "s");
    } catch (e) {
      showToast(`Reset failed: ${e instanceof Error ? e.message : String(e)}`, "e");
    }
  }

  const dp = data?.dataplane;
  const cfg = (dp?.config ?? {}) as Record<string, unknown>;
  const listeners = (cfg.listeners as Array<Record<string, unknown>> | undefined) ?? [];
  const logging   = (cfg.logging as Record<string, unknown> | undefined) ?? {};
  const limits    = (cfg.limits  as Record<string, unknown> | undefined) ?? {};
  // Effective eBPF/XDP state, taken from the NODE and not from the file.
  //
  // Two facts make the file useless here. First, `ebpf.enable`/`ebpf.programs`
  // in the YAML have zero consumers in the data plane — the manager is built
  // entirely from SENTINEL_XDP_* environment variables — so this card was
  // rendering an inert key and reported "off" on a node running kernel XDP with
  // 11 million packets passed. Second, there is no "off" state to report at all:
  // EbpfMode is Kernel or Software, and the userspace software fast-fail always
  // runs. Claiming "off" was doubly wrong.
  //
  // The pair that matters is mode vs kernel_requested. Requested-but-software
  // means the kernel program did not attach and the DDoS path is running in
  // userspace — the silent degradation this row now has to make visible.
  const rt        = (dp?.runtime as Record<string, unknown> | undefined) ?? undefined;
  const rtEbpf    = (rt?.ebpf as Record<string, unknown> | undefined) ?? undefined;
  const ebpfState = (() => {
    if (!rtEbpf) return dp?.reachable ? "unknown — node did not report" : "unknown — node unreachable";
    const mode     = String(rtEbpf.mode ?? "");
    const iface    = String(rtEbpf.interface ?? "");
    const wanted   = rtEbpf.kernel_requested === true;
    const passed   = Number(rtEbpf.xdp_pass ?? 0);
    const dropped  = Number(rtEbpf.xdp_drop ?? 0);
    const counters = `${passed.toLocaleString()} passed · ${dropped.toLocaleString()} dropped`;
    if (mode === "kernel-xdp") {
      return `kernel XDP${iface ? ` on ${iface}` : ""} · ${counters}`;
    }
    if (mode === "software") {
      return wanted
        ? `software fallback — kernel XDP requested but did not attach · ${counters}`
        : `software fast-fail — kernel XDP not enabled · ${counters}`;
    }
    return mode ? `${mode} · ${counters}` : "unknown — node did not report";
  })();
  const cluster   = (cfg.cluster as Record<string, unknown> | undefined) ?? {};
  const storage   = (cfg.storage as Record<string, unknown> | undefined) ?? {};
  const tlsOf = (l: Record<string, unknown>) => (l.tls as Record<string, unknown> | null | undefined) ?? null;

  return (
    <motion.div className="sec" variants={staggerContainer} initial="hidden" animate="visible">
      <motion.div variants={fadeUp} style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 14 }}>
        <div>
          <div className="sec-title">Global Settings</div>
          <div className="sec-sub">Node-wide values with their source · editable ones apply live · the data plane&apos;s own file is shown read-only</div>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button className="btn bg-btn btn-sm" onClick={load}>⟳ Refresh</button>
          <motion.button className="btn bp btn-sm" disabled={!dirty || saving} onClick={save} whileTap={{ scale: 0.97 }}>
            {saving ? "Saving…" : dirty ? `Save ${Object.keys(draft).length} change${Object.keys(draft).length === 1 ? "" : "s"}` : "No changes"}
          </motion.button>
        </div>
      </motion.div>

      {err && (
        <motion.div variants={fadeUp} className="code-block" style={{ borderLeft: "3px solid var(--red-b)" }}>
          <span style={{ color: "var(--red-b)" }}>● COULD NOT LOAD SETTINGS</span> — {err}
        </motion.div>
      )}
      {data && !data.db_available && (
        <motion.div variants={fadeUp} className="code-block" style={{ borderLeft: "3px solid var(--amber)" }}>
          <span style={{ color: "var(--amber)" }}>● READ-ONLY</span> — the control plane has no database, so operator overrides cannot be stored. Values shown come from the environment and defaults.
        </motion.div>
      )}

      {Array.from(byGroup.entries()).map(([group, items]) => {
        const meta = GROUP_META[group] ?? { title: group, blurb: "" };
        return (
          <motion.div key={group} className="panel" variants={fadeUp}>
            <div className="ph">
              <div className="ptitle">{meta.title}</div>
              <span className="td3" style={{ fontSize: 12.5 }}>{meta.blurb}</span>
            </div>
            <div className="tw">
              <table>
                <thead><tr><th style={{ width: "34%" }}>Setting</th><th>Value</th><th>Source</th><th>Applies</th><th></th></tr></thead>
                <tbody>
                  {items.map(k => {
                    const pending = k.key in draft;
                    const cur = pending ? draft[k.key] : k.value;
                    return (
                      <tr key={k.key} style={pending ? { background: "var(--accent-tint)" } : undefined}>
                        <td>
                          <div style={{ fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--cyan)" }}>{k.key}</div>
                          <div className="td3" style={{ fontSize: 12.5, whiteSpace: "normal", lineHeight: 1.45, marginTop: 2 }}>{k.description}</div>
                          {k.env && <div className="td3" style={{ fontSize: 11, fontFamily: "var(--font-mono)", marginTop: 2 }}>env {k.env}</div>}
                        </td>
                        <td style={{ minWidth: 220 }}>
                          {k.type === "bool" ? (
                            <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer" }}>
                              <div className={`tog ${cur ? "on" : ""}`} onClick={() => setField(k, !cur)} />
                              <span className="td3" style={{ fontSize: 13 }}>{cur ? "on" : "off"}</span>
                            </label>
                          ) : k.type === "int" ? (
                            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                              <input className="fin2" type="number" value={String(cur ?? "")} onChange={e => setField(k, e.target.value)} style={{ width: 130 }} />
                              <span className="td3" style={{ fontSize: 12, fontFamily: "var(--font-sans)" }}>{k.unit === "seconds" ? fmtVal(cur, "seconds") : k.unit ?? ""}</span>
                            </div>
                          ) : (
                            <input className="fin2" type="text" value={String(cur ?? "")} onChange={e => setField(k, e.target.value)} placeholder={k.unit === "url" ? "https://… or off" : ""} style={{ width: "100%", fontFamily: "var(--font-mono)", fontSize: 12.5 }} />
                          )}
                          {pending && <div className="td3" style={{ fontSize: 11, marginTop: 3 }}>was {fmtVal(k.value, k.unit)} · unsaved</div>}
                        </td>
                        <td><SourcePill s={k.source} />{k.updated_at && <div className="td3" style={{ fontSize: 11, marginTop: 3 }}>{new Date(k.updated_at).toLocaleString()}</div>}</td>
                        <td className="td3" style={{ fontSize: 12.5 }}>{k.applies}</td>
                        <td>{k.source === "db" && <button className="btn bg-btn btn-xs" title="Drop the override; fall back to env or default" onClick={() => reset(k)}>↺ Reset</button>}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </motion.div>
        );
      })}

      <motion.div className="panel" variants={fadeUp}>
        <div className="ph">
          <div className="ptitle">Data plane node <span className="bdg ba" style={{ marginLeft: 8, textTransform: "none" }}>read-only · restart to change</span></div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            {dp?.reachable && <span className="td3" style={{ fontSize: 12.5 }}>data plane {String(cfg.version ?? "")} · {String(cfg.site_count ?? 0)} sites</span>}
            <button className="btn bg-btn btn-xs" onClick={() => setShowRaw(v => !v)}>{showRaw ? "Hide raw" : "Raw JSON"}</button>
          </div>
        </div>
        <div className="pb" style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          {!dp ? (
            <div className="td3" style={{ fontFamily: "var(--font-sans)", fontSize: 13 }}>Loading…</div>
          ) : !dp.reachable ? (
            <div className="code-block" style={{ borderLeft: "3px solid var(--red-b)" }}>
              <span style={{ color: "var(--red-b)" }}>● DATA PLANE UNREACHABLE</span> — {dp.error}. Nothing below is known.
            </div>
          ) : (
            <>
              <div className="td3" style={{ fontSize: 12.5, lineHeight: 1.5 }}>
                These values come from the node&apos;s configuration file and take effect at start-up. To change one, edit the file on the node
                (<span style={{ fontFamily: "var(--font-mono)" }}>sentinel.proxy.yaml</span> in the standard deployment) and restart the data plane.
                Secrets are redacted before they leave the node.
              </div>

              <div className="tw">
                <table>
                  <thead><tr><th>Listener</th><th>Bind</th><th>Protocols</th><th>TLS floor</th><th>Role</th><th>Default site</th></tr></thead>
                  <tbody>
                    {listeners.map((l, i) => {
                      const tls = tlsOf(l);
                      return (
                        <tr key={i}>
                          <td style={{ fontFamily: "var(--font-mono)" }}>{String(l.name)}</td>
                          <td className="td3" style={{ fontFamily: "var(--font-mono)" }}>{String(l.bind)}</td>
                          <td className="td3">{Array.isArray(l.protocol) ? (l.protocol as unknown[]).join(", ") : String(l.protocol ?? "")}</td>
                          <td className="td3">{tls ? `${String(tls.min_version ?? "")}${tls.post_quantum && tls.post_quantum !== "off" ? ` · PQ ${String(tls.post_quantum)}` : ""}` : "plaintext"}</td>
                          <td className="td3">{String(l.role ?? "")}</td>
                          <td className="td3">{String(l.default_site ?? "—")}</td>
                        </tr>
                      );
                    })}
                    {listeners.length === 0 && <tr><td colSpan={6} className="td3">no listeners reported</td></tr>}
                  </tbody>
                </table>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(230px, 1fr))", gap: 12 }}>
                {[
                  ["Logging", `${String(logging.level ?? "—")} · ${String(logging.format ?? "")} · ${Array.isArray(logging.outputs) ? (logging.outputs as unknown[]).length : 0} output(s)`],
                  ["Admission limits", `${String(limits.max_connections ?? "—")} connections · ${String(limits.max_inflight_requests ?? "—")} in-flight`],
                  ["eBPF / XDP", ebpfState],
                  ["Control-plane sync", `${String(cluster.sync_url ?? "—")} · every ${String(cluster.sync_interval_secs ?? "—")} s`],
                  ["Cache / KV", `${String((storage.cache as Record<string, unknown> | undefined)?.backend ?? "—")} ${String((storage.cache as Record<string, unknown> | undefined)?.size ?? "")} · kv ${String((storage.kv as Record<string, unknown> | undefined)?.backend ?? "—")}`],
                  ["Cert directory", String(cfg.cert_dir ?? "default")],
                ].map(([label, val]) => (
                  <div key={label} style={{ border: "1px solid var(--border)", borderRadius: 6, padding: "10px 12px" }}>
                    <div className="td3" style={{ fontSize: 11 }}>{label}</div>
                    <div style={{ fontFamily: "var(--font-mono)", fontSize: 13, marginTop: 4, wordBreak: "break-all" }}>{val}</div>
                  </div>
                ))}
              </div>

              {showRaw && <pre className="code-block" style={{ maxHeight: 420, overflow: "auto", fontSize: 12 }}>{JSON.stringify(cfg, null, 2)}</pre>}
            </>
          )}
        </div>
      </motion.div>
    </motion.div>
  );
}
