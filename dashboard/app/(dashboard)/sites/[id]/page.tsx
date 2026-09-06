"use client";
/**
 * Client Services — per-site management dashboard.
 * Everything here is real: site config from the control plane, per-site
 * request/block counters from the proxy NDJSON stream, live WAF/access logs
 * filtered to this site, the certificate from the /certs API, and a
 * learning↔blocking↔off mode control that hot-applies in ~5s.
 */
import { useState, useEffect, useMemo, useCallback } from "react";
import { useParams, useRouter } from "next/navigation";
import { motion, AnimatePresence } from "framer-motion";
import { showToast } from "@/components/ui/Toast";
import { api, type Site, type Certificate, type SiteStat, type LearningStat, type EffectiveConfig } from "@/lib/api";
import { staggerContainer, cardVariants, fadeUp } from "@/lib/animations";
import SiteWizard from "@/components/sites/SiteWizard";
import { siteToForm, type SiteForm, type PathOverride, CRS_REQUEST_CATEGORIES, ALL_CRS_RESPONSE_KEYS } from "@/lib/siteConfig";

type WafRow = { ts: string; ip: string; rule: string; attack: string; sev: string; action: string };
type AccessRow = { ts: string; ip: string; method: string; path: string; status: number; latency: number };
type Tab = "overview" | "waf" | "access" | "learning" | "paths" | "cert" | "config";

const MODES = [
  { key: "off",      label: "Off",      desc: "WAF disabled — pass-through",         color: "var(--text3)" },
  { key: "learning", label: "Learning", desc: "Log only · no traffic impact",        color: "var(--amber, #ffb020)" },
  { key: "blocking", label: "Blocking", desc: "Enforce · block malicious requests",  color: "#ef4444" },
] as const;

function timePart(ts: unknown): string {
  const s = String(ts ?? "");
  const m = s.match(/(\d{2}:\d{2}:\d{2})/);
  return m ? m[1] : new Date().toTimeString().slice(0, 8);
}

export default function SiteDetailPage() {
  const params = useParams();
  const router = useRouter();
  const siteId = String(params.id);

  const [site, setSite] = useState<Site | null>(null);
  const [form, setForm] = useState<SiteForm | null>(null);
  const [stat, setStat] = useState<SiteStat | null>(null);
  const [certs, setCerts] = useState<Certificate[]>([]);
  const [wafLogs, setWafLogs] = useState<WafRow[]>([]);
  const [accessLogs, setAccessLogs] = useState<AccessRow[]>([]);
  const [learn, setLearn] = useState<LearningStat[]>([]);
  const [learnBusy, setLearnBusy] = useState<number | null>(null);
  const [tab, setTab] = useState<Tab>("overview");
  // Pushed-vs-held config, fetched when the tab opens and on demand.
  const [eff, setEff] = useState<EffectiveConfig | null>(null);
  const [effErr, setEffErr] = useState<string | null>(null);
  const loadEffective = useCallback(async () => {
    try { setEff(await api.sites.effective(siteId)); setEffErr(null); }
    catch (e) { setEffErr(e instanceof Error ? e.message : String(e)); }
  }, [siteId]);
  useEffect(() => { if (tab === "config") loadEffective(); }, [tab, loadEffective]);
  const [pathBusy, setPathBusy] = useState(false);
  const [busy, setBusy] = useState(false);
  const [editing, setEditing] = useState(false);
  const [loading, setLoading] = useState(true);

  const loadSite = useCallback(async () => {
    try {
      const res = await api.sites.get(siteId);
      setSite(res.site);
      setForm(siteToForm(res.site));
    } catch {
      showToast("Failed to load site", "e", "⚠️");
    } finally { setLoading(false); }
  }, [siteId]);

  useEffect(() => { loadSite(); }, [loadSite]);
  useEffect(() => { api.certs.list().then(r => setCerts(r.certs ?? [])).catch(() => {}); }, []);

  // Per-site cumulative counters (real, from the hub).
  useEffect(() => {
    if (!site) return;
    let cancelled = false;
    async function f() {
      try {
        const r = await api.metrics.sites();
        if (!cancelled && site) setStat(r.sites?.[site.name] ?? { total: 0, blocked: 0, status_4xx: 0, status_5xx: 0 });
      } catch { /* control plane down */ }
    }
    f(); const t = setInterval(f, 5_000); return () => { cancelled = true; clearInterval(t); };
  }, [site]);

  // Live WAF + access logs filtered to this site.
  useEffect(() => {
    if (!site) return;
    const match = (s: unknown) => { const v = String(s ?? ""); return v === site.name || site.domains.includes(v); };
    const wafES = new EventSource(api.logs.streamURL("waf"));
    wafES.onmessage = (evt) => {
      try {
        const e: { data: Record<string, unknown> } = JSON.parse(evt.data);
        if (!e.data || !match(e.data.site)) return;
        setWafLogs(p => [{ ts: timePart(e.data.ts), ip: String(e.data.ip ?? ""), rule: String(e.data.rule ?? "-"), attack: String(e.data.attack ?? ""), sev: String(e.data.sev ?? ""), action: String(e.data.action ?? "") }, ...p].slice(0, 40));
      } catch { /* */ }
    };
    const accES = new EventSource(api.logs.streamURL("access"));
    accES.onmessage = (evt) => {
      try {
        const e: { data: Record<string, unknown> } = JSON.parse(evt.data);
        if (!e.data || !match(e.data.site)) return;
        setAccessLogs(p => [{ ts: timePart(e.data.ts), ip: String(e.data.ip ?? ""), method: String(e.data.method ?? "GET"), path: String(e.data.path ?? "/"), status: Number(e.data.status ?? 0), latency: parseFloat(String(e.data.latency ?? 0)) }, ...p].slice(0, 40));
      } catch { /* */ }
    };
    return () => { wafES.close(); accES.close(); };
  }, [site]);

  // Learning-mode would-have-blocked aggregation (polled while the tab is open).
  useEffect(() => {
    if (!site || tab !== "learning") return;
    let cancelled = false;
    async function f() {
      try {
        const r = await api.metrics.learning(site!.name);
        if (!cancelled) setLearn(r.rules ?? []);
      } catch { /* control plane down */ }
    }
    f(); const t = setInterval(f, 5_000); return () => { cancelled = true; clearInterval(t); };
  }, [site, tab]);

  const mode = site?.waf_policy?.mode ?? "blocking";
  // Rule IDs currently excluded on this site (from the persisted waf_policy).
  const excludedIds = useMemo(
    () => new Set((form?.rule_exclusions ?? []).map(e => String(e.rule_id))),
    [form]
  );

  async function disableRule(ruleId: string) {
    if (!site) return;
    const id = Number(ruleId);
    if (!Number.isFinite(id) || id === 0) { showToast("Rule has no numeric ID", "e", "⚠️"); return; }
    setLearnBusy(id);
    try {
      await api.sites.addExclusion(siteId, { rule_id: id });
      showToast(`Rule ${ruleId} disabled · applies in ~5s`, "s", "🔕");
      await loadSite();
    } catch (e) { showToast(e instanceof Error ? e.message : "Failed", "e", "⚠️"); }
    finally { setLearnBusy(null); }
  }

  /** Persist the path-override list.
   *
   *  Sent as a merge into the existing waf_policy so nothing else on the site is
   *  disturbed. Incomplete rows are dropped rather than sent: the API refuses an
   *  override that sets neither mode nor threshold, and a half-typed row should
   *  not fail the operator's whole save. */
  async function savePathOverrides() {
    if (!site || !form) return;
    setPathBusy(true);
    try {
      const clean = (form.path_overrides ?? [])
        .filter(o => o.path_prefix.trim() !== "")
        .map(o => {
          const out: Record<string, unknown> = { path_prefix: o.path_prefix.trim() };
          if (o.mode) out.mode = o.mode;
          if (o.anomaly_threshold !== "" && o.anomaly_threshold !== undefined) {
            out.anomaly_threshold = Number(o.anomaly_threshold);
          }
          return out;
        })
        .filter(o => o.mode !== undefined || o.anomaly_threshold !== undefined);

      await api.sites.update(siteId, {
        waf_policy: { ...(site.waf_policy as object), path_overrides: clean },
      });
      showToast(
        clean.length ? `${clean.length} path override(s) saved` : "Path overrides cleared",
        "s", "🛣",
      );
      await loadSite();
    } catch (err: unknown) {
      // The API validates prefixes and rejects per-path paranoia_level /
      // rule_exclusions, so surface its message rather than a generic failure.
      showToast(err instanceof Error ? err.message : "Could not save path overrides", "e", "⚠️");
    } finally { setPathBusy(false); }
  }

  async function reEnableRule(ruleId: string) {
    if (!site) return;
    const id = Number(ruleId);
    setLearnBusy(id);
    try {
      await api.sites.removeExclusion(siteId, id);
      showToast(`Rule ${ruleId} re-enabled · applies in ~5s`, "s", "🔔");
      await loadSite();
    } catch (e) { showToast(e instanceof Error ? e.message : "Failed", "e", "⚠️"); }
    finally { setLearnBusy(null); }
  }

  const cert = useMemo(() => {
    if (!site) return undefined;
    return certs.find(c => site.domains.includes(c.domain) || (c.san ?? []).some(s => site.domains.includes(s)));
  }, [certs, site]);

  async function setMode(newMode: string) {
    if (!site || busy || newMode === mode) return;
    setBusy(true);
    try {
      await api.sites.update(siteId, { waf_policy: { ...(site.waf_policy as object), mode: newMode } });
      showToast(`Mode → ${newMode.toUpperCase()} · applies in ~5s`, "s", newMode === "blocking" ? "🛡️" : newMode === "learning" ? "📚" : "⏸️");
      await loadSite();
    } catch (e) { showToast(e instanceof Error ? e.message : "Failed", "e", "⚠️"); }
    finally { setBusy(false); }
  }

  async function toggleStatus() {
    if (!site) return;
    const next = site.status === "active" ? "paused" : "active";
    try { await api.sites.updateStatus(siteId, next); showToast(`Site ${next}`, "s", next === "active" ? "✅" : "⏸️"); await loadSite(); }
    catch { showToast("Failed", "e", "⚠️"); }
  }

  async function del() {
    if (!site || !confirm(`Delete site "${site.name}"? This cannot be undone.`)) return;
    try { await api.sites.delete(siteId); showToast("Site deleted", "s", "🗑️"); router.push("/sites"); }
    catch { showToast("Failed to delete", "e", "⚠️"); }
  }

  if (loading) return <div className="sec"><div style={{ padding: 40, textAlign: "center", color: "var(--text3)", fontFamily: "var(--font-mono)", fontSize: 14 }}>Loading site…</div></div>;
  if (!site || !form) return <div className="sec"><div style={{ padding: 40, textAlign: "center", color: "var(--text3)" }}>Site not found. <button className="btn bg-btn btn-sm" onClick={() => router.push("/sites")}>← Back</button></div></div>;

  const scheme = form.front_https ? "https" : "http";
  const blockRate = stat && stat.total > 0 ? (stat.blocked / stat.total) * 100 : 0;
  const certDays = cert && cert.expires_at > 0 ? Math.round((cert.expires_at * 1000 - Date.now()) / 86400000) : null;

  return (
    <motion.div className="sec" variants={staggerContainer} initial="hidden" animate="visible">

      {/* Header */}
      <motion.div variants={fadeUp} style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 14 }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <button onClick={() => router.push("/sites")} style={{ background: "none", border: "none", color: "var(--text3)", cursor: "pointer", fontSize: 13, padding: 0, textAlign: "left", fontFamily: "var(--font-mono)" }}>← All sites</button>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div className="sec-title">{site.name}</div>
            <span className={`bdg ${site.status === "active" ? "bgg" : "bgr"}`}>{site.status}</span>
          </div>
          <div className="sec-sub" style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            {site.domains.map(d => <a key={d} href={`${scheme}://${d}:9080/`} target="_blank" rel="noreferrer" style={{ color: "var(--cyan)", fontFamily: "var(--font-mono)", fontSize: 13 }}>{scheme}://{d} ↗</a>)}
          </div>
        </div>
        <div style={{ display: "flex", gap: 8, flexShrink: 0 }}>
          <button className="btn bc btn-sm" onClick={() => setEditing(true)}>✏️ Edit</button>
          <button className="btn bg-btn btn-sm" onClick={toggleStatus}>{site.status === "active" ? "⏸️ Pause" : "▶️ Activate"}</button>
          <button className="btn bg-btn btn-sm" onClick={del} style={{ color: "#ef4444" }}>🗑️ Delete</button>
        </div>
      </motion.div>

      {/* Mode control — the learning→blocking workflow */}
      <motion.div className="panel" variants={fadeUp}>
        <div className="ph"><div className="ptitle">WAF Enforcement Mode</div><span className="panel-badge pb-info">applies live ~5s</span></div>
        <div className="pb" style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 12 }}>
          {MODES.map(m => {
            const active = mode === m.key;
            return (
              <div key={m.key} onClick={() => setMode(m.key)} style={{
                cursor: busy ? "wait" : "pointer", padding: "14px 16px", borderRadius: 12,
                background: active ? "color-mix(in srgb, " + m.color + " 14%, transparent)" : "var(--bg3)",
                border: `1.5px solid ${active ? m.color : "var(--bg4)"}`, opacity: busy ? 0.7 : 1, transition: "all .15s",
              }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <span style={{ fontWeight: 700, fontSize: 16, color: active ? m.color : "var(--text2)", fontFamily: "var(--font-display)" }}>{m.label}</span>
                  {active && <span style={{ width: 10, height: 10, borderRadius: "50%", background: m.color }} />}
                </div>
                <div style={{ fontSize: 14, color: "var(--text3)", marginTop: 6, lineHeight: 1.5 }}>{m.desc}</div>
              </div>
            );
          })}
        </div>
        {mode === "learning" && (
          <div className="pb" style={{ paddingTop: 0 }}>
            <div style={{ padding: "9px 13px", background: "rgba(255,176,32,.08)", border: "1px solid rgba(255,176,32,.25)", borderRadius: "var(--r2)", fontSize: 12.5, color: "var(--text3)", fontFamily: "var(--font-mono)", lineHeight: 1.6 }}>
              📚 In Learning mode the WAF logs what it <strong>would</strong> block without affecting traffic. Watch the <strong>WAF Logs</strong> tab below, then switch to <strong>Blocking</strong> when false-positives are tuned out.
            </div>
          </div>
        )}
      </motion.div>

      {/* Per-site KPIs (real) */}
      <motion.div variants={staggerContainer} style={{ display: "grid", gridTemplateColumns: "repeat(5,1fr)", gap: 12 }}>
        {[
          { lbl: "Requests", val: stat ? stat.total.toLocaleString() : "—", ico: "📡", accent: "var(--text)" },
          { lbl: "Blocked", val: stat ? stat.blocked.toLocaleString() : "—", ico: "🛑", accent: "#ef4444" },
          { lbl: "Block rate", val: stat ? `${blockRate.toFixed(1)}%` : "—", ico: "📊", accent: "var(--cyan)" },
          { lbl: "4xx / 5xx", val: stat ? `${stat.status_4xx} / ${stat.status_5xx}` : "—", ico: "⚠️", accent: "var(--amber,#ffb020)" },
          { lbl: "Certificate", val: cert ? (certDays !== null ? `${certDays}d` : "active") : "none", ico: "🔐", accent: cert ? "var(--green)" : "var(--text3)" },
        ].map((k, i) => (
          <motion.div key={i} className="panel" variants={cardVariants} style={{ padding: "13px 15px" }}>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span style={{ fontSize: 14, color: "var(--text3)", textTransform: "uppercase", letterSpacing: 1, fontFamily: "var(--font-mono)" }}>{k.lbl}</span>
              <span style={{ fontSize: 15 }}>{k.ico}</span>
            </div>
            <div style={{ fontSize: 25, fontWeight: 700, color: k.accent, marginTop: 6, fontFamily: "var(--font-display)" }}>{k.val}</div>
          </motion.div>
        ))}
      </motion.div>

      {/* Tabs */}
      <motion.div variants={fadeUp} style={{ display: "flex", gap: 4, padding: 4, background: "var(--bg3)", borderRadius: 10, width: "fit-content" }}>
        {([["overview", "🗂 Overview"], ["waf", "🛡️ WAF Logs"], ["access", "📡 Access Logs"], ["learning", "📚 Learning Report"], ["paths", "🛣 Path Policy"], ["cert", "🔐 Certificate"], ["config", "🧾 Effective Config"]] as [Tab, string][]).map(([k, label]) => (
          <button key={k} onClick={() => setTab(k)} style={{
            padding: "7px 16px", borderRadius: 7, border: "none", cursor: "pointer", fontSize: 14, fontWeight: 600,
            background: tab === k ? "var(--cyan)" : "transparent", color: tab === k ? "#021018" : "var(--text2)",
          }}>{label}</button>
        ))}
      </motion.div>

      <AnimatePresence mode="wait">
        <motion.div key={tab} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.15 }}>

          {/* OVERVIEW — rich config */}
          {tab === "overview" && (
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
              <ConfigCard title="Reverse Proxy">
                <KV k="Load balancer" v={form.lb} />
                {form.servers.map((s, i) => <KV key={i} k={`Upstream #${i + 1}`} v={`${s.tls ? "https" : "http"}://${s.host}:${s.port} · w${s.weight}`} />)}
                <KV k="Health checks" v={form.health.enabled ? `${form.health.path} every ${form.health.interval}` : "off"} />
                <KV k="WebSocket" v={form.proxy_websocket ? "on" : "off"} />
              </ConfigCard>
              <ConfigCard title="WAF Rules">
                <KV k="Paranoia level" v={`PL${form.paranoia_level}`} />
                <KV k="Anomaly threshold" v={String(form.anomaly_threshold)} />
                <KV k="Request inspection" v={`${form.rule_categories.filter(k => !ALL_CRS_RESPONSE_KEYS.includes(k)).length}/${CRS_REQUEST_CATEGORIES.length} categories`} />
                <KV k="Response inspection" v={(() => {
                  const n = form.rule_categories.filter(k => ALL_CRS_RESPONSE_KEYS.includes(k)).length;
                  return n === 0 ? "off" : `${n}/${ALL_CRS_RESPONSE_KEYS.length} categories`;
                })()} />
                <KV k="Rule exclusions" v={`${form.rule_exclusions.length}`} />
                <KV k="Path overrides" v={`${(form.path_overrides ?? []).length}`} />
                <KV k="ML anomaly" v={form.ml_enabled ? `on (${form.ml_sensitivity})` : "off"} />
              </ConfigCard>
              <ConfigCard title="Rate & DDoS">
                <KV k="Rate limit" v={form.rate_limit_enabled ? `${form.rl_per_ip.rps}/s per IP · ${form.rl_global.rps}/s global` : "off"} />
                <KV k="Anti-DDoS" v={form.antiddos_enabled ? `${form.antiddos_conn_rate} conn/s · block ${form.antiddos_block_secs}s` : "off"} />
                <KV k="Max body" v={`${form.max_body_size_mb} MB`} />
                <KV k="Allowed methods" v={form.allowed_methods.join(" ")} />
              </ConfigCard>
              <ConfigCard title="Bots · Geo · IP">
                <KV k="JA4 fingerprint" v={form.bot_ja4 ? "on" : "off"} />
                <KV k="Challenge" v={form.bot_challenge} />
                <KV k="GeoIP" v={form.geo_mode === "off" ? "off" : `${form.geo_mode}: ${form.geo_countries.join(", ") || "—"}`} />
                <KV k="IP lists" v={`${form.ip_allow.length} allow · ${form.ip_block.length} block`} />
                <KV k="Blacklists" v={form.dnsbl_enabled ? "DNSBL on" : "off"} />
              </ConfigCard>
              <ConfigCard title="Front Service / TLS">
                <KV k="Public" v={`${scheme}://:${form.front_https ? 9443 : 9080}${form.force_https ? " · force-https" : ""}`} />
                <KV k="HTTP/2 · HTTP/3" v={`${form.http2 ? "h2" : "—"} · ${form.http3 ? "h3" : "—"}`} />
                <KV k="TLS mode" v={form.tls_mode === "auto" ? `auto · ${form.acme_staging ? "staging" : form.acme_provider}` : form.tls_mode} />
                <KV k="HSTS" v={form.hsts ? "on" : "off"} />
              </ConfigCard>
              <ConfigCard title="HTTP Headers">
                <KV k="CSP" v={form.csp || "default"} />
                <KV k="Referrer-Policy" v={form.referrer_policy} />
                <KV k="CORS" v={form.cors_enabled ? form.cors_origins : "off"} />
                <KV k="Custom headers" v={`${form.custom_headers.filter(h => h.name).length}`} />
              </ConfigCard>
            </div>
          )}

          {/* WAF LOGS */}
          {tab === "waf" && (
            <div className="panel">
              <div className="ph"><div className="ptitle">WAF events — {site.name}</div><span className="panel-badge pb-live">● Live</span></div>
              <div className="tw">
                {wafLogs.length === 0 ? <Empty text="No WAF events yet — send traffic through the proxy to populate." /> : (
                  <table><thead><tr><th>Time</th><th>IP</th><th>Rule</th><th>Attack</th><th>Severity</th><th>Action</th></tr></thead>
                    <tbody>{wafLogs.map((r, i) => (
                      <tr key={i}>
                        <td className="td3">{r.ts}</td><td className="td2">{r.ip}</td>
                        <td className="td3">{r.rule}</td>
                        <td style={{ maxWidth: 240, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.attack}</td>
                        <td><span className={`bdg ${r.sev === "CRITICAL" ? "br blink" : r.sev === "HIGH" ? "ba" : "bcy"}`}>{r.sev || "—"}</span></td>
                        <td><span className={`bdg ${r.action === "BLOCK" ? "br" : "ba"}`}>{r.action === "BLOCK" ? "BLOCKED" : "LOGGED"}</span></td>
                      </tr>
                    ))}</tbody>
                  </table>
                )}
              </div>
            </div>
          )}

          {/* ACCESS LOGS */}
          {tab === "access" && (
            <div className="panel">
              <div className="ph"><div className="ptitle">Access log — {site.name}</div><span className="panel-badge pb-live">● Live</span></div>
              <div className="tw">
                {accessLogs.length === 0 ? <Empty text="No requests yet — traffic to this site will appear here in real time." /> : (
                  <table><thead><tr><th>Time</th><th>IP</th><th>Method</th><th>Path</th><th>Status</th><th>Latency</th></tr></thead>
                    <tbody>{accessLogs.map((r, i) => (
                      <tr key={i}>
                        <td className="td3">{r.ts}</td><td className="td2">{r.ip}</td><td className="td3">{r.method}</td>
                        <td style={{ maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.path}</td>
                        <td><span className={`bdg ${r.status === 403 || r.status >= 500 ? "br" : r.status >= 400 ? "ba" : "bgg"}`}>{r.status || "—"}</span></td>
                        <td className="td3">{r.latency ? `${r.latency.toFixed(2)}ms` : "—"}</td>
                      </tr>
                    ))}</tbody>
                  </table>
                )}
              </div>
            </div>
          )}

          {/* LEARNING REPORT — would-have-blocked tuning */}
          {tab === "learning" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              <div style={{
                fontSize: 13, color: "var(--text3)", lineHeight: 1.7, fontFamily: "var(--font-mono)",
                background: "var(--bg3)", borderRadius: 8, padding: "10px 14px",
              }}>
                {mode === "learning"
                  ? <>📚 <strong>Learning mode is on.</strong> Each row is a rule that <strong>would</strong> have blocked traffic but didn&apos;t. Review the sample paths — if a rule is a false positive for your app, <strong>Disable</strong> it, then switch to <strong>Blocking</strong> once the list is clean.</>
                  : <>This report aggregates <strong>would-have-blocked</strong> detections recorded while the site ran in <strong>Learning</strong> mode. Switch the mode control above to <strong>Learning</strong> to collect fresh data without impacting traffic.</>}
              </div>
              <div className="panel">
                <div className="ph">
                  <div className="ptitle">Would-have-blocked by rule — {site.name}</div>
                  <span className="panel-badge">{learn.length} rule{learn.length === 1 ? "" : "s"}</span>
                </div>
                <div className="tw">
                  {learn.length === 0 ? (
                    <Empty text="No would-have-blocked detections recorded yet. Put the site in Learning mode and send traffic." />
                  ) : (
                    <table>
                      <thead><tr><th>Rule</th><th>Category</th><th>Severity</th><th>Count</th><th>Sample paths</th><th>Last seen</th><th style={{ textAlign: "right" }}>Action</th></tr></thead>
                      <tbody>
                        {learn.map((r) => {
                          const excluded = excludedIds.has(r.rule_id);
                          const isBusy = learnBusy === Number(r.rule_id);
                          return (
                            <tr key={r.rule_id} style={excluded ? { opacity: 0.55 } : undefined}>
                              <td className="td3">{r.rule_id}</td>
                              <td><span className="bdg bcy">{r.category || "—"}</span></td>
                              <td><span className={`bdg ${r.severity === "CRITICAL" ? "br" : r.severity === "HIGH" ? "ba" : "bcy"}`}>{r.severity || "—"}</span></td>
                              <td className="td2" style={{ fontWeight: 700 }}>{r.count}</td>
                              <td style={{ maxWidth: 300 }}>
                                <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                                  {r.samples.slice(0, 3).map((p, i) => (
                                    <span key={i} style={{ fontSize: 14, color: "var(--text3)", fontFamily: "var(--font-mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{p}</span>
                                  ))}
                                  {r.samples.length === 0 && <span style={{ fontSize: 14, color: "var(--text3)" }}>—</span>}
                                </div>
                              </td>
                              <td className="td3">{timePart(r.last_seen)}</td>
                              <td style={{ textAlign: "right" }}>
                                {excluded ? (
                                  <button className="btn bg-btn btn-xs" disabled={isBusy} onClick={() => reEnableRule(r.rule_id)}>🔔 Re-enable</button>
                                ) : (
                                  <button className="btn bc btn-xs" disabled={isBusy} onClick={() => disableRule(r.rule_id)}>🔕 Disable rule</button>
                                )}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  )}
                </div>
              </div>

              {/* Active exclusions not (or no longer) appearing in the report. */}
              {(form.rule_exclusions ?? []).length > 0 && (
                <div className="panel">
                  <div className="ph"><div className="ptitle">Active rule exclusions ({form.rule_exclusions.length})</div></div>
                  <div className="tw">
                    <table>
                      <thead><tr><th>Rule</th><th>Scope</th><th style={{ textAlign: "right" }}>Action</th></tr></thead>
                      <tbody>
                        {form.rule_exclusions.map((e) => (
                          <tr key={e.rule_id}>
                            <td className="td3">{e.rule_id}</td>
                            <td className="td2">{e.disable || !e.exclude_targets?.length ? "whole rule disabled" : `targets: ${e.exclude_targets.join(", ")}`}</td>
                            <td style={{ textAlign: "right" }}>
                              <button className="btn bg-btn btn-xs" disabled={learnBusy === e.rule_id} onClick={() => reEnableRule(String(e.rule_id))}>🔔 Re-enable</button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* PATH POLICY — per-path overrides */}
          {tab === "paths" && form && (
            <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
              <div className="panel">
                <div className="ph">
                  <div className="ptitle">Per-path policy overrides</div>
                  <button className="btn bp btn-sm" disabled={pathBusy} onClick={savePathOverrides}>
                    {pathBusy ? "Saving…" : "💾 Save"}
                  </button>
                </div>
                <div className="pb" style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                  <div className="td3" style={{ fontSize: 13, lineHeight: 1.6 }}>
                    One site normally means one policy, which is necessarily wrong somewhere:
                    strict enough for an API is too strict for content pages, and static assets
                    need no inspection at all. These override the site policy
                    (<span style={{ fontFamily: "var(--font-mono)" }}>mode {form.mode} · threshold {form.anomaly_threshold}</span>)
                    for requests whose path starts with the given prefix.
                    <br />
                    <strong>Longest matching prefix wins</strong>, so
                    <span style={{ fontFamily: "var(--font-mono)" }}> /api/admin/ </span>
                    beats <span style={{ fontFamily: "var(--font-mono)" }}>/api/</span> no matter what
                    order they are listed in. Paranoia level and rule exclusions cannot vary by path —
                    they decide which rules get compiled into the engine, so they stay site-wide.
                  </div>

                  {(form.path_overrides ?? []).length === 0 ? (
                    <Empty text="No overrides — every path uses the site policy." />
                  ) : (
                    <div className="tw">
                      <table>
                        <thead><tr><th>Path prefix</th><th>Mode</th><th>Threshold</th><th style={{ textAlign: "right" }}></th></tr></thead>
                        <tbody>
                          {(form.path_overrides ?? []).map((o, i) => (
                            <tr key={i}>
                              <td>
                                <input className="fin2" style={{ width: "100%", minWidth: 160 }}
                                  placeholder="/api/" value={o.path_prefix}
                                  onChange={e => setForm(f => f && ({
                                    ...f,
                                    path_overrides: f.path_overrides.map((x, j) =>
                                      j === i ? { ...x, path_prefix: e.target.value } : x),
                                  }))} />
                              </td>
                              <td>
                                <select className="fin2 fsel2" value={o.mode ?? ""}
                                  onChange={e => setForm(f => f && ({
                                    ...f,
                                    path_overrides: f.path_overrides.map((x, j) =>
                                      j === i ? { ...x, mode: e.target.value as PathOverride["mode"] } : x),
                                  }))}>
                                  <option value="">(inherit site)</option>
                                  <option value="blocking">blocking</option>
                                  <option value="learning">learning — record, do not block</option>
                                  <option value="off">off — exempt this path</option>
                                </select>
                              </td>
                              <td>
                                <input className="fin2" type="number" min={1} style={{ width: 90 }}
                                  placeholder="inherit" value={o.anomaly_threshold ?? ""}
                                  onChange={e => setForm(f => f && ({
                                    ...f,
                                    path_overrides: f.path_overrides.map((x, j) =>
                                      j === i ? { ...x, anomaly_threshold: e.target.value === "" ? "" : Number(e.target.value) } : x),
                                  }))} />
                              </td>
                              <td style={{ textAlign: "right" }}>
                                <button className="btn bg-btn btn-xs"
                                  onClick={() => setForm(f => f && ({
                                    ...f, path_overrides: f.path_overrides.filter((_, j) => j !== i),
                                  }))}>🗑 Remove</button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}

                  <div style={{ display: "flex", gap: 8 }}>
                    <button className="btn bc btn-sm"
                      onClick={() => setForm(f => f && ({
                        ...f, path_overrides: [...(f.path_overrides ?? []), { path_prefix: "", mode: "", anomaly_threshold: "" }],
                      }))}>＋ Add override</button>
                    <button className="btn bg-btn btn-sm"
                      title="Common starting point: exempt static assets, watch a legacy path, tighten the API"
                      onClick={() => setForm(f => f && ({
                        ...f,
                        path_overrides: [
                          { path_prefix: "/assets/", mode: "off",      anomaly_threshold: "" },
                          { path_prefix: "/static/", mode: "off",      anomaly_threshold: "" },
                          { path_prefix: "/api/",    mode: "",         anomaly_threshold: 5 },
                        ],
                      }))}>Suggest a starting set</button>
                  </div>

                  <div className="td3" style={{ fontSize: 12 }}>
                    An override that sets neither mode nor threshold would do nothing and is
                    dropped on save. Changes take effect on the fleet within seconds — no restart.
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* CERTIFICATE */}
          {tab === "config" && (
            <EffectiveConfigPanel eff={eff} err={effErr} onRefresh={loadEffective} />
          )}

          {tab === "cert" && (
            <div className="panel">
              <div className="ph"><div className="ptitle">TLS Certificate</div></div>
              <div className="pb">
                {!cert ? (
                  <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                    <Empty text="No certificate installed for this site's domains." />
                    <div style={{ fontSize: 13, color: "var(--text3)", lineHeight: 1.7, fontFamily: "var(--font-mono)" }}>
                      Configure TLS in <button className="btn bg-btn btn-xs" onClick={() => setEditing(true)}>✏️ Edit → Front Service</button>. With automatic ACME, a cert is requested on save (once DNS points here). Self-signed is served until then.
                    </div>
                  </div>
                ) : (
                  <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                      <KV k="Domain" v={cert.domain} />
                      <KV k="Source" v={typeof cert.source === "string" ? cert.source : "acme"} />
                      <KV k="SAN" v={(cert.san ?? []).join(", ") || "—"} />
                      <KV k="Fingerprint" v={cert.fingerprint ? cert.fingerprint.slice(0, 24) + "…" : "—"} />
                    </div>
                    {certDays !== null && (
                      <div>
                        <div style={{ display: "flex", justifyContent: "space-between", fontSize: 14, color: "var(--text3)", marginBottom: 4, fontFamily: "var(--font-mono)" }}>
                          <span>Validity</span><span>{certDays} days remaining</span>
                        </div>
                        <div style={{ height: 7, background: "var(--bg3)", borderRadius: 4, overflow: "hidden" }}>
                          <div style={{ height: "100%", width: `${Math.max(3, Math.min(100, (certDays / 90) * 100))}%`, background: certDays < 14 ? "#ef4444" : certDays < 30 ? "var(--amber,#ffb020)" : "var(--green)", borderRadius: 4 }} />
                        </div>
                      </div>
                    )}
                    <div style={{ display: "flex", gap: 8 }}>
                      <button className="btn bg-btn btn-sm" onClick={async () => { try { await api.certs.renew(cert.domain); showToast("Renewal requested", "s", "🔐"); } catch (e) { showToast(e instanceof Error ? e.message : "Renew failed", "e", "⚠️"); } }}>🔄 Renew</button>
                      <button className="btn bg-btn btn-sm" onClick={() => router.push("/certificates")}>Manage all certs →</button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </motion.div>
      </AnimatePresence>

      <AnimatePresence>
        {editing && (
          <SiteWizard mode="edit" siteId={siteId} initial={form}
            onClose={() => setEditing(false)}
            onSaved={() => { setEditing(false); loadSite(); }} />
        )}
      </AnimatePresence>
    </motion.div>
  );
}

/** Pushed vs held. Two JSON panes and the list of fields that differ, plus the
 *  stored policy keys that never reach the data plane. Every silently-inert
 *  defect found so far would have shown up here as a diff row or an ignored key. */
function EffectiveConfigPanel({ eff, err, onRefresh }: { eff: EffectiveConfig | null; err: string | null; onRefresh: () => void }) {
  const [showJSON, setShowJSON] = useState(false);
  if (err) return <div className="code-block" style={{ borderLeft: "3px solid var(--red-b)" }}><span style={{ color: "var(--red-b)" }}>● COULD NOT LOAD</span> — {err}</div>;
  if (!eff) return <Empty text="Comparing what the control plane pushes with what the data plane holds…" />;
  const dp = eff.dataplane;
  const diff = eff.diff ?? [];
  // Three kinds of difference, in order of how much they matter: a value that
  // differs, a field pushed but not held, and a field the data plane filled with
  // a default because the control plane never sent it (the wizard does not model
  // it yet). The last group is informational and starts collapsed.
  const changed  = diff.filter(d => d.pushed !== "(not sent)" && d.applied !== "(not held)");
  const notHeld  = diff.filter(d => d.applied === "(not held)");
  const notSent  = diff.filter(d => d.pushed === "(not sent)");
  const [showDefaults, setShowDefaults] = useState(false);
  const clean = dp.reachable && eff.applied && changed.length === 0 && notHeld.length === 0 && eff.ignored_policy_keys.length === 0 && !eff.pushed_error;
  const fmt = (v: unknown) => typeof v === "string" ? v : JSON.stringify(v);
  const DiffTable = ({ rows, tone }: { rows: typeof diff; tone: string }) => (
    <div className="tw" style={{ borderLeft: `3px solid ${tone}` }}>
      <table>
        <thead><tr><th>Field</th><th>Pushed by control plane</th><th>Held by data plane</th></tr></thead>
        <tbody>
          {rows.map(d => (
            <tr key={d.path}>
              <td style={{ fontFamily: "var(--font-mono)", fontSize: 12.5 }}>{d.path}</td>
              <td className="td3" style={{ fontFamily: "var(--font-mono)", fontSize: 12.5, maxWidth: 320, wordBreak: "break-all", whiteSpace: "normal" }}>{fmt(d.pushed)}</td>
              <td className="td3" style={{ fontFamily: "var(--font-mono)", fontSize: 12.5, maxWidth: 320, wordBreak: "break-all", whiteSpace: "normal" }}>{fmt(d.applied)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      <div className="panel">
        <div className="ph">
          <div className="ptitle">Pushed vs held — {eff.site}</div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            {dp.engine && <span className="td3" style={{ fontSize: 12.5 }}>engine: {dp.engine.rules_enforced}/{dp.engine.rules_compiled} rules enforcing{dp.engine.rules_dropped ? ` · ${dp.engine.rules_dropped} dropped` : ""}</span>}
            <button className="btn bg-btn btn-xs" onClick={() => setShowJSON(v => !v)}>{showJSON ? "Hide JSON" : "Show JSON"}</button>
            <button className="btn bg-btn btn-xs" onClick={onRefresh}>⟳</button>
          </div>
        </div>
        <div className="pb" style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <div className="td3" style={{ fontSize: 12.5, lineHeight: 1.5 }}>
            <strong>Pushed</strong> is the exact structure this control plane sends to the data plane for this site — the same
            conversion the config sync runs. <strong>Held</strong> is what the data plane reports it is applying right now.
            A difference here is a control that is not doing what the console says.
          </div>

          {eff.pushed_error && (
            <div className="code-block" style={{ borderLeft: "3px solid var(--red-b)" }}>
              <span style={{ color: "var(--red-b)" }}>● THIS SITE CANNOT BE CONVERTED</span> — it is excluded from the sync and is not protected.{"\n"}{eff.pushed_error}
            </div>
          )}
          {!dp.reachable && (
            <div className="code-block" style={{ borderLeft: "3px solid var(--red-b)" }}>
              <span style={{ color: "var(--red-b)" }}>● DATA PLANE UNREACHABLE</span> — nothing is known about what is held. {dp.error}
            </div>
          )}
          {dp.reachable && eff.applied === null && (
            <div className="code-block" style={{ borderLeft: "3px solid var(--red-b)" }}>
              <span style={{ color: "var(--red-b)" }}>● NOT ON THE DATA PLANE</span> — the data plane does not hold this site at all.
              {eff.status === "active" ? " It is listed as active here and is NOT being protected." : ` Expected: the site is ${eff.status}.`}
            </div>
          )}
          {eff.ignored_policy_keys.length > 0 && (
            <div className="code-block" style={{ borderLeft: "3px solid var(--amber)" }}>
              <span style={{ color: "var(--amber)" }}>● {eff.ignored_policy_keys.length} STORED KEY{eff.ignored_policy_keys.length === 1 ? "" : "S"} NEVER REACH THE DATA PLANE</span>
              {" — "}stored and echoed back to the console, but not in the conversion, so whatever they represent is inert:{"\n"}
              {eff.ignored_policy_keys.join(", ")}
            </div>
          )}
          {clean && (
            <div className="code-block" style={{ borderLeft: "3px solid var(--green)" }}>
              <span style={{ color: "var(--green)" }}>● IDENTICAL</span> — every field pushed is held with the same value, and every stored policy key is understood.
            </div>
          )}

          {changed.length > 0 && (<>
            <div style={{ color: "var(--red-b)", fontSize: 13, fontWeight: 600 }}>● {changed.length} field{changed.length === 1 ? "" : "s"} differ — the console is not showing what the data plane does</div>
            <DiffTable rows={changed} tone="var(--red-b)" />
          </>)}
          {notHeld.length > 0 && (<>
            <div style={{ color: "var(--red-b)", fontSize: 13, fontWeight: 600 }}>● {notHeld.length} field{notHeld.length === 1 ? "" : "s"} pushed but NOT held by the data plane</div>
            <DiffTable rows={notHeld} tone="var(--red-b)" />
          </>)}
          {notSent.length > 0 && (
            <div>
              <button className="btn bg-btn btn-xs" onClick={() => setShowDefaults(v => !v)}>
                {showDefaults ? "▾" : "▸"} {notSent.length} field{notSent.length === 1 ? "" : "s"} filled by data-plane defaults (never sent by the control plane)
              </button>
              {showDefaults && <div style={{ marginTop: 8 }}><DiffTable rows={notSent} tone="var(--amber)" /></div>}
            </div>
          )}

          {showJSON && (
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
              <div><div className="td3" style={{ fontSize: 11, letterSpacing: ".04em", textTransform: "uppercase", marginBottom: 4 }}>pushed</div>
                <pre className="code-block" style={{ maxHeight: 460, overflow: "auto", fontSize: 11.5 }}>{JSON.stringify(eff.pushed ?? null, null, 2)}</pre></div>
              <div><div className="td3" style={{ fontSize: 11, letterSpacing: ".04em", textTransform: "uppercase", marginBottom: 4 }}>held{dp.version ? ` · data plane ${dp.version}` : ""}</div>
                <pre className="code-block" style={{ maxHeight: 460, overflow: "auto", fontSize: 11.5 }}>{JSON.stringify(eff.applied ?? null, null, 2)}</pre></div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function ConfigCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <motion.div className="panel" variants={cardVariants}>
      <div className="ph"><div className="ptitle">{title}</div></div>
      <div className="pb" style={{ display: "flex", flexDirection: "column", gap: 7 }}>{children}</div>
    </motion.div>
  );
}

function KV({ k, v }: { k: string; v: string }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", gap: 10, fontSize: 13 }}>
      <span style={{ color: "var(--text3)" }}>{k}</span>
      <span style={{ color: "var(--text)", fontFamily: "var(--font-mono)", textAlign: "right", maxWidth: "62%", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{v}</span>
    </div>
  );
}

function Empty({ text }: { text: string }) {
  return <div style={{ padding: "22px 12px", textAlign: "center", fontSize: 13, color: "var(--text3)", fontFamily: "var(--font-mono)" }}>{text}</div>;
}
