"use client";
import { useState, useEffect, useRef } from "react";
import { motion } from "framer-motion";
import { showToast } from "@/components/ui/Toast";
import {
  api,
  type DashboardStats, type MetricsSnapshot, type Attacker,
  type Rule, type MLStats, type ThreatIntelSummary, type ClusterHealth, type RuleInventory } from "@/lib/api";
import { staggerContainer, cardVariants, fadeUp, spring } from "@/lib/animations";
import { country } from "@/lib/geo";
import WorldMap from "@/components/dashboard/WorldMap";
import ThreatTrend from "@/components/dashboard/ThreatTrend";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
interface FeedRow { t: string; ip: string; m: string; path: string; st: number; latency: number }

// Attack-category presentation (keys mirror the Go hub's attackCategory()).
const ATTACK_META: Record<string, { label: string; color: string }> = {
  sqli:     { label: "SQL Injection",  color: "#ef4444" },
  xss:      { label: "XSS",            color: "#f59e0b" },
  rfi_lfi:  { label: "RFI / LFI",      color: "#a78bfa" },
  rce:      { label: "RCE / Code Exec",color: "#fb7185" },
  ssrf:     { label: "SSRF",           color: "#06b6d4" },
  bot:      { label: "Bot / Scanner",  color: "#22c55e" },
  protocol: { label: "Protocol",       color: "#3b82f6" },
  other:    { label: "Other",          color: "#94a3b8" },
};

// ---------------------------------------------------------------------------
// Animated counter
// ---------------------------------------------------------------------------
function AnimatedValue({ value, suffix = "" }: { value: number; suffix?: string }) {
  const [display, setDisplay] = useState(0);
  const prevRef = useRef(0);
  useEffect(() => {
    const prev = prevRef.current;
    const diff = value - prev;
    const steps = 15;
    let frame = 0;
    const interval = setInterval(() => {
      frame++;
      const progress = frame / steps;
      const eased = 1 - Math.pow(1 - progress, 3);
      setDisplay(Math.round(prev + diff * eased));
      if (frame >= steps) { setDisplay(value); clearInterval(interval); }
    }, 16);
    prevRef.current = value;
    return () => clearInterval(interval);
  }, [value]);
  return <>{display.toLocaleString()}{suffix}</>;
}

function fmtBytes(b: number): string {
  if (!b) return "—";
  const gb = b / (1024 ** 3);
  if (gb >= 1) return `${gb.toFixed(1)}GB`;
  return `${(b / (1024 ** 2)).toFixed(0)}MB`;
}

// ---------------------------------------------------------------------------
// Small KPI tile
// ---------------------------------------------------------------------------
function Kpi({ icon, label, value, sub, accent, hint }: { icon: string; label: string; value: React.ReactNode; sub?: string; accent?: string; hint?: string }) {
  return (
    <motion.div className="panel" variants={cardVariants} style={{ padding: "14px 16px", cursor: hint ? "help" : undefined }} title={hint}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div style={{ fontSize: 14, color: "var(--text3)", textTransform: "uppercase", letterSpacing: 1, fontFamily: "var(--font-mono)" }}>{label}</div>
        <span style={{ fontSize: 17, opacity: 0.85 }}>{icon}</span>
      </div>
      <div style={{ fontSize: 27, fontWeight: 700, color: accent ?? "var(--text)", marginTop: 8, fontFamily: "var(--font-display)", lineHeight: 1 }}>{value}</div>
      {sub && <div style={{ fontSize: 14, color: "var(--text3)", marginTop: 6, fontFamily: "var(--font-mono)" }}>{sub}</div>}
    </motion.div>
  );
}

// ---------------------------------------------------------------------------
// Overview page
// ---------------------------------------------------------------------------
export default function OverviewPage() {
  const [stats, setStats]     = useState<DashboardStats | null>(null);
  const [metrics, setMetrics] = useState<MetricsSnapshot | null>(null);
  const [feed, setFeed]       = useState<FeedRow[]>([]);
  const [wafStatus, setWafStatus] = useState<{ running: boolean; uptime?: number; sites?: number; upstreams_healthy?: number; upstreams_total?: number; http3?: { enabled: boolean; listener?: string; bind?: string; advertise_port?: number }; geoip?: { configured: number; active: number; inert: { site: string; db_path: string; db_present: boolean }[] } } | null>(null);
  const [plugins, setPlugins] = useState<number | null>(null);
  const [instances, setInstances] = useState<number | null>(null);
  // Blocked-by-country lives ONLY in ClickHouse (the hub's by_country snapshot
  // field is never populated), so the world map is fed from the country facet.
  const [byCountry, setByCountry] = useState<Record<string, number>>({});
  const [geoLoaded, setGeoLoaded] = useState(false);

  // ── DB stats ──
  useEffect(() => {
    let cancelled = false;
    async function f() { try { const r = await api.dashboard.stats(); if (!cancelled) setStats(r.stats); } catch { /* degraded */ } }
    f(); const t = setInterval(f, 15_000); return () => { cancelled = true; clearInterval(t); };
  }, []);

  // ── WAF health ──
  useEffect(() => {
    let cancelled = false;
    async function f() {
      try {
        const r = await api.waf.status();
        if (!cancelled) setWafStatus({ running: r.waf_running, uptime: r.uptime_secs, sites: r.sites, upstreams_healthy: r.upstreams_healthy, upstreams_total: r.upstreams_total, http3: r.http3 });
      } catch { setWafStatus(null); }
    }
    f(); const t = setInterval(f, 10_000); return () => { cancelled = true; clearInterval(t); };
  }, []);

  // ── Plugins + cluster (instances) — slow poll ──
  useEffect(() => {
    let cancelled = false;
    async function f() {
      try { const p = await api.plugins.list(); if (!cancelled) setPlugins((p.plugins ?? []).length); } catch { /* */ }
      try {
        // /cluster/status describes THIS control-plane node (node_id, role,
        // leader_id) and carries no peer list, so `status.peers?.length ?? 0`
        // was always 0 and this card read "1 · standalone" on a healthy
        // three-node cluster while the Cluster page showed 3/3 correctly.
        // /cluster/health is the fleet roll-up that page uses.
        const h = await api.cluster.health();
        if (!cancelled) {
          const dp = h.data_plane?.total ?? 0;
          const cp = h.control_plane?.total ?? 0;
          setInstances(Math.max(dp, cp, 1));
        }
      } catch { if (!cancelled) setInstances(null); }
    }
    f(); const t = setInterval(f, 30_000); return () => { cancelled = true; clearInterval(t); };
  }, []);

  // ── Blocked-by-country (ClickHouse facet → world map) ──
  useEffect(() => {
    let cancelled = false;
    async function f() {
      try {
        const r = await api.events.facets("country", undefined, undefined, 60);
        if (cancelled) return;
        const rec: Record<string, number> = {};
        (r.facets ?? []).forEach(({ key, count }) => { if (key) rec[key.toUpperCase()] = count; });
        setByCountry(rec);
        setGeoLoaded(!!r.clickhouse && Object.keys(rec).length > 0);
      } catch { /* control plane / clickhouse down — map shows honest empty state */ }
    }
    f(); const t = setInterval(f, 30_000); return () => { cancelled = true; clearInterval(t); };
  }, []);

  // ── Real metrics (1s) ──
  useEffect(() => {
    let cancelled = false;
    async function f() {
      try {
        const snap = await api.metrics.snapshot();
        if (!cancelled) setMetrics(snap);
      } catch { /* control plane may be down */ }
    }
    f(); const t = setInterval(f, 1_000); return () => { cancelled = true; clearInterval(t); };
  }, []);

  // ── Live access-log SSE ──
  useEffect(() => {
    const es = new EventSource(api.logs.streamURL("access"));
    es.onmessage = (evt) => {
      try {
        const entry: { kind: string; data: Record<string, unknown> } = JSON.parse(evt.data);
        if (!entry.data) return;
        const d = entry.data;
        setFeed(prev => [{
          t: String(d.ts ?? new Date().toTimeString().slice(0, 8)).slice(-8),
          ip: String(d.ip ?? ""), m: String(d.method ?? "GET"),
          path: String(d.path ?? "/"), st: Number(d.status ?? 200),
          latency: parseFloat(String(d.latency ?? 0)),
        }, ...prev].slice(0, 20));
      } catch { /* skip */ }
    };
    return () => es.close();
  }, []);

  // ── Derived ──
  const rps        = metrics?.rps              ?? 0;
  const p99        = metrics?.p99_latency_ms   ?? 0;
  const mlDet      = metrics?.ml_anomalies     ?? 0;
  const blkCount   = metrics?.blocked_requests ?? 0;
  const uniqueIPs  = metrics?.unique_blocked_ips ?? 0;
  const openAlerts = stats?.open_alerts        ?? 0;
  const memUsed    = metrics?.mem_used_bytes   ?? 0;
  const memTotal   = metrics?.mem_total_bytes  ?? 0;
  const memPct     = memTotal > 0 ? (memUsed / memTotal) * 100 : 0;

  // Tooltip text for every statistic on this page. The windows are not
  // decoration: the hub keeps a 10-second ring for RPS, a 1000-sample ring for
  // each p99, and plain counters for everything else that reset when the control
  // plane restarts. Two numbers on one screen measured over different windows,
  // with nothing saying so, is what made "sub-millisecond target" and
  // "THREATS BLOCKED 39,534" look like defects rather than different questions.
  const p99Waf     = metrics?.p99_waf_ms ?? 0;
  const sinceStart = "Counted since this control plane last started — a restart resets it.";
  const tip = {
    rps:      "Requests per second across every site, averaged over a 10-second rolling window of access-log events.",
    blocked:  `Requests the WAF refused. ${sinceStart} Learning-mode sites are inspected and scored but not blocked, so their attacks are not counted here.`,
    p99:      `99th-percentile end-to-end request latency, including the wait on the origin, over the last ${metrics?.p99_samples ?? 0} samples.`
              + (p99Waf > 0 ? ` The WAF's own processing accounts for ${p99Waf.toFixed(2)} ms of it.` : ""),
    ml:       `Requests the ML anomaly engine flagged, independently of signature rules. ${sinceStart}`,
    http3:    "Whether this deployment advertises HTTP/3 (QUIC), and on which listener. Per-site toggles do not apply — the listener is deployment-wide.",
    ram:      "Physical memory in use on the control-plane host, from /proc/meminfo. This is the host, not the container.",
    sites:    "Sites configured in the database, and how many are active. A paused or draft site is configured but serves nothing.",
    services: "Configured upstream services, with the health of their origins as checked by the data plane.",
    inst:     "Data-plane and control-plane nodes reporting to the cluster roll-up. Shows — when the roll-up cannot be reached, rather than assuming a single node.",
    plugins:  "WASM plugins loaded on the data plane. A loaded plugin only runs on the sites it is scoped to.",
    blkIPs:   `Distinct source addresses that have had at least one request blocked. ${sinceStart}`,
    alerts:   "Alerts currently in the open state, from the database — not a count of recent attacks.",
  };

  // Real attack breakdown from the hub (sorted desc).
  const breakdown = metrics?.attack_breakdown ?? {};
  const attackRows = Object.entries(breakdown)
    .filter(([k]) => ATTACK_META[k])
    .sort((a, b) => b[1] - a[1]);
  const attackMax = Math.max(1, ...attackRows.map(([, v]) => v));

  // Real status distribution.
  const s2 = metrics?.status_2xx ?? 0, s3 = metrics?.status_3xx ?? 0, s4 = metrics?.status_4xx ?? 0, s5 = metrics?.status_5xx ?? 0;
  const sTotal = s2 + s3 + s4 + s5;
  const statusSlices = [
    { label: "2xx", v: s2, color: "#22c55e" },
    { label: "3xx", v: s3, color: "#3b82f6" },
    { label: "4xx", v: s4, color: "#f59e0b" },
    { label: "5xx", v: s5, color: "#ef4444" },
  ];
  // Build conic-gradient stops.
  let acc = 0;
  const conic = sTotal > 0
    ? statusSlices.map(s => { const start = (acc / sTotal) * 360; acc += s.v; const end = (acc / sTotal) * 360; return `${s.color} ${start}deg ${end}deg`; }).join(", ")
    : "var(--bg3) 0deg 360deg";

  function formatUptime(secs: number): string {
    if (secs < 60) return `${secs}s`;
    const mins = Math.floor(secs / 60); if (mins < 60) return `${mins}m`;
    const hrs = Math.floor(mins / 60), rm = mins % 60;
    return rm > 0 ? `${hrs}h ${rm}m` : `${hrs}h`;
  }

  return (
    <motion.div className="sec" variants={staggerContainer} initial="hidden" animate="visible">

      {/* Header */}
      <motion.div variants={fadeUp} style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 14 }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          <div className="sec-title">Overview</div>
          <div className="sec-sub">Real-time security intelligence — live feed from data plane</div>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexShrink: 0 }}>
          <motion.div
            style={{ display: "flex", alignItems: "center", gap: 6, padding: "6px 12px", background: wafStatus?.running ? "rgba(34,197,94,0.08)" : "rgba(239,68,68,0.08)", border: wafStatus?.running ? "1px solid rgba(34,197,94,0.2)" : "1px solid rgba(239,68,68,0.2)", borderRadius: 20, fontSize: 13, color: wafStatus?.running ? "#86efac" : "#fca5a5" }}
            animate={{ boxShadow: wafStatus?.running ? ["0 0 8px rgba(34,197,94,.15)", "0 0 18px rgba(34,197,94,.3)", "0 0 8px rgba(34,197,94,.15)"] : ["0 0 8px rgba(239,68,68,.15)", "0 0 18px rgba(239,68,68,.3)", "0 0 8px rgba(239,68,68,.15)"] }}
            transition={{ duration: 2, repeat: Infinity }}>
            <div className={`sd ${wafStatus?.running ? "g" : "r"}`} />
            {wafStatus === null ? "WAF status: unknown" : wafStatus.running ? `WAF active · ${wafStatus.sites ?? "?"} sites · uptime ${formatUptime(wafStatus.uptime ?? 0)}` : "WAF proxy NOT running"}
          </motion.div>
          <motion.button className="btn bg-btn btn-sm" whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }} onClick={() => {
            // Real export of the current overview data (not a fake toast).
            const snap = { generated_at: new Date().toISOString(), stats, metrics, waf: wafStatus, plugins, instances, by_country: byCountry };
            const blob = new Blob([JSON.stringify(snap, null, 2)], { type: "application/json" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url; a.download = `waf-overview-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.json`;
            document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
            showToast("Overview snapshot exported", "s", "📄");
          }}>📄 Export</motion.button>
          <motion.button className="btn bp btn-sm" whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }} onClick={() => { api.dashboard.stats().then(r => { setStats(r.stats); showToast("Dashboard refreshed", "i", "🔄"); }).catch(() => showToast("Refresh failed", "e", "⚠️")); }}>🔄 Refresh</motion.button>
        </div>
      </motion.div>

      {/* KPI grid — all real */}
      <motion.div variants={staggerContainer} style={{ display: "grid", gridTemplateColumns: "repeat(7,minmax(0,1fr))", gap: 12 }}>
        <Kpi icon="🧠" label="System RAM" accent="var(--cyan)" hint={tip.ram}
          value={memTotal > 0 ? `${memPct.toFixed(0)}%` : "—"}
          sub={memTotal > 0 ? `${fmtBytes(memUsed)} / ${fmtBytes(memTotal)}` : "host metric"} />
        <Kpi icon="🌐" label="Sites" hint={tip.sites} value={<AnimatedValue value={stats?.total_sites ?? 0} />} sub={`${stats?.active_sites ?? 0} active`} />
        <Kpi icon="📦" label="Services" hint={tip.services} value={<AnimatedValue value={stats?.active_sites ?? 0} />} sub={`${wafStatus?.upstreams_healthy ?? 0}/${wafStatus?.upstreams_total ?? 0} upstreams`} />
        <Kpi icon="🖧" label="Instances" hint={tip.inst} value={instances === null ? "—" : instances} sub={(instances ?? 1) > 1 ? "clustered" : "standalone"} />
        <Kpi icon="🔌" label="Plugins" hint={tip.plugins} value={plugins === null ? "—" : plugins} sub="WASM loaded" />
        <Kpi icon="🛑" label="Blocked" accent="#ef4444" hint={tip.blocked} value={<AnimatedValue value={blkCount} />} sub={`${openAlerts} open alerts`} />
        <Kpi icon="📍" label="Blocked IPs" accent="#ef4444" hint={tip.blkIPs} value={<AnimatedValue value={uniqueIPs} />} sub="unique sources" />
      </motion.div>

      {/* Live metric cards */}
      <motion.div variants={staggerContainer} style={{ display: "grid", gridTemplateColumns: "repeat(5,minmax(0,1fr))", gap: 14 }}>
        <motion.div className="mc blue" variants={cardVariants} title={tip.rps} style={{ cursor: "help" }}><div className="mc-label">Requests / sec</div><div className="mc-val"><AnimatedValue value={rps} /></div><div className="mc-delta up">▲ 10-second rolling window</div></motion.div>
        <motion.div className="mc red" variants={cardVariants} title={tip.blocked} style={{ cursor: "help" }}><div className="mc-label">Threats blocked</div><div className="mc-val"><AnimatedValue value={blkCount} /></div><div className="mc-delta up" title={tip.alerts}>▲ {openAlerts} open alerts</div></motion.div>
        <motion.div className="mc green" variants={cardVariants} title={tip.p99} style={{ cursor: "help" }}><div className="mc-label">p99 Latency</div><div className="mc-val">{p99 > 0 ? p99.toFixed(2) + "ms" : "—"}</div><div className="mc-delta up">{p99Waf > 0 ? `▼ end-to-end · WAF ${p99Waf.toFixed(2)}ms of it` : "▼ end-to-end, incl. origin"}</div></motion.div>
        <motion.div className="mc pur" variants={cardVariants} title={tip.ml} style={{ cursor: "help" }}><div className="mc-label">ML detections</div><div className="mc-val"><AnimatedValue value={mlDet} /></div><div className="mc-delta" style={{ color: "#c4b5fd" }}>▲ anomaly engine active</div></motion.div>
        <motion.div className="mc cyan" variants={cardVariants} title={tip.http3} style={{ cursor: "help" }}>
          <div className="mc-label">HTTP/3</div>
          <div className="mc-val" style={{ fontSize: 25 }}>{wafStatus?.http3?.enabled ? "Active" : "Off"}</div>
          <div className="mc-delta" style={{ color: wafStatus?.http3?.enabled ? "#67e8f9" : "var(--text3)" }}>
            {wafStatus?.http3?.enabled ? `▲ QUIC · :${wafStatus.http3.advertise_port ?? "443"}` : "— not enabled"}
          </div>
        </motion.div>
      </motion.div>

      {/* Threat detection trend + Attack breakdown */}
      <motion.div variants={fadeUp} style={{ display: "grid", gridTemplateColumns: "1.6fr 1fr", gap: 14 }}>
        <ThreatTrend />
        <div className="panel">
          <div className="ph"><div className="ptitle">Attack breakdown</div><span className="panel-badge pb-info">Live</span></div>
          <div className="pb">
            {attackRows.length === 0 ? (
              <div style={{ padding: "20px 0", textAlign: "center", fontSize: 13, fontFamily: "var(--font-mono)", color: "var(--text3)" }}>No attacks detected yet</div>
            ) : attackRows.map(([key, count], idx) => {
              const meta = ATTACK_META[key];
              return (
                <motion.div key={key} className="atk-row" initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.2 + idx * 0.06, ...spring }}>
                  <div className="atk-label">{meta.label}</div>
                  <div className="atk-bar-bg"><div className="atk-bar" style={{ width: `${(count / attackMax) * 100}%`, background: meta.color }} /></div>
                  <div className="atk-count">{count.toLocaleString()}</div>
                </motion.div>
              );
            })}
          </div>
        </div>
      </motion.div>

      {/* Blocked-by-country map + status distribution */}
      <motion.div variants={fadeUp} style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 14 }}>
        <div className="panel">
          <div className="ph"><div className="ptitle">Blocked requests by origin</div><span className="panel-badge pb-info">{geoLoaded ? `GeoIP · ${Object.keys(byCountry).length} countries` : "GeoIP · awaiting events"}</span></div>
          <div className="pb"><WorldMap data={byCountry} loaded={geoLoaded} /></div>
        </div>
        <div className="panel" style={{ display: "flex", flexDirection: "column" }}>
          <div className="ph"><div className="ptitle">Response status</div><span className="panel-badge pb-info">{sTotal.toLocaleString()} reqs</span></div>
          <div className="pb" style={{ flex: 1, display: "flex", flexDirection: "column", justifyContent: "space-between", gap: 18, padding: "22px 18px" }}>

            {/* Donut */}
            <div style={{ display: "flex", justifyContent: "center" }}>
              <div style={{ width: 172, height: 172, borderRadius: "50%", background: `conic-gradient(${conic})`, position: "relative" }}>
                <div style={{ position: "absolute", inset: 23, borderRadius: "50%", background: "var(--bg2)", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
                  <div style={{ fontSize: 36, fontWeight: 700, color: "var(--text)", fontFamily: "var(--font-display)", lineHeight: 1 }}>{sTotal > 0 ? `${((s2 / sTotal) * 100).toFixed(0)}%` : "—"}</div>
                  <div style={{ fontSize: 12, color: "var(--text3)", marginTop: 5, letterSpacing: 1, textTransform: "uppercase", fontFamily: "var(--font-mono)" }}>success</div>
                </div>
              </div>
            </div>

            {/* Per-status proportion bars */}
            <div style={{ display: "flex", flexDirection: "column", gap: 15 }}>
              {statusSlices.map(s => (
                <div key={s.label} style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 14 }}>
                  <span style={{ width: 10, height: 10, borderRadius: 2, background: s.color, flexShrink: 0 }} />
                  <span style={{ color: "var(--text2)", width: 30, fontFamily: "var(--font-mono)", flexShrink: 0 }}>{s.label}</span>
                  <div className="atk-bar-bg" style={{ flex: 1 }}>
                    <div className="atk-bar" style={{ width: `${sTotal > 0 ? (s.v / sTotal) * 100 : 0}%`, background: s.color }} />
                  </div>
                  <span style={{ color: "var(--text)", fontFamily: "var(--font-mono)", width: 48, textAlign: "right", flexShrink: 0 }}>{s.v.toLocaleString()}</span>
                  <span style={{ color: "var(--text3)", fontFamily: "var(--font-mono)", width: 38, textAlign: "right", flexShrink: 0 }}>{sTotal > 0 ? `${((s.v / sTotal) * 100).toFixed(0)}%` : "—"}</span>
                </div>
              ))}
            </div>

            {/* Summary footer */}
            <div style={{ display: "flex", alignItems: "stretch", gap: 12, borderTop: "1px solid var(--bg4)", paddingTop: 16 }}>
              <div style={{ flex: 1, textAlign: "center" }}>
                <div style={{ fontSize: 21, fontWeight: 700, color: "#22c55e", fontFamily: "var(--font-display)", lineHeight: 1 }}>{sTotal > 0 ? `${(((s2 + s3) / sTotal) * 100).toFixed(1)}%` : "—"}</div>
                <div style={{ fontSize: 11, color: "var(--text3)", letterSpacing: 1, textTransform: "uppercase", marginTop: 5, fontFamily: "var(--font-mono)" }}>OK · 2xx/3xx</div>
              </div>
              <div style={{ width: 1, background: "var(--bg4)" }} />
              <div style={{ flex: 1, textAlign: "center" }}>
                <div style={{ fontSize: 21, fontWeight: 700, color: "#ef4444", fontFamily: "var(--font-display)", lineHeight: 1 }}>{(s4 + s5).toLocaleString()}</div>
                <div style={{ fontSize: 11, color: "var(--text3)", letterSpacing: 1, textTransform: "uppercase", marginTop: 5, fontFamily: "var(--font-mono)" }}>Errors · 4xx/5xx</div>
              </div>
            </div>
          </div>
        </div>
      </motion.div>

      {/* Threat sources + system health */}
      <motion.div variants={fadeUp} style={{ display: "grid", gridTemplateColumns: "1.5fr 1fr", gap: 14 }}>
        <TopAttackers />
        <SystemHealth
          wafRunning={wafStatus === null ? null : wafStatus.running}
          geoip={wafStatus?.geoip}
        />
      </motion.div>

      {/* Live event feed + rule-engine health */}
      <motion.div variants={fadeUp} style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
        <div className="panel">
          <div className="ph"><div className="ptitle">Recent events</div><span className="panel-badge pb-live">Live</span></div>
          <div className="pb">
            {feed.length === 0 ? (
              <div style={{ padding: "16px 0", textAlign: "center", fontSize: 13, fontFamily: "var(--font-mono)", color: "var(--text3)" }}>Waiting for events…</div>
            ) : feed.slice(0, 7).map((r, i) => {
              const dotCls = r.st === 403 || r.st === 400 ? "ev-red" : r.st >= 500 || r.latency > 3 ? "ev-amber" : r.m === "POST" || r.m === "PUT" ? "ev-blue" : "ev-green";
              const label = r.st === 403 ? `Blocked — ${r.m} ${r.path}` : r.st >= 500 ? `Error — ${r.m} ${r.path}` : `${r.m} ${r.path}`;
              return (
                <motion.div key={i} className="ev-item" initial={{ opacity: 0, y: 5 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.5 + i * 0.04 }}>
                  <div className={`ev-dot ${dotCls}`} />
                  <div><div className="ev-text">{label}</div><div className="ev-time">{r.t} · {r.ip}</div></div>
                </motion.div>
              );
            })}
          </div>
        </div>

        <RuleEngineHealth metrics={metrics} running={!!wafStatus?.running} />
      </motion.div>

      <AlertsPreview />
    </motion.div>
  );
}

// ---------------------------------------------------------------------------
// Alerts preview (reads real DB)
// ---------------------------------------------------------------------------
function AlertsPreview() {
  const [alerts, setAlerts] = useState<import("@/lib/api").Alert[]>([]);
  useEffect(() => { api.alerts.list("open").then(r => setAlerts(r.alerts ?? [])).catch(() => {}); }, []);
  return (
    <motion.div className="panel" variants={fadeUp}>
      <div className="ph">
        <div className="ptitle">Recent Alerts</div>
        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
          <button className="btn bg-btn btn-sm" onClick={() => window.location.href = "/alerts"}>View All →</button>
        </div>
      </div>
      <div className="tw">
        {alerts.length === 0 ? (
          <div style={{ padding: "16px", fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--text3)", textAlign: "center" }}>No open alerts</div>
        ) : (
          <table>
            <thead><tr><th>Severity</th><th>Time</th><th>Kind</th><th>Summary</th><th>State</th></tr></thead>
            <tbody>
              {alerts.slice(0, 5).map((a, idx) => (
                <motion.tr key={a.id} className={`sev-${a.severity[0].toLowerCase()}`} initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.6 + idx * 0.04 }}>
                  <td><span className={`bdg ${a.severity === "critical" ? "br blink" : a.severity === "high" ? "ba" : a.severity === "medium" ? "bcy" : "bgr"}`}><span className="bdr" />{a.severity.toUpperCase()}</span></td>
                  <td className="td3">{new Date(a.created_at).toLocaleTimeString()}</td>
                  <td className="td2">{a.kind}</td>
                  <td style={{ maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.summary}</td>
                  <td><span className={`bdg ${a.state === "open" ? "br" : a.state === "acked" ? "ba" : "bgr"}`}>{a.state.toUpperCase()}</span></td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </motion.div>
  );
}

// ---------------------------------------------------------------------------
// Shared: centred info/empty line inside a panel body
// ---------------------------------------------------------------------------
function CardMsg({ text }: { text: string }) {
  return (
    <div style={{ padding: "22px 8px", textAlign: "center", fontSize: 13, lineHeight: 1.55, fontFamily: "var(--font-mono)", color: "var(--text3)" }}>
      {text}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Top Attacker IPs — real ClickHouse-backed roll-up: IP · country · requests ·
// blocked, sorted by volume. Rows drill into Threat Search. Honest empty state
// when the event store isn't configured (there is no per-IP data without it).
// ---------------------------------------------------------------------------
function TopAttackers() {
  const [rows, setRows] = useState<Attacker[] | null>(null);
  const [ch, setCh]     = useState(true);

  useEffect(() => {
    let cancelled = false;
    async function f() {
      try {
        const r = await api.events.topAttackers(8);
        if (cancelled) return;
        setRows(r.attackers ?? []);
        setCh(r.clickhouse);
      } catch { if (!cancelled) { setRows([]); setCh(true); } }
    }
    f(); const t = setInterval(f, 20_000); return () => { cancelled = true; clearInterval(t); };
  }, []);

  return (
    <div className="panel">
      <div className="ph">
        <div className="ptitle">Top Attacker IPs</div>
        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
          <span className="panel-badge pb-info">Last 24h</span>
          <button className="btn bg-btn btn-sm" onClick={() => { window.location.href = "/events"; }}>View All →</button>
        </div>
      </div>
      <div className="tw">
        {rows === null ? (
          <CardMsg text="Loading attacker intelligence…" />
        ) : !ch ? (
          <CardMsg text="Event store (ClickHouse) not configured — enable it to rank attacker IPs by volume and geography." />
        ) : rows.length === 0 ? (
          <CardMsg text="No attacker traffic in the last 24 hours." />
        ) : (
          <table>
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Country</th>
                <th style={{ textAlign: "right" }}>Requests</th>
                <th style={{ textAlign: "right" }}>Blocked</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((a, i) => {
                const c = country(a.country);
                return (
                  <motion.tr key={a.ip}
                    initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.04 * i }}
                    onClick={() => { window.location.href = `/events?ip=${encodeURIComponent(a.ip)}`; }}
                    title="Open in Threat Search">
                    <td><span style={{ color: "var(--cyan)" }}>{a.ip}</span></td>
                    <td className="td2">
                      <span style={{ fontSize: 15, marginRight: 8 }} title={a.country || "unknown"}>{c.flag}</span>
                      {c.name}
                    </td>
                    <td style={{ textAlign: "right" }}>{a.requests.toLocaleString()}</td>
                    <td style={{ textAlign: "right", color: a.blocked > 0 ? "var(--red-b)" : "var(--text3)", fontWeight: 600 }}>
                      {a.blocked.toLocaleString()}
                    </td>
                  </motion.tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Rule Engine Health — real ruleset load-state from /rules grouped by source,
// plus real per-category block counts from the metrics hub's attack_breakdown
// (always-on; no ClickHouse dependency) and the live ML/proxy signals.
// ---------------------------------------------------------------------------
function RuleEngineHealth({ metrics, running }: { metrics: MetricsSnapshot | null; running: boolean }) {
  const [rules, setRules] = useState<Rule[] | null>(null);
  // The compiled inventory is what the data plane enforces. Without it this card
  // read "OWASP CRS v4 core 5/5 rules enabled" — the five seeded rows of the
  // authored store — while the engine held a few hundred compiled CRS rules.
  const [inv, setInv] = useState<RuleInventory | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function f() {
      try { const r = await api.rules.list(); if (!cancelled) setRules(r.rules ?? []); }
      catch { if (!cancelled) setRules([]); }
      try { const i = await api.rules.inventory({ summary: true }); if (!cancelled) setInv(i); }
      catch { if (!cancelled) setInv(null); }
    }
    f(); const t = setInterval(f, 30_000); return () => { cancelled = true; clearInterval(t); };
  }, []);

  const loading = rules === null;
  const rl = rules ?? [];
  const grp = (pred: (r: Rule) => boolean) => {
    const g = rl.filter(pred);
    return { total: g.length, on: g.filter(r => r.enabled).length };
  };
  const crs    = grp(r => r.source === "crs");
  const custom = grp(r => r.source === "custom" || r.source === "ai_generated");
  const vp     = grp(r => r.source === "virtual_patch");
  const enabled = rl.filter(r => r.enabled).length;

  const bd = metrics?.attack_breakdown ?? {};
  const n = (k: string) => bd[k] ?? 0;
  const crsHits = n("sqli") + n("xss") + n("rfi_lfi") + n("rce") + n("ssrf") + n("protocol");
  const mlHits  = metrics?.ml_anomalies ?? 0;

  const rows: { name: string; sub: string; on: boolean; loading: boolean; hits: number | null }[] = [
    {
      name: "OWASP CRS v4 (compiled)",
      sub: inv == null ? (loading ? "…" : "inventory unavailable")
         : !inv.dataplane_reachable ? "data plane unreachable"
         : `${inv.totals.enforced.toLocaleString()} of ${inv.totals.compiled.toLocaleString()} compiled rules enforcing`
           + (inv.totals.dropped > 0 ? ` · ${inv.totals.dropped} failed to compile` : "")
           + (inv.totals.disabled > 0 ? ` · ${inv.totals.disabled} inert` : ""),
      on: (inv?.totals.enforced ?? 0) > 0,
      loading: inv == null && loading,
      hits: crsHits,
    },
    { name: "Custom SRL rules",    sub: loading ? "…" : `${custom.on}/${custom.total} rules enabled`, on: custom.on > 0,      loading, hits: null },
    { name: "Virtual patches",     sub: loading ? "…" : vp.total > 0 ? `${vp.on}/${vp.total} rules enabled` : "none loaded", on: vp.on > 0, loading, hits: null },
    { name: "ML anomaly engine",   sub: "behavioural scoring",       on: running, loading: false, hits: mlHits },
    { name: "Bot / scanner defense", sub: "signatures + heuristics", on: crs.on > 0 || running, loading, hits: n("bot") },
  ];

  return (
    <div className="panel">
      <div className="ph">
        <div className="ptitle">Rule Engine Health</div>
        <span className="panel-badge pb-info">{loading ? "loading…" : `${enabled}/${rl.length} enabled`}</span>
      </div>
      <div className="pb">
        {rows.map((row, idx) => (
          <motion.div key={row.name} className="rule-row"
            initial={{ opacity: 0, x: -4 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.05 * idx }}>
            <div className="rule-name">
              {row.name}
              <span style={{ display: "block", fontSize: 11, fontWeight: 400, marginTop: 2, color: "var(--text3)", fontFamily: "var(--font-mono)" }}>{row.sub}</span>
            </div>
            <span className={`rule-st ${row.loading ? "rs-warn" : row.on ? "rs-on" : "rs-warn"}`}>
              {row.loading ? "…" : row.on ? "Active" : "Off"}
            </span>
            <div className="rule-hits" title={row.hits == null ? "no per-source counter" : "blocked this session"}>
              {row.hits == null ? "—" : row.hits.toLocaleString()}
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// System Health — at-a-glance fleet/engine roll-up from real endpoints.
// ---------------------------------------------------------------------------
function titleCase(s: string): string {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
}

type HLevel = "g" | "a" | "r" | "gr";

type GeoIpStatus = { configured: number; active: number; inert: { site: string; db_path: string; db_present: boolean }[] };

function SystemHealth({ wafRunning, geoip }: { wafRunning: boolean | null; geoip?: GeoIpStatus }) {
  const [health, setHealth]   = useState<ClusterHealth | null>(null);
  const [ml, setMl]           = useState<MLStats | null>(null);
  const [ti, setTi]           = useState<ThreatIntelSummary | null>(null);
  const [plugins, setPlugins] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function f() {
      try { const h = await api.cluster.health();     if (!cancelled) setHealth(h); } catch { /* */ }
      try { const m = await api.ml.stats();           if (!cancelled) setMl(m); }     catch { /* */ }
      try { const t = await api.threatIntel.stats();  if (!cancelled) setTi(t); }     catch { /* */ }
      try { const p = await api.plugins.list();       if (!cancelled) setPlugins((p.plugins ?? []).length); } catch { /* */ }
    }
    f(); const t = setInterval(f, 30_000); return () => { cancelled = true; clearInterval(t); };
  }, []);

  const dp = health?.data_plane;
  const mlActive = !!ml && !!ml.model_status && !/off|disabl|error|down/i.test(ml.model_status);

  // Overall summary — data-plane liveness dominates, then the fleet roll-up.
  const summary: { level: HLevel; text: string } =
    wafRunning === false ? { level: "r", text: "Data plane offline — traffic unprotected" }
    : health?.overall === "critical" ? { level: "r", text: "Critical — action required" }
    : health?.overall === "degraded" ? { level: "a", text: "Degraded — one or more checks failing" }
    : wafRunning === null && !health   ? { level: "gr", text: "Checking system status…" }
    : { level: "g", text: "All Systems Operational" };

  // Resolved before the array so the ternaries stay readable.
  const gi = geoip;
  const geoInert = gi?.inert?.length ?? 0;
  const geo: { name: string; value: string; level: HLevel } =
    !gi
      ? { name: "GeoIP Database", value: "—", level: "gr" }
      : geoInert > 0
        // Configured and NOT enforced. Red, and it says why — a missing database
        // is an operator action, not a transient state.
        ? { name: "GeoIP Database",
            value: `NOT enforced · no database · ${geoInert} site${geoInert === 1 ? "" : "s"}`,
            level: "r" }
        : gi.active > 0
          ? { name: "GeoIP Database", value: `Active · ${gi.active} site${gi.active === 1 ? "" : "s"}`, level: "g" }
          : { name: "GeoIP Database", value: "Not configured", level: "gr" };

  const rows: { name: string; level: HLevel; value: string }[] = [
    dp
      ? { name: "Data Plane Nodes", value: `${dp.healthy}/${dp.total} healthy`,
          level: dp.total === 0 ? "gr" : dp.healthy === dp.total ? "g" : dp.healthy > 0 ? "a" : "r" }
      : { name: "Data Plane Nodes", value: "—", level: "gr" },
    { name: "ML Engine",         value: ml ? titleCase(ml.model_status || "unknown") : "—", level: mlActive ? "g" : ml ? "a" : "gr" },
    { name: "Rule Engine",       value: wafRunning === null ? "—" : wafRunning ? "Active" : "Inactive", level: wafRunning === null ? "gr" : wafRunning ? "g" : "r" },
    // GeoIP state comes from the DATA PLANE (/waf/status -> /healthz), not from
    // how many countries happen to appear in recent events. Inferring it from
    // event data was actively misleading: with no MaxMind database the WAF
    // resolves every address to Unknown, so no country ever appears, and this row
    // read "Awaiting events" — which sounds like normal startup rather than a
    // configured control that is not running. `inert` is the data plane naming
    // the sites whose country policy is displayed and not applied.
    geo,
    { name: "Threat Intel Feeds", value: ti ? (ti.total_active > 0 ? `${ti.total_active.toLocaleString()} indicators` : "No IOCs loaded") : "—", level: ti ? (ti.total_active > 0 ? "g" : "a") : "gr" },
    { name: "WASM Sandbox",      value: plugins === null ? "—" : plugins > 0 ? `${plugins} plugin${plugins === 1 ? "" : "s"} loaded` : "Idle", level: plugins && plugins > 0 ? "g" : "gr" },
  ];

  const valColor: Record<HLevel, string> = { g: "var(--green)", a: "var(--amber)", r: "var(--red-b)", gr: "var(--text3)" };

  return (
    <div className="panel">
      <div className="ph">
        <div className="ptitle">System Health</div>
        <button className="btn bg-btn btn-sm" onClick={() => { window.location.href = "/cluster"; }}>View Details →</button>
      </div>
      <div className="pb">
        <div style={{ display: "flex", alignItems: "center", gap: 9, paddingBottom: 12, marginBottom: 4, borderBottom: "1px solid var(--bg4)" }}>
          <span className={`sd ${summary.level}`} />
          <span style={{ fontSize: 14, fontWeight: 600, color: valColor[summary.level] }}>{summary.text}</span>
        </div>
        {rows.map((row, idx) => (
          <motion.div key={row.name}
            initial={{ opacity: 0, x: -4 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.05 * idx }}
            style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 0", borderBottom: idx < rows.length - 1 ? "1px solid rgba(255,255,255,.04)" : "none" }}>
            <span className={`sd ${row.level}`} />
            <span style={{ flex: 1, fontSize: 13, color: "var(--text2)" }}>{row.name}</span>
            <span style={{ fontSize: 13, fontFamily: "var(--font-mono)", color: valColor[row.level] }}>{row.value}</span>
          </motion.div>
        ))}
      </div>
    </div>
  );
}
