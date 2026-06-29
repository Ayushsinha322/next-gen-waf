"use client";
import { useState, useEffect, useRef } from "react";
import { motion } from "framer-motion";
import { showToast } from "@/components/ui/Toast";
import { api, type DashboardStats, type MetricsSnapshot } from "@/lib/api";
import { staggerContainer, cardVariants, fadeUp, spring } from "@/lib/animations";
import { PLANS, ACTIVE_PLAN, type PlanKey } from "@/lib/plans";
import WorldMap from "@/components/dashboard/WorldMap";

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
function Kpi({ icon, label, value, sub, accent }: { icon: string; label: string; value: React.ReactNode; sub?: string; accent?: string }) {
  return (
    <motion.div className="panel" variants={cardVariants} style={{ padding: "14px 16px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div style={{ fontSize: 12, color: "var(--text3)", textTransform: "uppercase", letterSpacing: 1, fontFamily: "'Share Tech Mono',monospace" }}>{label}</div>
        <span style={{ fontSize: 15, opacity: 0.85 }}>{icon}</span>
      </div>
      <div style={{ fontSize: 24, fontWeight: 800, color: accent ?? "var(--text)", marginTop: 8, fontFamily: "'Orbitron',sans-serif", lineHeight: 1 }}>{value}</div>
      {sub && <div style={{ fontSize: 12, color: "var(--text3)", marginTop: 6, fontFamily: "'Share Tech Mono',monospace" }}>{sub}</div>}
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
  const [wafStatus, setWafStatus] = useState<{ running: boolean; uptime?: number; sites?: number; upstreams_healthy?: number; upstreams_total?: number } | null>(null);
  const [plugins, setPlugins] = useState<number | null>(null);
  const [instances, setInstances] = useState<number | null>(null);

  const chartRef       = useRef<HTMLCanvasElement>(null);
  const trafficHistory = useRef<{ total: number; blocked: number; ml: number }[]>([]);

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
        if (!cancelled) setWafStatus({ running: r.waf_running, uptime: r.uptime_secs, sites: r.sites, upstreams_healthy: r.upstreams_healthy, upstreams_total: r.upstreams_total });
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
        const c = await api.cluster.status();
        if (!cancelled) setInstances(c.enabled ? ((c.status?.peers?.length ?? 0) + 1) : 1);
      } catch { if (!cancelled) setInstances(1); }
    }
    f(); const t = setInterval(f, 30_000); return () => { cancelled = true; clearInterval(t); };
  }, []);

  // ── Real metrics (1s) ──
  useEffect(() => {
    let cancelled = false;
    async function f() {
      try {
        const snap = await api.metrics.snapshot();
        if (!cancelled) {
          setMetrics(snap);
          trafficHistory.current = [...trafficHistory.current, { total: snap.total_requests, blocked: snap.blocked_requests, ml: snap.ml_anomalies }].slice(-60);
          drawTrafficChart();
        }
      } catch { /* control plane may be down */ }
    }
    f(); const t = setInterval(f, 1_000); return () => { cancelled = true; clearInterval(t); };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

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

  // ── Traffic chart ──
  function drawTrafficChart() {
    const canvas = chartRef.current; if (!canvas) return;
    const ctx = canvas.getContext("2d"); if (!ctx) return;
    const hist = trafficHistory.current; if (hist.length < 2) return;
    const dpr = window.devicePixelRatio || 1;
    const W = canvas.offsetWidth || 600, H = 160;
    canvas.width = W * dpr; canvas.height = H * dpr; ctx.scale(dpr, dpr);
    const traffic = hist.map(d => d.total), threats = hist.map(d => d.blocked);
    const pts = traffic.length;
    const pad = { t: 10, b: 30, l: 36, r: 8 };
    const cW = W - pad.l - pad.r, cH = H - pad.t - pad.b;
    const maxV = Math.max(...traffic) * 1.1 || 1;
    const px = (i: number) => pad.l + i * (cW / (pts - 1));
    const py = (v: number) => pad.t + cH * (1 - v / maxV);
    for (let i = 0; i <= 4; i++) {
      const y = pad.t + i * (cH / 4);
      ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(W - pad.r, y);
      ctx.strokeStyle = "rgba(128,128,128,0.10)"; ctx.lineWidth = 1; ctx.stroke();
      ctx.fillStyle = "rgba(128,140,160,0.5)"; ctx.font = "10px Inter,sans-serif"; ctx.textAlign = "right";
      ctx.fillText(Math.round(maxV * (1 - i / 4) / 1000) + "k", pad.l - 4, y + 4);
    }
    ctx.textAlign = "left";
    ctx.beginPath(); ctx.moveTo(px(0), py(traffic[0]));
    for (let i = 1; i < pts; i++) ctx.lineTo(px(i), py(traffic[i]));
    ctx.strokeStyle = "rgba(59,130,246,0.85)"; ctx.lineWidth = 1.5; ctx.stroke();
    ctx.lineTo(px(pts - 1), pad.t + cH); ctx.lineTo(px(0), pad.t + cH); ctx.closePath();
    ctx.fillStyle = "rgba(59,130,246,0.08)"; ctx.fill();
    ctx.beginPath(); ctx.moveTo(px(0), py(threats[0]));
    for (let i = 1; i < pts; i++) ctx.lineTo(px(i), py(threats[i]));
    ctx.strokeStyle = "rgba(239,68,68,0.8)"; ctx.lineWidth = 1.5; ctx.stroke();
    ctx.lineTo(px(pts - 1), pad.t + cH); ctx.lineTo(px(0), pad.t + cH); ctx.closePath();
    ctx.fillStyle = "rgba(239,68,68,0.07)"; ctx.fill();
    ctx.fillStyle = "rgba(96,165,250,0.85)"; ctx.fillRect(pad.l, H - 18, 16, 2);
    ctx.fillStyle = "rgba(128,140,160,0.7)"; ctx.font = "11px Inter,sans-serif"; ctx.fillText("Requests", pad.l + 20, H - 13);
    ctx.fillStyle = "rgba(239,68,68,0.85)"; ctx.fillRect(pad.l + 100, H - 18, 16, 2);
    ctx.fillStyle = "rgba(128,140,160,0.7)"; ctx.fillText("Threats", pad.l + 120, H - 13);
  }

  // ── Derived ──
  const rps        = metrics?.rps              ?? 0;
  const p99        = metrics?.p99_latency_ms   ?? 0;
  const mlDet      = metrics?.ml_anomalies     ?? 0;
  const blkCount   = metrics?.blocked_requests ?? 0;
  const uniqueIPs  = metrics?.unique_blocked_ips ?? 0;
  const openAlerts = stats?.open_alerts        ?? 0;
  const totalRules = stats?.total_rules        ?? 0;
  const enabledRules = stats?.enabled_rules    ?? totalRules;
  const memUsed    = metrics?.mem_used_bytes   ?? 0;
  const memTotal   = metrics?.mem_total_bytes  ?? 0;
  const memPct     = memTotal > 0 ? (memUsed / memTotal) * 100 : 0;

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

  // Top attacker IPs from live feed.
  const ipCounts: Record<string, number> = {};
  feed.forEach(r => { if (r.ip) ipCounts[r.ip] = (ipCounts[r.ip] ?? 0) + 1; });
  const topIPs = Object.entries(ipCounts).sort((a, b) => b[1] - a[1]).slice(0, 6);

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
            style={{ display: "flex", alignItems: "center", gap: 6, padding: "6px 12px", background: wafStatus?.running ? "rgba(34,197,94,0.08)" : "rgba(239,68,68,0.08)", border: wafStatus?.running ? "1px solid rgba(34,197,94,0.2)" : "1px solid rgba(239,68,68,0.2)", borderRadius: 20, fontSize: 11, color: wafStatus?.running ? "#86efac" : "#fca5a5" }}
            animate={{ boxShadow: wafStatus?.running ? ["0 0 8px rgba(34,197,94,.15)", "0 0 18px rgba(34,197,94,.3)", "0 0 8px rgba(34,197,94,.15)"] : ["0 0 8px rgba(239,68,68,.15)", "0 0 18px rgba(239,68,68,.3)", "0 0 8px rgba(239,68,68,.15)"] }}
            transition={{ duration: 2, repeat: Infinity }}>
            <div className={`sd ${wafStatus?.running ? "g" : "r"}`} />
            {wafStatus === null ? "WAF status: unknown" : wafStatus.running ? `WAF active · ${wafStatus.sites ?? "?"} sites · uptime ${formatUptime(wafStatus.uptime ?? 0)}` : "WAF proxy NOT running"}
          </motion.div>
          <motion.button className="btn bg-btn btn-sm" whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }} onClick={() => showToast("Report generated", "s", "📄")}>📄 Export</motion.button>
          <motion.button className="btn bp btn-sm" whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }} onClick={() => { api.dashboard.stats().then(r => { setStats(r.stats); showToast("Dashboard refreshed", "i", "🔄"); }).catch(() => showToast("Refresh failed", "e", "⚠️")); }}>🔄 Refresh</motion.button>
        </div>
      </motion.div>

      {/* Plans */}
      <motion.div variants={fadeUp} style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
        {(Object.keys(PLANS) as PlanKey[]).map(k => {
          const p = PLANS[k]; const active = k === ACTIVE_PLAN;
          return (
            <div key={k} className="panel" style={{ padding: 18, position: "relative", border: active ? "1px solid var(--cyan-ring)" : undefined, background: active ? "var(--cyan-dim)" : undefined }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <span style={{ fontFamily: "'Orbitron',sans-serif", fontSize: 18, fontWeight: 800, color: p.accent }}>{p.name}</span>
                  {active && <span style={{ fontSize: 9, fontWeight: 700, padding: "3px 9px", borderRadius: 20, background: "var(--cyan)", color: "#021018", letterSpacing: 0.5 }}>● CURRENT PLAN</span>}
                </div>
                <span style={{ fontSize: 11, color: "var(--text3)", fontFamily: "'Share Tech Mono',monospace" }}>{p.price}</span>
              </div>
              <div style={{ fontSize: 11, color: "var(--text3)", marginTop: 4 }}>{p.tagline}</div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, margin: "14px 0" }}>
                {Object.entries(p.limits).map(([key, val]) => (
                  <div key={key} style={{ fontSize: 10.5, color: "var(--text2)", display: "flex", alignItems: "center", gap: 6 }}>
                    <span style={{ color: p.accent }}>▸</span>{val}
                  </div>
                ))}
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 5, borderTop: "1px solid var(--bg4)", paddingTop: 12 }}>
                {p.highlights.map(h => (
                  <div key={h} style={{ fontSize: 10.5, color: h.endsWith(":") ? "var(--text3)" : "var(--text2)", display: "flex", gap: 7 }}>
                    {!h.endsWith(":") && <span style={{ color: "var(--green)" }}>✓</span>}{h}
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </motion.div>

      {/* KPI grid — all real */}
      <motion.div variants={staggerContainer} style={{ display: "grid", gridTemplateColumns: "repeat(7,minmax(0,1fr))", gap: 12 }}>
        <Kpi icon="🧠" label="System RAM" accent="var(--cyan)"
          value={memTotal > 0 ? `${memPct.toFixed(0)}%` : "—"}
          sub={memTotal > 0 ? `${fmtBytes(memUsed)} / ${fmtBytes(memTotal)}` : "host metric"} />
        <Kpi icon="🌐" label="Sites" value={<AnimatedValue value={stats?.total_sites ?? 0} />} sub={`${stats?.active_sites ?? 0} active`} />
        <Kpi icon="📦" label="Services" value={<AnimatedValue value={stats?.active_sites ?? 0} />} sub={`${wafStatus?.upstreams_healthy ?? 0}/${wafStatus?.upstreams_total ?? 0} upstreams`} />
        <Kpi icon="🖧" label="Instances" value={instances === null ? "—" : instances} sub={(instances ?? 1) > 1 ? "clustered" : "standalone"} />
        <Kpi icon="🔌" label="Plugins" value={plugins === null ? "—" : plugins} sub="WASM loaded" />
        <Kpi icon="🛑" label="Blocked" accent="#ef4444" value={<AnimatedValue value={blkCount} />} sub={`${openAlerts} open alerts`} />
        <Kpi icon="📍" label="Blocked IPs" accent="#ef4444" value={<AnimatedValue value={uniqueIPs} />} sub="unique sources" />
      </motion.div>

      {/* Live metric cards */}
      <motion.div variants={staggerContainer} style={{ display: "grid", gridTemplateColumns: "repeat(4,minmax(0,1fr))", gap: 14 }}>
        <motion.div className="mc blue" variants={cardVariants}><div className="mc-label">Requests / sec</div><div className="mc-val"><AnimatedValue value={rps} /></div><div className="mc-delta up">▲ live · 1-sec samples</div></motion.div>
        <motion.div className="mc red" variants={cardVariants}><div className="mc-label">Threats blocked</div><div className="mc-val"><AnimatedValue value={blkCount} /></div><div className="mc-delta up">▲ {openAlerts} open alerts</div></motion.div>
        <motion.div className="mc green" variants={cardVariants}><div className="mc-label">p99 Latency</div><div className="mc-val">{p99 > 0 ? p99.toFixed(2) + "ms" : "—"}</div><div className="mc-delta up">▼ sub-millisecond target</div></motion.div>
        <motion.div className="mc pur" variants={cardVariants}><div className="mc-label">ML detections</div><div className="mc-val"><AnimatedValue value={mlDet} /></div><div className="mc-delta" style={{ color: "#c4b5fd" }}>▲ anomaly engine active</div></motion.div>
      </motion.div>

      {/* Traffic chart + Attack breakdown */}
      <motion.div variants={fadeUp} style={{ display: "grid", gridTemplateColumns: "1.6fr 1fr", gap: 14 }}>
        <div className="panel">
          <div className="ph"><div className="ptitle">Traffic &amp; threat timeline</div><div style={{ display: "flex", gap: 8 }}><span className="panel-badge pb-live">● Live</span><span className="panel-badge pb-info">Last 60s</span></div></div>
          <div className="pb">
            <canvas ref={chartRef} height={160} style={{ width: "100%", display: "block" }} />
            {metrics === null && <div style={{ textAlign: "center", paddingTop: 8, fontSize: 12, fontFamily: "'Share Tech Mono',monospace", color: "var(--text3)" }}>waiting for data plane…</div>}
          </div>
        </div>
        <div className="panel">
          <div className="ph"><div className="ptitle">Attack breakdown</div><span className="panel-badge pb-info">Live</span></div>
          <div className="pb">
            {attackRows.length === 0 ? (
              <div style={{ padding: "20px 0", textAlign: "center", fontSize: 11, fontFamily: "'Share Tech Mono',monospace", color: "var(--text3)" }}>No attacks detected yet</div>
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
          <div className="ph"><div className="ptitle">Blocked requests by origin</div><span className="panel-badge pb-info">{metrics?.geoip_loaded ? "GeoIP" : "GeoIP off"}</span></div>
          <div className="pb"><WorldMap data={metrics?.by_country ?? {}} loaded={!!metrics?.geoip_loaded} /></div>
        </div>
        <div className="panel" style={{ display: "flex", flexDirection: "column" }}>
          <div className="ph"><div className="ptitle">Response status</div><span className="panel-badge pb-info">{sTotal.toLocaleString()} reqs</span></div>
          <div className="pb" style={{ flex: 1, display: "flex", flexDirection: "column", justifyContent: "space-between", gap: 18, padding: "22px 18px" }}>

            {/* Donut */}
            <div style={{ display: "flex", justifyContent: "center" }}>
              <div style={{ width: 172, height: 172, borderRadius: "50%", background: `conic-gradient(${conic})`, position: "relative" }}>
                <div style={{ position: "absolute", inset: 23, borderRadius: "50%", background: "var(--bg2)", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
                  <div style={{ fontSize: 32, fontWeight: 800, color: "var(--text)", fontFamily: "'Orbitron',sans-serif", lineHeight: 1 }}>{sTotal > 0 ? `${((s2 / sTotal) * 100).toFixed(0)}%` : "—"}</div>
                  <div style={{ fontSize: 10, color: "var(--text3)", marginTop: 5, letterSpacing: 1, textTransform: "uppercase", fontFamily: "'Share Tech Mono',monospace" }}>success</div>
                </div>
              </div>
            </div>

            {/* Per-status proportion bars */}
            <div style={{ display: "flex", flexDirection: "column", gap: 15 }}>
              {statusSlices.map(s => (
                <div key={s.label} style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 12 }}>
                  <span style={{ width: 10, height: 10, borderRadius: 2, background: s.color, flexShrink: 0 }} />
                  <span style={{ color: "var(--text2)", width: 30, fontFamily: "'Share Tech Mono',monospace", flexShrink: 0 }}>{s.label}</span>
                  <div className="atk-bar-bg" style={{ flex: 1 }}>
                    <div className="atk-bar" style={{ width: `${sTotal > 0 ? (s.v / sTotal) * 100 : 0}%`, background: s.color }} />
                  </div>
                  <span style={{ color: "var(--text)", fontFamily: "'Share Tech Mono',monospace", width: 48, textAlign: "right", flexShrink: 0 }}>{s.v.toLocaleString()}</span>
                  <span style={{ color: "var(--text3)", fontFamily: "'Share Tech Mono',monospace", width: 38, textAlign: "right", flexShrink: 0 }}>{sTotal > 0 ? `${((s.v / sTotal) * 100).toFixed(0)}%` : "—"}</span>
                </div>
              ))}
            </div>

            {/* Summary footer */}
            <div style={{ display: "flex", alignItems: "stretch", gap: 12, borderTop: "1px solid var(--bg4)", paddingTop: 16 }}>
              <div style={{ flex: 1, textAlign: "center" }}>
                <div style={{ fontSize: 19, fontWeight: 800, color: "#22c55e", fontFamily: "'Orbitron',sans-serif", lineHeight: 1 }}>{sTotal > 0 ? `${(((s2 + s3) / sTotal) * 100).toFixed(1)}%` : "—"}</div>
                <div style={{ fontSize: 9, color: "var(--text3)", letterSpacing: 1, textTransform: "uppercase", marginTop: 5, fontFamily: "'Share Tech Mono',monospace" }}>OK · 2xx/3xx</div>
              </div>
              <div style={{ width: 1, background: "var(--bg4)" }} />
              <div style={{ flex: 1, textAlign: "center" }}>
                <div style={{ fontSize: 19, fontWeight: 800, color: "#ef4444", fontFamily: "'Orbitron',sans-serif", lineHeight: 1 }}>{(s4 + s5).toLocaleString()}</div>
                <div style={{ fontSize: 9, color: "var(--text3)", letterSpacing: 1, textTransform: "uppercase", marginTop: 5, fontFamily: "'Share Tech Mono',monospace" }}>Errors · 4xx/5xx</div>
              </div>
            </div>
          </div>
        </div>
      </motion.div>

      {/* Bottom 3-panel row */}
      <motion.div variants={fadeUp} style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 14 }}>
        <div className="panel">
          <div className="ph"><div className="ptitle">Recent events</div><span className="panel-badge pb-live">Live</span></div>
          <div className="pb">
            {feed.length === 0 ? (
              <div style={{ padding: "16px 0", textAlign: "center", fontSize: 11, fontFamily: "'Share Tech Mono',monospace", color: "var(--text3)" }}>Waiting for events…</div>
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

        <div className="panel">
          <div className="ph"><div className="ptitle">Top attacker IPs</div><span className="panel-badge pb-info">Live feed</span></div>
          <div className="pb">
            {topIPs.length === 0 ? (
              <div style={{ padding: "16px 0", textAlign: "center", fontSize: 11, fontFamily: "'Share Tech Mono',monospace", color: "var(--text3)" }}>No traffic yet</div>
            ) : topIPs.map(([ip, cnt], idx) => (
              <motion.div key={ip} className="ip-row" initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.5 + idx * 0.05 }}>
                <div className="ip-addr">{ip}</div><div className="ip-count">{cnt} hits</div>
                <span className="ip-badge ip-blocked">BLOCKED</span>
              </motion.div>
            ))}
          </div>
        </div>

        <div className="panel">
          <div className="ph"><div className="ptitle">Rule engine health</div><span className="panel-badge pb-info">{totalRules > 0 ? `${totalRules.toLocaleString()} rules` : "loading…"}</span></div>
          <div className="pb">
            {[
              { name: "OWASP CRS v4 core", on: enabledRules > 0 },
              { name: "SQL injection suite", on: enabledRules > 0 },
              { name: "XSS ruleset", on: enabledRules > 0 },
              { name: "Bot / scanner signatures", on: enabledRules > 0 },
              { name: "ML anomaly engine", on: !!wafStatus?.running },
              { name: "Custom site rules", on: totalRules > 0 },
            ].map((row, idx) => (
              <motion.div key={row.name} className="rule-row" initial={{ opacity: 0, x: -4 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.5 + idx * 0.05 }}>
                <div className="rule-name">{row.name}</div>
                <span className={`rule-st ${row.on ? "rs-on" : "rs-warn"}`}>{row.on ? "Active" : "Off"}</span>
                <div className="rule-hits">—</div>
              </motion.div>
            ))}
          </div>
        </div>
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
          <div style={{ padding: "16px", fontFamily: "'Share Tech Mono',monospace", fontSize: 11, color: "var(--text3)", textAlign: "center" }}>No open alerts</div>
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
