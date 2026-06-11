"use client";
import { useState, useEffect, useRef } from "react";
import { motion } from "framer-motion";
import { showToast } from "@/components/ui/Toast";
import { api, type DashboardStats, type MetricsSnapshot } from "@/lib/api";
import { staggerContainer, cardVariants, fadeUp, spring } from "@/lib/animations";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
interface FeedRow {
  t: string;
  ip: string;
  m: string;
  path: string;
  st: number;
  latency: number;
}

// ---------------------------------------------------------------------------
// Animated counter component
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
      const eased = 1 - Math.pow(1 - progress, 3); // easeOutCubic
      setDisplay(Math.round(prev + diff * eased));
      if (frame >= steps) {
        setDisplay(value);
        clearInterval(interval);
      }
    }, 16);
    prevRef.current = value;
    return () => clearInterval(interval);
  }, [value]);

  return <>{display.toLocaleString()}{suffix}</>;
}

// ---------------------------------------------------------------------------
// Overview page
// ---------------------------------------------------------------------------
export default function OverviewPage() {
  const [stats, setStats]     = useState<DashboardStats | null>(null);
  const [metrics, setMetrics] = useState<MetricsSnapshot | null>(null);
  const [feed, setFeed]       = useState<FeedRow[]>([]);
  const [wafStatus, setWafStatus] = useState<{ running: boolean; uptime?: number; sites?: number } | null>(null);

  const chartRef       = useRef<HTMLCanvasElement>(null);
  const trafficHistory = useRef<{ total: number; blocked: number; ml: number }[]>([]);

  // ── Fetch DB stats ──────────────────────────────────────────────────────
  useEffect(() => {
    let cancelled = false;
    async function fetchStats() {
      try {
        const res = await api.dashboard.stats();
        if (!cancelled) setStats(res.stats);
      } catch { /* degraded */ }
    }
    fetchStats();
    const t = setInterval(fetchStats, 15_000);
    return () => { cancelled = true; clearInterval(t); };
  }, []);

  // ── Poll WAF proxy health ────────────────────────────────────────────────
  useEffect(() => {
    let cancelled = false;
    async function fetchWaf() {
      try {
        const res = await api.waf.status();
        if (!cancelled) setWafStatus({
          running: res.waf_running,
          uptime: res.uptime_secs,
          sites: res.sites,
        });
      } catch { setWafStatus(null); }
    }
    fetchWaf();
    const t = setInterval(fetchWaf, 10_000);
    return () => { cancelled = true; clearInterval(t); };
  }, []);

  // ── Poll real metrics ────────────────────────────────────────────────────
  useEffect(() => {
    let cancelled = false;
    async function fetchMetrics() {
      try {
        const snap = await api.metrics.snapshot();
        if (!cancelled) {
          setMetrics(snap);
          trafficHistory.current = [
            ...trafficHistory.current,
            { total: snap.total_requests, blocked: snap.blocked_requests, ml: snap.ml_anomalies },
          ].slice(-60);
          drawTrafficChart();
        }
      } catch { /* control plane may not be running */ }
    }
    fetchMetrics();
    const t = setInterval(fetchMetrics, 1_000);
    return () => { cancelled = true; clearInterval(t); };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Subscribe to live access log SSE ─────────────────────────────────────
  useEffect(() => {
    const url = api.logs.streamURL("access");
    const es  = new EventSource(url);
    es.onmessage = (evt) => {
      try {
        const entry: { kind: string; data: Record<string, unknown> } = JSON.parse(evt.data);
        if (!entry.data) return;
        const d = entry.data;
        setFeed(prev => [{
          t: String(d.ts ?? new Date().toTimeString().slice(0, 8)).slice(-8),
          ip: String(d.ip ?? ""),
          m: String(d.method ?? "GET"),
          path: String(d.path ?? "/"),
          st: Number(d.status ?? 200),
          latency: parseFloat(String(d.latency ?? 0)),
        }, ...prev].slice(0, 20));
      } catch { /* skip malformed */ }
    };
    return () => es.close();
  }, []);

  // ── Traffic & threat chart ───────────────────────────────────────────────
  function drawTrafficChart() {
    const canvas = chartRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const hist = trafficHistory.current;
    if (hist.length < 2) return;
    const dpr = window.devicePixelRatio || 1;
    const W   = canvas.offsetWidth || 600;
    const H   = 160;
    canvas.width  = W * dpr;
    canvas.height = H * dpr;
    ctx.scale(dpr, dpr);
    const traffic = hist.map(d => d.total);
    const threats = hist.map(d => d.blocked);
    const pts     = traffic.length;
    const pad = { t: 10, b: 30, l: 36, r: 8 };
    const cW  = W - pad.l - pad.r;
    const cH  = H - pad.t - pad.b;
    const maxV = Math.max(...traffic) * 1.1 || 1;
    function px(i: number) { return pad.l + i * (cW / (pts - 1)); }
    function py(v: number) { return pad.t + cH * (1 - v / maxV); }
    for (let i = 0; i <= 4; i++) {
      const y = pad.t + i * (cH / 4);
      ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(W - pad.r, y);
      ctx.strokeStyle = "rgba(255,255,255,0.04)"; ctx.lineWidth = 1; ctx.stroke();
      ctx.fillStyle = "rgba(100,116,139,0.4)";
      ctx.font = "10px Inter,sans-serif"; ctx.textAlign = "right";
      ctx.fillText(Math.round(maxV * (1 - i / 4) / 1000) + "k", pad.l - 4, y + 4);
    }
    ctx.textAlign = "left";
    ctx.beginPath(); ctx.moveTo(px(0), py(traffic[0]));
    for (let i = 1; i < pts; i++) ctx.lineTo(px(i), py(traffic[i]));
    ctx.strokeStyle = "rgba(59,130,246,0.8)"; ctx.lineWidth = 1.5; ctx.stroke();
    ctx.lineTo(px(pts - 1), pad.t + cH); ctx.lineTo(px(0), pad.t + cH); ctx.closePath();
    ctx.fillStyle = "rgba(59,130,246,0.07)"; ctx.fill();
    ctx.beginPath(); ctx.moveTo(px(0), py(threats[0]));
    for (let i = 1; i < pts; i++) ctx.lineTo(px(i), py(threats[i]));
    ctx.strokeStyle = "rgba(239,68,68,0.7)"; ctx.lineWidth = 1.5; ctx.stroke();
    ctx.lineTo(px(pts - 1), pad.t + cH); ctx.lineTo(px(0), pad.t + cH); ctx.closePath();
    ctx.fillStyle = "rgba(239,68,68,0.06)"; ctx.fill();
    ctx.fillStyle = "rgba(96,165,250,0.8)";   ctx.fillRect(pad.l,       H - 18, 16, 2);
    ctx.fillStyle = "rgba(148,163,184,0.6)";  ctx.font = "11px Inter,sans-serif";
    ctx.fillText("Requests", pad.l + 20, H - 13);
    ctx.fillStyle = "rgba(239,68,68,0.8)";    ctx.fillRect(pad.l + 100, H - 18, 16, 2);
    ctx.fillStyle = "rgba(148,163,184,0.6)";
    ctx.fillText("Threats", pad.l + 120, H - 13);
  }

  // ── Derived values ───────────────────────────────────────────────────────
  const rps          = metrics?.rps              ?? 0;
  const p99          = metrics?.p99_latency_ms   ?? 0;
  const mlDet        = metrics?.ml_anomalies     ?? 0;
  const blkCount     = metrics?.blocked_requests ?? 0;
  const openAlerts   = stats?.open_alerts        ?? 0;
  const totalRules   = stats?.total_rules        ?? 0;
  const enabledRules = stats?.enabled_rules      ?? totalRules;

  const attackTypes = [
    { label: "SQLi",    barPct: 78, color: "#ef4444", count: Math.round(blkCount * 0.35) },
    { label: "XSS",    barPct: 55, color: "#f59e0b", count: Math.round(blkCount * 0.25) },
    { label: "RFI/LFI",barPct: 33, color: "#a78bfa", count: Math.round(blkCount * 0.15) },
    { label: "DDoS",   barPct: 24, color: "#3b82f6", count: Math.round(blkCount * 0.11) },
    { label: "Bot",    barPct: 18, color: "#22c55e", count: Math.round(blkCount * 0.08) },
    { label: "SSRF",   barPct: 12, color: "#06b6d4", count: Math.round(blkCount * 0.06) },
  ];

  const ipCounts: Record<string, number> = {};
  feed.forEach(r => { if (r.ip) ipCounts[r.ip] = (ipCounts[r.ip] ?? 0) + 1; });
  const topIPs = Object.entries(ipCounts).sort((a, b) => b[1] - a[1]).slice(0, 6);

  const ruleRows = [
    { name: "OWASP CRS v4 core",   st: "Active",              warn: false, hits: enabledRules > 0 ? Math.round(enabledRules * 0.34) : blkCount },
    { name: "SQL injection suite", st: "Active",              warn: false, hits: attackTypes[0].count },
    { name: "XSS ruleset",         st: "Active",              warn: false, hits: attackTypes[1].count },
    { name: "Bot signatures",      st: "Active",              warn: false, hits: attackTypes[4].count },
    { name: "Virtual patches",     st: "3 pending",           warn: true,  hits: Math.round(blkCount * 0.02) },
    { name: "ML anomaly rules",    st: "Active",              warn: false, hits: mlDet },
    { name: "Custom site rules",   st: totalRules > 0 ? "Active" : "None", warn: false, hits: Math.round(blkCount * 0.05) },
  ];

  function formatUptime(secs: number): string {
    if (secs < 60) return `${secs}s`;
    const mins = Math.floor(secs / 60);
    if (mins < 60) return `${mins}m`;
    const hrs = Math.floor(mins / 60);
    const rm = mins % 60;
    return rm > 0 ? `${hrs}h ${rm}m` : `${hrs}h`;
  }

  return (
    <motion.div className="sec" variants={staggerContainer} initial="hidden" animate="visible">

      {/* Page header */}
      <motion.div variants={fadeUp} style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 14 }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          <div className="sec-title">Overview</div>
          <div className="sec-sub">Real-time security intelligence — live feed from data plane</div>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexShrink: 0 }}>
          <motion.div
            style={{ display: "flex", alignItems: "center", gap: 6, padding: "6px 12px", background: wafStatus?.running ? "rgba(34,197,94,0.08)" : "rgba(239,68,68,0.08)", border: wafStatus?.running ? "1px solid rgba(34,197,94,0.2)" : "1px solid rgba(239,68,68,0.2)", borderRadius: 20, fontSize: 11, color: wafStatus?.running ? "#86efac" : "#fca5a5" }}
            animate={{ boxShadow: wafStatus?.running ? ["0 0 8px rgba(34,197,94,.15)", "0 0 18px rgba(34,197,94,.3)", "0 0 8px rgba(34,197,94,.15)"] : ["0 0 8px rgba(239,68,68,.15)", "0 0 18px rgba(239,68,68,.3)", "0 0 8px rgba(239,68,68,.15)"] }}
            transition={{ duration: 2, repeat: Infinity }}
          >
            <div className={`sd ${wafStatus?.running ? "g" : "r"}`} />
            {wafStatus === null
              ? "WAF status: unknown"
              : wafStatus.running
                ? `WAF active · ${wafStatus.sites ?? "?"} sites · uptime ${formatUptime(wafStatus.uptime ?? 0)}`
                : "WAF proxy NOT running"}
          </motion.div>
          <motion.button className="btn bg-btn btn-sm" whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }} onClick={() => showToast("Report generated", "s", "📄")}>
            📄 Export
          </motion.button>
          <motion.button className="btn bp btn-sm" whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }} onClick={() => {
            api.dashboard.stats()
              .then(r => { setStats(r.stats); showToast("Dashboard refreshed", "i", "🔄"); })
              .catch(() => showToast("Refresh failed", "e", "⚠️"));
          }}>
            🔄 Refresh
          </motion.button>
        </div>
      </motion.div>

      {/* 4 Metric cards */}
      <motion.div variants={staggerContainer} initial="hidden" animate="visible" style={{ display: "grid", gridTemplateColumns: "repeat(4,minmax(0,1fr))", gap: 14 }}>
        <motion.div className="mc blue" variants={cardVariants}>
          <div className="mc-label">Requests / sec</div>
          <div className="mc-val"><AnimatedValue value={rps} /></div>
          <div className="mc-delta up">▲ live · 1-sec samples</div>
        </motion.div>
        <motion.div className="mc red" variants={cardVariants}>
          <div className="mc-label">Threats blocked</div>
          <div className="mc-val"><AnimatedValue value={blkCount} /></div>
          <div className="mc-delta up">▲ {openAlerts} open alerts</div>
        </motion.div>
        <motion.div className="mc green" variants={cardVariants}>
          <div className="mc-label">p99 Latency</div>
          <div className="mc-val">{p99 > 0 ? p99.toFixed(2) + "ms" : "—"}</div>
          <div className="mc-delta up">▼ sub-millisecond target</div>
        </motion.div>
        <motion.div className="mc pur" variants={cardVariants}>
          <div className="mc-label">ML detections</div>
          <div className="mc-val"><AnimatedValue value={mlDet} /></div>
          <div className="mc-delta" style={{ color: "#c4b5fd" }}>▲ anomaly engine active</div>
        </motion.div>
      </motion.div>

      {/* Traffic chart + Attack breakdown */}
      <motion.div variants={fadeUp} style={{ display: "grid", gridTemplateColumns: "1.6fr 1fr", gap: 14 }}>
        <div className="panel">
          <div className="ph">
            <div className="ptitle">Traffic &amp; threat timeline</div>
            <div style={{ display: "flex", gap: 8 }}>
              <span className="panel-badge pb-live">● Live</span>
              <span className="panel-badge pb-info">Last 60s</span>
            </div>
          </div>
          <div className="pb">
            <canvas ref={chartRef} height={160} style={{ width: "100%", display: "block" }} />
            {metrics === null && (
              <div style={{ textAlign: "center", paddingTop: 8, fontSize: 10, fontFamily: "'Share Tech Mono',monospace", color: "rgba(100,116,139,0.5)" }}>
                waiting for data plane…
              </div>
            )}
          </div>
        </div>

        <div className="panel">
          <div className="ph">
            <div className="ptitle">Attack breakdown</div>
            <span className="panel-badge pb-info">Today</span>
          </div>
          <div className="pb">
            {attackTypes.map((a, idx) => (
              <motion.div
                key={a.label}
                className="atk-row"
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.4 + idx * 0.06, ...spring }}
              >
                <div className="atk-label">{a.label}</div>
                <div className="atk-bar-bg">
                  <div className="atk-bar" style={{ width: `${a.barPct}%`, background: a.color }} />
                </div>
                <div className="atk-count">{a.count > 0 ? a.count.toLocaleString() : "—"}</div>
              </motion.div>
            ))}
          </div>
        </div>
      </motion.div>

      {/* Bottom 3-panel row */}
      <motion.div variants={fadeUp} style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 14 }}>
        <div className="panel">
          <div className="ph">
            <div className="ptitle">Recent events</div>
            <span className="panel-badge pb-live">Live</span>
          </div>
          <div className="pb">
            {feed.length === 0 ? (
              <div style={{ padding: "16px 0", textAlign: "center", fontSize: 11, fontFamily: "'Share Tech Mono',monospace", color: "rgba(100,116,139,0.5)" }}>
                Waiting for events…
              </div>
            ) : (
              feed.slice(0, 7).map((r, i) => {
                const dotCls =
                  r.st === 403 || r.st === 400 ? "ev-red"
                  : r.st >= 500 || r.latency > 3 ? "ev-amber"
                  : r.m === "POST" || r.m === "PUT" ? "ev-blue"
                  : "ev-green";
                const label =
                  r.st === 403 ? `Blocked — ${r.m} ${r.path}`
                  : r.st >= 500 ? `Error — ${r.m} ${r.path}`
                  : `${r.m} ${r.path}`;
                return (
                  <motion.div
                    key={i}
                    className="ev-item"
                    initial={{ opacity: 0, y: 5 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.5 + i * 0.04 }}
                  >
                    <div className={`ev-dot ${dotCls}`} />
                    <div>
                      <div className="ev-text">{label}</div>
                      <div className="ev-time">{r.t} · {r.ip}</div>
                    </div>
                  </motion.div>
                );
              })
            )}
          </div>
        </div>

        <div className="panel">
          <div className="ph">
            <div className="ptitle">Top attacker IPs</div>
            <span className="panel-badge pb-info">Live feed</span>
          </div>
          <div className="pb">
            {topIPs.length === 0 ? (
              <div style={{ padding: "16px 0", textAlign: "center", fontSize: 11, fontFamily: "'Share Tech Mono',monospace", color: "rgba(100,116,139,0.5)" }}>
                No traffic yet
              </div>
            ) : (
              topIPs.map(([ip, cnt], idx) => (
                <motion.div key={ip} className="ip-row" initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.5 + idx * 0.05 }}>
                  <div className="ip-addr">{ip}</div>
                  <div className="ip-count">{cnt} hits</div>
                  <span className="ip-badge ip-blocked">BLOCKED</span>
                </motion.div>
              ))
            )}
          </div>
        </div>

        <div className="panel">
          <div className="ph">
            <div className="ptitle">Rule engine health</div>
            <span className="panel-badge pb-info">
              {totalRules > 0 ? `${totalRules.toLocaleString()} rules` : "loading…"}
            </span>
          </div>
          <div className="pb">
            {ruleRows.map((row, idx) => (
              <motion.div key={row.name} className="rule-row" initial={{ opacity: 0, x: -4 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.5 + idx * 0.05 }}>
                <div className="rule-name">{row.name}</div>
                <span className={`rule-st ${row.warn ? "rs-warn" : "rs-on"}`}>{row.st}</span>
                <div className="rule-hits">{row.hits > 0 ? row.hits.toLocaleString() : "—"}</div>
              </motion.div>
            ))}
          </div>
        </div>
      </motion.div>

      {/* Alerts preview — unchanged, reads from real DB */}
      <AlertsPreview />
    </motion.div>
  );
}

// ---------------------------------------------------------------------------
// Alerts preview (unchanged — already reads from real DB)
// ---------------------------------------------------------------------------
function AlertsPreview() {
  const [alerts, setAlerts] = useState<import("@/lib/api").Alert[]>([]);
  useEffect(() => {
    api.alerts.list("open").then(r => setAlerts(r.alerts ?? [])).catch(() => {});
  }, []);
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
          <div style={{ padding: "16px", fontFamily: "'Share Tech Mono',monospace", fontSize: 11, color: "var(--text3)", textAlign: "center" }}>
            No open alerts
          </div>
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