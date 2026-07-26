"use client";
import { useState, useEffect, useRef, useCallback } from "react";
import { motion } from "framer-motion";
import { showToast } from "@/components/ui/Toast";
import { api, type TrafficBucket, type MetricsSnapshot } from "@/lib/api";
import { staggerContainer, cardVariants, fadeUp, spring } from "@/lib/animations";

interface AccessRow {
  ts:      string;
  site:    string;
  method:  string;
  path:    string;
  ip:      string;
  status:  number;
  latency: number;
  score:   number;
  action:  string;
}

export default function TrafficPage() {
  const [rows, setRows]       = useState<AccessRow[]>([]);
  const [metrics, setMetrics] = useState<MetricsSnapshot | null>(null);
  const [buckets, setBuckets] = useState<TrafficBucket[]>([]);
  const [search, setSearch]   = useState("");
  const [siteFilter, setSiteFilter]     = useState("All Sites");
  const [methodFilter, setMethodFilter] = useState("All Methods");
  const [statusFilter, setStatusFilter] = useState("All Status");

  const chartRef  = useRef<HTMLCanvasElement>(null);
  const liveSites = useRef<Set<string>>(new Set());

  // ── SSE: live access events ─────────────────────────────────────────────────
  useEffect(() => {
    const es = new EventSource(api.logs.streamURL());
    es.onmessage = (evt) => {
      try {
        const { kind, data } = JSON.parse(evt.data) as { kind: string; data: Record<string, unknown> };
        if (kind === "access" && data) {
          const site   = String(data.site   ?? "");
          const status = Number(data.status ?? 200);
          const score  = Number(data.score  ?? 0);
          if (site) liveSites.current.add(site);
          setRows(prev => [{
            ts:      String(data.ts ?? new Date().toTimeString().slice(0, 8)).slice(-8),
            site,
            method:  String(data.method  ?? "GET"),
            path:    String(data.path    ?? "/"),
            ip:      String(data.ip      ?? ""),
            status,
            latency: parseFloat(String(data.latency ?? "0")),
            score,
            action:  status === 403 || score >= 5 ? "BLOCKED" : "ALLOWED",
          }, ...prev].slice(0, 400));
        }
      } catch { /* skip malformed */ }
    };
    return () => es.close();
  }, []);

  // ── Metrics snapshot every 2 s ─────────────────────────────────────────────
  useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      try { const snap = await api.metrics.snapshot(); if (!cancelled) setMetrics(snap); }
      catch { /* degraded */ }
    };
    poll();
    const t = setInterval(poll, 2000);
    return () => { cancelled = true; clearInterval(t); };
  }, []);

  // ── Traffic history for chart ───────────────────────────────────────────────
  useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      try {
        const res = await api.traffic.history();
        if (!cancelled && res.buckets?.length) setBuckets(res.buckets);
      } catch { /* degraded */ }
    };
    poll();
    const t = setInterval(poll, 5000);
    return () => { cancelled = true; clearInterval(t); };
  }, []);

  // ── Draw chart ──────────────────────────────────────────────────────────────
  const drawChart = useCallback(() => {
    const canvas = chartRef.current;
    if (!canvas || buckets.length < 2) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const dpr = window.devicePixelRatio || 1;
    const W = canvas.offsetWidth || 600;
    const H = 110;
    canvas.width  = W * dpr;
    canvas.height = H * dpr;
    ctx.scale(dpr, dpr);
    const reqs    = buckets.map(b => b.reqs);
    const blocked = buckets.map(b => b.blocked);
    const pts     = reqs.length;
    const maxV    = Math.max(...reqs, 1) * 1.15;
    const pad     = { t: 8, b: 26, l: 32, r: 6 };
    const cW = W - pad.l - pad.r;
    const cH = H - pad.t - pad.b;
    const px = (i: number) => pad.l + i * (cW / Math.max(pts - 1, 1));
    const py = (v: number) => pad.t + cH * (1 - v / maxV);
    ctx.clearRect(0, 0, W, H);
    for (let i = 0; i <= 4; i++) {
      const y = pad.t + i * (cH / 4);
      ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(W - pad.r, y);
      ctx.strokeStyle = "rgba(255,255,255,0.04)"; ctx.lineWidth = 1; ctx.stroke();
      ctx.fillStyle = "rgba(100,116,139,0.5)"; ctx.font = "9px monospace"; ctx.textAlign = "right";
      ctx.fillText(String(Math.round(maxV * (1 - i / 4))), pad.l - 3, y + 3);
    }
    ctx.textAlign = "left";
    const drawLine = (data: number[], stroke: string, fill: string) => {
      ctx.beginPath(); ctx.moveTo(px(0), py(data[0]));
      for (let i = 1; i < pts; i++) ctx.lineTo(px(i), py(data[i]));
      ctx.strokeStyle = stroke; ctx.lineWidth = 1.5; ctx.stroke();
      ctx.lineTo(px(pts - 1), pad.t + cH); ctx.lineTo(px(0), pad.t + cH); ctx.closePath();
      ctx.fillStyle = fill; ctx.fill();
    };
    drawLine(reqs,    "rgba(59,130,246,0.85)", "rgba(59,130,246,0.07)");
    drawLine(blocked, "rgba(239,68,68,0.75)",  "rgba(239,68,68,0.06)");
    ctx.fillStyle = "rgba(96,165,250,0.8)";  ctx.fillRect(pad.l, H - 16, 14, 2);
    ctx.fillStyle = "rgba(148,163,184,0.6)"; ctx.font = "10px Inter,sans-serif"; ctx.fillText("Req/s", pad.l + 18, H - 12);
    ctx.fillStyle = "rgba(239,68,68,0.8)";   ctx.fillRect(pad.l + 80, H - 16, 14, 2);
    ctx.fillStyle = "rgba(148,163,184,0.6)"; ctx.fillText("Blocked/s", pad.l + 98, H - 12);
  }, [buckets]);

  useEffect(() => { drawChart(); }, [drawChart]);

  // ── Derived ─────────────────────────────────────────────────────────────────
  const ipMap: Record<string, number> = {};
  rows.forEach(r => { if (r.ip) ipMap[r.ip] = (ipMap[r.ip] ?? 0) + 1; });
  const topIPs = Object.entries(ipMap).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const maxIp  = topIPs[0]?.[1] ?? 1;

  const displayed = rows.filter(r => {
    if (siteFilter !== "All Sites"     && r.site   !== siteFilter)    return false;
    if (methodFilter !== "All Methods" && r.method !== methodFilter)  return false;
    if (statusFilter === "2xx OK"      && (r.status < 200 || r.status > 299)) return false;
    if (statusFilter === "403 Blocked" && r.status !== 403)           return false;
    if (search) {
      const q = search.toLowerCase();
      if (!r.ip.includes(q) && !r.path.toLowerCase().includes(q) && !r.site.includes(q)) return false;
    }
    return true;
  });

  const siteList = Array.from(liveSites.current);

  return (
    <motion.div className="sec" variants={staggerContainer} initial="hidden" animate="visible">
      <motion.div variants={fadeUp} style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 14 }}>
        <div>
          <div className="sec-title">📊 Traffic Analysis</div>
          <div className="sec-sub">Live request stream · real-time anomaly scoring · source IP analysis</div>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <select className="fsel" value={siteFilter} onChange={e => setSiteFilter(e.target.value)}>
            <option>All Sites</option>
            {siteList.map(s => <option key={s}>{s}</option>)}
          </select>
          <motion.button className="btn bp btn-sm" whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }} onClick={() => showToast("Export coming in Phase 5", "i", "📤")}>📤 Export</motion.button>
        </div>
      </motion.div>

      {/* KPIs */}
      <motion.div variants={staggerContainer} initial="hidden" animate="visible" style={{ display: "grid", gridTemplateColumns: "repeat(4,minmax(0,1fr))", gap: 12 }}>
        {([
          { label: "Req / sec",      val: metrics ? metrics.rps.toFixed(1)                    : "—", cls: "blue" },
          { label: "Blocked total",  val: metrics ? metrics.blocked_requests.toLocaleString() : "—", cls: "red"  },
          { label: "p99 Latency",    val: metrics ? metrics.p99_latency_ms.toFixed(1) + " ms"  : "—", cls: "green"},
          { label: "eBPF Drops",     val: metrics ? metrics.ebpf_drops.toLocaleString()        : "—", cls: "pur" },
        ] as { label: string; val: string; cls: string }[]).map(k => (
          <motion.div key={k.label} className={`mc ${k.cls}`} variants={cardVariants}>
            <div className="mc-label">{k.label}</div>
            <div className="mc-val">{k.val}</div>
          </motion.div>
        ))}
      </motion.div>

      {/* Chart + Top IPs */}
      <motion.div variants={fadeUp} style={{ display: "grid", gridTemplateColumns: "1.6fr 1fr", gap: 14 }}>
        <div className="panel">
          <div className="ph">
            <div className="ptitle">⚡ Request rate (live)</div>
            <div style={{ display: "flex", gap: 6 }}>
              <span className="panel-badge pb-live">● Live</span>
              <span className="panel-badge pb-info">Last 60 s</span>
            </div>
          </div>
          <div className="pb">
            <canvas ref={chartRef} height={110} style={{ width: "100%", display: "block" }} />
            {buckets.length === 0 && (
              <div style={{ textAlign: "center", paddingTop: 8, fontSize: 14, fontFamily: "var(--font-mono)", color: "rgba(100,116,139,0.5)" }}>
                waiting for traffic data…
              </div>
            )}
          </div>
        </div>

        <div className="panel">
          <div className="ph">
            <div className="ptitle">🌐 Top Source IPs</div>
            <span className="panel-badge pb-live">Live feed</span>
          </div>
          <div className="pb">
            {topIPs.length === 0 ? (
              <div style={{ padding: "16px 0", textAlign: "center", fontSize: 13, fontFamily: "var(--font-mono)", color: "rgba(100,116,139,0.5)" }}>
                No traffic yet
              </div>
            ) : (
              topIPs.map(([ip, cnt], idx) => (
                <motion.div key={ip} className="eprow" style={{ marginBottom: 7 }} initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: idx * 0.04 }}>
                  <span className="eppath" style={{ fontSize: 14, minWidth: 120 }}>{ip}</span>
                  <div className="epbw" style={{ flex: 1 }}>
                    <div className="pwrap">
                      <div className="pbar" style={{ width: `${Math.round(cnt / maxIp * 100)}%`, background: cnt > 5 ? "var(--red-b)" : "var(--cyan)" }} />
                    </div>
                  </div>
                  <span className="epcount">{cnt}</span>
                </motion.div>
              ))
            )}
          </div>
        </div>
      </motion.div>

      {/* Live request log */}
      <motion.div className="panel" variants={fadeUp}>
        <div className="ph">
          <div className="ptitle">📜 Live Request Log</div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
            <div style={{ position: "relative" }}>
              <span style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)", color: "var(--text3)", fontSize: 14, pointerEvents: "none" }}>🔍</span>
              <input className="fi2" type="text" placeholder="Filter by IP, path, site…" style={{ width: 200 }}
                value={search} onChange={e => setSearch(e.target.value)} />
            </div>
            <select className="fsel" value={methodFilter} onChange={e => setMethodFilter(e.target.value)}>
              <option>All Methods</option>
              {["GET","POST","PUT","DELETE","PATCH","HEAD"].map(m => <option key={m}>{m}</option>)}
            </select>
            <select className="fsel" value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
              <option>All Status</option>
              <option>2xx OK</option>
              <option>403 Blocked</option>
            </select>
            <span className="panel-badge pb-live">● {rows.length} events</span>
          </div>
        </div>
        <div className="tw" style={{ maxHeight: 380, overflowY: "auto" }}>
          {displayed.length === 0 ? (
            <div style={{ padding: "24px", textAlign: "center", fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--text3)" }}>
              {rows.length === 0 ? "Waiting for live events…" : "No rows match current filters"}
            </div>
          ) : (
            <table>
              <thead>
                <tr><th>Time</th><th>Site</th><th>Method</th><th>Path</th><th>Source IP</th><th>Status</th><th>Latency</th><th>Score</th><th>Action</th></tr>
              </thead>
              <tbody>
                {displayed.slice(0, 200).map((r, i) => (
                  <motion.tr key={i} initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: Math.min(i * 0.01, 0.3) }}>
                    <td className="td3">{r.ts}</td>
                    <td className="td2">{r.site || "—"}</td>
                    <td><span className={`fm2 ${r.method.toLowerCase()}`}>{r.method}</span></td>
                    <td style={{ maxWidth: 180, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.path}</td>
                    <td className="td2">{r.ip}</td>
                    <td style={{ color: r.status === 403 ? "var(--red-b)" : r.status >= 500 ? "var(--amber)" : "var(--green)" }}>{r.status}</td>
                    <td className="td3">{r.latency > 0 ? r.latency.toFixed(1) + " ms" : "—"}</td>
                    <td style={{ color: r.score > 5 ? "var(--red-b)" : r.score > 2 ? "var(--amber)" : "var(--text3)" }}>{r.score > 0 ? r.score : "—"}</td>
                    <td><span className={`bdg ${r.action === "BLOCKED" ? "br" : "bgr"}`}>{r.action}</span></td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </motion.div>
    </motion.div>
  );
}