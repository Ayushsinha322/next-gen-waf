"use client";
import { useState, useEffect, useRef } from "react";
import { motion } from "framer-motion";
import { api, type MLStats } from "@/lib/api";
import { staggerContainer, cardVariants, fadeUp, spring } from "@/lib/animations";

// ── Arc gauge (SVG) ───────────────────────────────────────────────────────────
function ArcGauge({ value, label, color }: { value: number; label: string; color: string }) {
  const pct = Math.max(0, Math.min(1, value));
  const r = 52, cx = 64, cy = 64;
  const startAngle = -210, sweepAngle = 240;
  const toRad = (d: number) => (d * Math.PI) / 180;
  const arc = (deg: number) => ({
    x: cx + r * Math.cos(toRad(deg)),
    y: cy + r * Math.sin(toRad(deg)),
  });
  const s = arc(startAngle);
  const e = arc(startAngle + sweepAngle * pct);
  const large = sweepAngle * pct > 180 ? 1 : 0;
  const bg1 = arc(startAngle);
  const bg2 = arc(startAngle + sweepAngle);
  const displayVal = (pct * 100).toFixed(1);

  return (
    <svg viewBox="0 0 128 90" className="ml-gauge-svg">
      <path d={`M${bg1.x},${bg1.y} A${r},${r} 0 1,1 ${bg2.x},${bg2.y}`} fill="none" stroke="rgba(255,255,255,.07)" strokeWidth="8" strokeLinecap="round" />
      {pct > 0 && (
        <path d={`M${s.x},${s.y} A${r},${r} 0 ${large},1 ${e.x},${e.y}`} fill="none" stroke={color} strokeWidth="8" strokeLinecap="round" />
      )}
      <text x={cx} y={cy - 4} textAnchor="middle" fill="#f1f5f9" fontSize="18" fontFamily="var(--font-mono)" fontWeight="700">{displayVal}%</text>
      <text x={cx} y={cy + 14} textAnchor="middle" fill="rgba(148,163,184,.7)" fontSize="9" fontFamily="Inter,sans-serif" letterSpacing=".5">{label}</text>
    </svg>
  );
}

// ── Mini sparkline ────────────────────────────────────────────────────────────
function Spark({ data, color }: { data: number[]; color: string }) {
  if (data.length < 2) return <svg viewBox="0 0 80 24" className="ml-spark" />;
  const max = Math.max(...data, 1);
  const pts = data.map((v, i) =>
    `${(i / (data.length - 1)) * 80},${4 + (1 - v / max) * 18}`
  ).join(" ");
  return (
    <svg viewBox="0 0 80 24" className="ml-spark" preserveAspectRatio="none">
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" />
    </svg>
  );
}

export default function MLPage() {
  const [stats, setStats]     = useState<MLStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(false);
  const anomHist = useRef<number[]>([]);
  const tpHist   = useRef<number[]>([]);
  const fpHist   = useRef<number[]>([]);

  useEffect(() => {
    let cancelled = false;
    async function fetchML() {
      try {
        const res = await api.ml.stats();
        if (!cancelled) {
          setStats(res);
          setLoading(false);
          anomHist.current = [...anomHist.current, res.anomalies_detected].slice(-40);
        }
      } catch {
        if (!cancelled) { setLoading(false); setError(true); }
      }
    }
    fetchML();
    const t = setInterval(fetchML, 5_000);
    return () => { cancelled = true; clearInterval(t); };
  }, []);

  // Green only when ML is genuinely enabled everywhere; amber otherwise. The old
  // check compared against the constant "active" the API always returned, so the
  // dot was green on installs where ML was disabled on every site.
  const statusColor = stats?.model_status === "enabled" ? "#22c55e" : "#f59e0b";

  return (
    <motion.div className="ml-page" variants={staggerContainer} initial="hidden" animate="visible">
      <motion.div className="ml-hd" variants={fadeUp}>
        <div className="ml-bc">/ <span>Intelligence</span> / <span>ML Engine</span></div>
        <div className="ml-hrow">
          <div className="ml-ttl">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#a78bfa" strokeWidth="1.5">
              <path d="M12 2a10 10 0 100 20A10 10 0 0012 2z" /><path d="M8 12h8M12 8v8" />
            </svg>
            ML / AI Engine
            {stats && <span className="ml-status-dot" style={{ background: statusColor }} title={stats.model_status} />}
          </div>
          <div style={{ fontSize: 13, fontFamily: "var(--font-mono)", color: "var(--text2)" }}>Auto-refresh: 5 s</div>
        </div>
      </motion.div>

      {loading && <div className="ml-loading">Loading ML stats…</div>}
      {error   && <div className="ml-error">Could not reach control plane — showing cached data</div>}

      {stats && (
        <>
          <motion.div className="ml-kpis" variants={staggerContainer} initial="hidden" animate="visible">
            {[
              { v: stats.total_analyzed.toLocaleString(), l: "Requests Analyzed", c: "#60a5fa", d: anomHist.current },
              { v: stats.anomalies_detected.toLocaleString(), l: "Anomalies Detected", c: "#f87171", d: anomHist.current, cls: "r" },
            ].map((k, i) => (
              <motion.div key={i} className="ml-kpi" variants={cardVariants}>
                <div className={`ml-kpi-v ${k.cls || ""}`}>{k.v}</div>
                <div className="ml-kpi-l">{k.l}</div>
                <Spark data={k.d} color={k.c} />
              </motion.div>
            ))}
            <motion.div className="ml-kpi" variants={cardVariants}>
              <div className="ml-kpi-v" style={{ color: "#a78bfa" }}>{stats.block_rate.toFixed(2)}%</div>
              <div className="ml-kpi-l">Block Rate</div>
            </motion.div>
          </motion.div>

          {/*
            This block replaces three ArcGauges that displayed Precision, Recall
            and F1 from hardcoded API literals (0.953 / 0.891), refreshed every 5s
            so they read as live measurement. They are not measurable without
            labelled ground truth. Saying so is the feature.
          */}
          {!stats.quality_measured && (
            <motion.div className="ml-gauge-card" variants={fadeUp} style={{ padding: "18px 20px" }}>
              <div className="ml-gc-lbl">Model accuracy — not measured</div>
              <div className="ml-gc-sub" style={{ marginTop: 8, lineHeight: 1.6, textAlign: "left" }}>
                {stats.quality_note}
              </div>
            </motion.div>
          )}

          <motion.div className="ml-sec-hd" variants={fadeUp}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#a78bfa" strokeWidth="1.5"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>
            Active Models
          </motion.div>
          <motion.div className="ml-models" variants={staggerContainer} initial="hidden" animate="visible">
            {/*
              Previously listed three models — payload-classifier, anomaly-detector
              and bot-classifier — with invented versions, precision/recall bars and
              latencies. Only one classifier ships; the other two had no model file
              anywhere in the repo. The API now returns the real one, and the bars
              are gone because the model carries weights, not accuracy figures.
            */}
            {stats.models.map((m, idx) => (
              <motion.div key={m.name} className="ml-model" variants={cardVariants} custom={idx}>
                <div className="ml-model-hd">
                  <div>
                    <div className="ml-model-nm">{m.name}</div>
                    <div className="ml-model-ver">{m.kind}</div>
                  </div>
                  <span className={`ml-model-st ${m.status === "loaded" ? "on" : "off"}`}>{m.status}</span>
                </div>
                <div className="ml-model-ft">
                  <span className="ml-chip">{m.buckets.toLocaleString()} feature buckets</span>
                  <span className="ml-chip">{m.metrics_note}</span>
                </div>
              </motion.div>
            ))}
          </motion.div>

          <motion.div variants={fadeUp}>
            <div className="ml-sec-hd">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#60a5fa" strokeWidth="1.5"><path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/></svg>
              Detection Tracker
            </div>
            <div className="ml-tracker">
              <table className="ml-tbl">
                <thead><tr><th>Metric</th><th>Today</th><th>Status</th></tr></thead>
                <tbody>
                  {/*
                    "True Positives" and "False Positives" rows removed. TP was the
                    raw anomaly count relabelled as correct; FP was anomalies x the
                    hardcoded 0.003. Neither is knowable without triaged ground
                    truth, and presenting them in a table headed "Today" made them
                    look like a daily measurement.
                  */}
                  <tr><td>Anomalies Detected</td><td className="r">{stats.anomalies_detected.toLocaleString()}</td><td><span className={`ml-tag ${stats.anomalies_detected > 100 ? "r" : "a"}`}>{stats.anomalies_detected > 100 ? "HIGH" : "NORMAL"}</span></td></tr>
                  <tr><td>Block Rate</td><td style={{ color: "#a78bfa" }}>{stats.block_rate.toFixed(2)}%</td><td><span className="ml-tag p">INFO</span></td></tr>
                </tbody>
              </table>
            </div>
          </motion.div>
        </>
      )}
    </motion.div>
  );
}