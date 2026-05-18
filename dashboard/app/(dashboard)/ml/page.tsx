"use client";
import { useState, useEffect, useRef } from "react";
import { api, type MLStats } from "@/lib/api";

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
      {/* Track */}
      <path
        d={`M${bg1.x},${bg1.y} A${r},${r} 0 1,1 ${bg2.x},${bg2.y}`}
        fill="none" stroke="rgba(255,255,255,.07)" strokeWidth="8" strokeLinecap="round"
      />
      {/* Fill */}
      {pct > 0 && (
        <path
          d={`M${s.x},${s.y} A${r},${r} 0 ${large},1 ${e.x},${e.y}`}
          fill="none" stroke={color} strokeWidth="8" strokeLinecap="round"
        />
      )}
      {/* Value */}
      <text x={cx} y={cy - 4} textAnchor="middle" fill="#f1f5f9" fontSize="18" fontFamily="'Share Tech Mono',monospace" fontWeight="700">
        {displayVal}%
      </text>
      <text x={cx} y={cy + 14} textAnchor="middle" fill="rgba(148,163,184,.7)" fontSize="9" fontFamily="Inter,sans-serif" letterSpacing=".5">
        {label}
      </text>
    </svg>
  );
}

// ── Mini sparkline ────────────────────────────────────────────────────────────
function Spark({ data, color }: { data: number[]; color: string }) {
  if (data.length < 2) return <svg viewBox="0 0 80 24" className="ml-spark" />;
  const max = Math.max(...data, 1);
  // Clamp y so a zero value sits at 20/24 (not the very edge) to avoid flat-bar appearance
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
  // Sparkline history for anomalies
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
          tpHist.current   = [...tpHist.current,   res.true_positives_today].slice(-40);
          fpHist.current   = [...fpHist.current,   res.false_positives_today].slice(-40);
        }
      } catch {
        if (!cancelled) { setLoading(false); setError(true); }
      }
    }
    fetchML();
    const t = setInterval(fetchML, 5_000);
    return () => { cancelled = true; clearInterval(t); };
  }, []);

  const statusColor = stats?.model_status === "active" ? "#22c55e" : "#f59e0b";

  return (
    <div className="ml-page">

      {/* ── Header ── */}
      <div className="ml-hd">
        <div className="ml-bc">/ <span>Intelligence</span> / <span>ML Engine</span></div>
        <div className="ml-hrow">
          <div className="ml-ttl">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#a78bfa" strokeWidth="1.5">
              <path d="M12 2a10 10 0 100 20A10 10 0 0012 2z" /><path d="M8 12h8M12 8v8" />
            </svg>
            ML / AI Engine
            {stats && (
              <span className="ml-status-dot" style={{ background: statusColor }} title={stats.model_status} />
            )}
          </div>
          <div style={{ fontSize: 11, fontFamily: "'Share Tech Mono',monospace", color: "var(--text2)" }}>
            Auto-refresh: 5 s
          </div>
        </div>
      </div>

      {loading && <div className="ml-loading">Loading ML stats…</div>}
      {error   && <div className="ml-error">Could not reach control plane — showing cached data</div>}

      {/* ── KPI row ── */}
      {stats && (
        <>
          <div className="ml-kpis">
            <div className="ml-kpi">
              <div className="ml-kpi-v">{stats.total_analyzed.toLocaleString()}</div>
              <div className="ml-kpi-l">Requests Analyzed</div>
              <Spark data={anomHist.current} color="#60a5fa" />
            </div>
            <div className="ml-kpi">
              <div className="ml-kpi-v r">{stats.anomalies_detected.toLocaleString()}</div>
              <div className="ml-kpi-l">Anomalies Detected</div>
              <Spark data={anomHist.current} color="#f87171" />
            </div>
            <div className="ml-kpi">
              <div className="ml-kpi-v g">{stats.true_positives_today.toLocaleString()}</div>
              <div className="ml-kpi-l">True Positives Today</div>
              <Spark data={tpHist.current} color="#4ade80" />
            </div>
            <div className="ml-kpi">
              <div className="ml-kpi-v a">{stats.false_positives_today.toLocaleString()}</div>
              <div className="ml-kpi-l">False Positives Today</div>
              <Spark data={fpHist.current} color="#fb923c" />
            </div>
            <div className="ml-kpi">
              <div className="ml-kpi-v" style={{ color: "#a78bfa" }}>{stats.block_rate.toFixed(2)}%</div>
              <div className="ml-kpi-l">Block Rate</div>
            </div>
            <div className="ml-kpi">
              <div className="ml-kpi-v" style={{ color: "#38bdf8" }}>{(stats.fp_rate * 100).toFixed(3)}%</div>
              <div className="ml-kpi-l">FP Rate</div>
            </div>
          </div>

          {/* ── Gauges row ── */}
          <div className="ml-gauges">
            <div className="ml-gauge-card">
              <div className="ml-gc-lbl">Precision</div>
              <ArcGauge value={stats.precision} label="PRECISION" color="#a78bfa" />
              <div className="ml-gc-sub">True positives / (TP + FP)</div>
            </div>
            <div className="ml-gauge-card">
              <div className="ml-gc-lbl">Recall</div>
              <ArcGauge value={stats.recall} label="RECALL" color="#38bdf8" />
              <div className="ml-gc-sub">True positives / (TP + FN)</div>
            </div>
            <div className="ml-gauge-card">
              <div className="ml-gc-lbl">F1 Score</div>
              <ArcGauge
                value={(2 * stats.precision * stats.recall) / (stats.precision + stats.recall || 1)}
                label="F1 SCORE"
                color="#4ade80"
              />
              <div className="ml-gc-sub">Harmonic mean P & R</div>
            </div>
          </div>

          {/* ── Model cards ── */}
          <div className="ml-sec-hd">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#a78bfa" strokeWidth="1.5"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>
            Active Models
          </div>
          <div className="ml-models">
            {stats.models.map(m => (
              <div key={m.name} className="ml-model">
                <div className="ml-model-hd">
                  <div>
                    <div className="ml-model-nm">{m.name}</div>
                    <div className="ml-model-ver">v{m.version} · updated {m.last_updated}</div>
                  </div>
                  <span className={`ml-model-st ${m.status === "active" ? "on" : "off"}`}>{m.status}</span>
                </div>
                <div className="ml-model-bars">
                  <div className="ml-bar-row">
                    <span className="ml-bar-lbl">Precision</span>
                    <div className="ml-bar-track">
                      <div className="ml-bar-fill" style={{ width: `${m.precision * 100}%`, background: "#a78bfa" }} />
                    </div>
                    <span className="ml-bar-val">{(m.precision * 100).toFixed(1)}%</span>
                  </div>
                  <div className="ml-bar-row">
                    <span className="ml-bar-lbl">Recall</span>
                    <div className="ml-bar-track">
                      <div className="ml-bar-fill" style={{ width: `${m.recall * 100}%`, background: "#38bdf8" }} />
                    </div>
                    <span className="ml-bar-val">{(m.recall * 100).toFixed(1)}%</span>
                  </div>
                </div>
                <div className="ml-model-ft">
                  <span className="ml-chip">⚡ {m.latency_ms} ms avg</span>
                  <span className="ml-chip g">● {m.status}</span>
                </div>
              </div>
            ))}
          </div>

          {/* ── TP / FP tracker table ── */}
          <div className="ml-sec-hd">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#60a5fa" strokeWidth="1.5"><path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/></svg>
            Detection Tracker
          </div>
          <div className="ml-tracker">
            <table className="ml-tbl">
              <thead>
                <tr>
                  <th>Metric</th>
                  <th>Today</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>True Positives</td>
                  <td className="g">{stats.true_positives_today.toLocaleString()}</td>
                  <td><span className="ml-tag g">GOOD</span></td>
                </tr>
                <tr>
                  <td>False Positives</td>
                  <td className="a">{stats.false_positives_today.toLocaleString()}</td>
                  <td><span className="ml-tag a">{stats.false_positives_today > 5 ? "REVIEW" : "OK"}</span></td>
                </tr>
                <tr>
                  <td>Anomalies Detected</td>
                  <td className="r">{stats.anomalies_detected.toLocaleString()}</td>
                  <td><span className={`ml-tag ${stats.anomalies_detected > 100 ? "r" : "a"}`}>{stats.anomalies_detected > 100 ? "HIGH" : "NORMAL"}</span></td>
                </tr>
                <tr>
                  <td>Block Rate</td>
                  <td style={{ color: "#a78bfa" }}>{stats.block_rate.toFixed(2)}%</td>
                  <td><span className="ml-tag p">INFO</span></td>
                </tr>
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
