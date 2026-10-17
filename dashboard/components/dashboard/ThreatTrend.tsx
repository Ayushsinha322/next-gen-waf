"use client";
/**
 * ThreatTrend — the "Threat Detection Trend" overview card.
 *
 * Real, ClickHouse-backed severity time-series (GET /events/severity-timeline):
 * four bands — High (CRITICAL+HIGH), Medium, Low, Info — over a selectable
 * window (1h / 6h / 24h). Pure inline SVG, no chart library, theme-aware. Shows
 * an honest empty state when the event store isn't configured.
 */
import { useState, useEffect, useMemo } from "react";
import { api, type SeverityBucket } from "@/lib/api";

const SERIES = [
  { key: "high",   label: "High",   color: "#ff453a" },
  { key: "medium", label: "Medium", color: "#ff9f0a" },
  { key: "low",    label: "Low",    color: "#0a84ff" },
  { key: "info",   label: "Info",   color: "#30d158" },
] as const;

const RANGES = [
  { label: "Last 1 hour",   secs: 3600,   bucket: 60 },
  { label: "Last 6 hours",  secs: 21600,  bucket: 300 },
  { label: "Last 24 hours", secs: 86400,  bucket: 1800 },
] as const;

const VBW = 660, VBH = 210;
const PAD = { t: 14, r: 14, b: 28, l: 40 };
const CW = VBW - PAD.l - PAD.r;
const CH = VBH - PAD.t - PAD.b;

function fmtClock(unix: number): string {
  const d = new Date(unix * 1000);
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
}

export default function ThreatTrend() {
  const [rangeIdx, setRangeIdx] = useState(0);
  const [buckets, setBuckets]   = useState<SeverityBucket[] | null>(null);
  const [ch, setCh]             = useState(true);

  const range = RANGES[rangeIdx];

  useEffect(() => {
    let cancelled = false;
    setBuckets(null);
    async function f() {
      try {
        const now = Math.floor(Date.now() / 1000);
        const r = await api.events.severityTimeline(now - range.secs, now, range.bucket);
        if (cancelled) return;
        setBuckets(r.buckets ?? []);
        setCh(r.clickhouse);
      } catch { if (!cancelled) { setBuckets([]); setCh(true); } }
    }
    f(); const t = setInterval(f, 30_000); return () => { cancelled = true; clearInterval(t); };
  }, [rangeIdx, range.secs, range.bucket]);

  const totals = useMemo(() => {
    const b = buckets ?? [];
    return SERIES.map(s => b.reduce((a, x) => a + (x[s.key] ?? 0), 0));
  }, [buckets]);
  const grandTotal = totals.reduce((a, b) => a + b, 0);

  const b = buckets ?? [];
  // Whole-number y steps from a "nice" series (1, 2, 5 × 10^k). Rounding
  // fractions of a small max (0.25 × 1.15, …) labelled the axis "1, 1, 1, 0, 0".
  const rawMax = Math.max(1, ...b.flatMap(x => [x.high, x.medium, x.low, x.info]));
  const yStep = niceStep(rawMax / 4);
  const maxV = yStep * 4;
  const n = b.length;
  const px = (i: number) => PAD.l + (n <= 1 ? 0 : (i / (n - 1)) * CW);
  const py = (v: number) => PAD.t + CH * (1 - v / maxV);
  const yTicks = [0, 1, 2, 3, 4].map(k => k * yStep);
  // ~5 evenly spaced x labels, each index and each printed time at most once:
  // with fewer than 5 buckets, or buckets finer than a minute, the same label
  // was drawn twice ("13:56 … 13:56").
  const xTickIdx = (() => {
    if (n <= 1) return [] as number[];
    const idx = [...new Set(Array.from({ length: 5 }, (_, k) => Math.round((k / 4) * (n - 1))))];
    const seen = new Set<string>();
    return idx.filter(i => { const t = fmtClock(b[i].ts); if (seen.has(t)) return false; seen.add(t); return true; });
  })();

  return (
    <div className="panel" style={{ display: "flex", flexDirection: "column" }}>
      <div className="ph">
        <div className="ptitle">Threat Detection Trend</div>
        <select
          value={rangeIdx}
          onChange={e => setRangeIdx(Number(e.target.value))}
          style={{
            background: "var(--bg2)", color: "var(--text2)", border: "1px solid var(--bg4)",
            borderRadius: 8, padding: "4px 10px", fontSize: 13, fontFamily: "var(--font-sans)", cursor: "pointer",
          }}>
          {RANGES.map((r, i) => <option key={r.label} value={i}>{r.label}</option>)}
        </select>
      </div>

      {/* Legend */}
      <div style={{ display: "flex", gap: 16, flexWrap: "wrap", padding: "10px 16px 2px" }}>
        {SERIES.map((s, i) => (
          <div key={s.key} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13, color: "var(--text2)" }}>
            <span style={{ width: 10, height: 10, borderRadius: 2, background: s.color }} />
            {s.label}
            <span style={{ color: "var(--text3)", fontFamily: "var(--font-sans)" }}>{totals[i].toLocaleString()}</span>
          </div>
        ))}
      </div>

      <div className="pb" style={{ flex: 1, paddingTop: 6 }}>
        {buckets === null ? (
          <Msg text="Loading detection trend…" />
        ) : !ch ? (
          <Msg text="Event store (ClickHouse) not configured — enable it to chart detections over time." />
        ) : grandTotal === 0 ? (
          <Msg text={`No detections in the ${range.label.replace("Last ", "last ")}.`} />
        ) : (
          <svg viewBox={`0 0 ${VBW} ${VBH}`} width="100%" style={{ display: "block", overflow: "visible" }} preserveAspectRatio="xMidYMid meet">
            {/* horizontal grid + y labels */}
            {yTicks.map((v, i) => {
              const y = PAD.t + (CH * i) / 4;
              return (
                <g key={i}>
                  <line x1={PAD.l} y1={y} x2={VBW - PAD.r} y2={y} style={{ stroke: "var(--sep-row)" }} strokeWidth={1} />
                  <text x={PAD.l - 6} y={y + 3} textAnchor="end" fontSize={10} style={{ fill: "var(--text3)" }} fontFamily="var(--font-sans)">
                    {yTicks[4 - i]}
                  </text>
                </g>
              );
            })}
            {/* x time labels */}
            {xTickIdx.map((idx, k) => (
              <text key={k} x={px(idx)} y={VBH - 8} textAnchor={k === 0 ? "start" : k === xTickIdx.length - 1 ? "end" : "middle"}
                fontSize={10} style={{ fill: "var(--text3)" }} fontFamily="var(--font-sans)">
                {fmtClock(b[idx].ts)}
              </text>
            ))}
            {/* series lines (drawn low→high so High sits on top) */}
            {[...SERIES].reverse().map(s => {
              const pts = b.map((x, i) => `${px(i).toFixed(1)},${py(x[s.key] ?? 0).toFixed(1)}`).join(" ");
              return (
                <polyline key={s.key} points={pts} fill="none" stroke={s.color} strokeWidth={1.8}
                  strokeLinejoin="round" strokeLinecap="round" opacity={0.92} />
              );
            })}
          </svg>
        )}
      </div>
    </div>
  );
}

function Msg({ text }: { text: string }) {
  return (
    <div style={{ height: 150, display: "flex", alignItems: "center", justifyContent: "center", textAlign: "center", padding: "0 12px", fontSize: 13, lineHeight: 1.5, fontFamily: "var(--font-sans)", color: "var(--text3)" }}>
      {text}
    </div>
  );
}

/** Smallest of 1, 2, 5 × 10^k that is ≥ x, and at least 1 (counts are whole). */
export function niceStep(x: number): number {
  if (!(x > 0)) return 1;
  const p = 10 ** Math.floor(Math.log10(x));
  for (const m of [1, 2, 5, 10]) if (m * p >= x) return Math.max(1, m * p);
  return Math.max(1, 10 * p);
}
