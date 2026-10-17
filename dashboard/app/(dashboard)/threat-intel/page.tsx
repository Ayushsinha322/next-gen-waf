"use client";
import Icon from "@/components/ui/Icon";
/**
 * Threat Intelligence — the managed IOC corpus that feeds the data plane.
 * Aggregated feeds (Tor / abuse.ch Feodo & URLhaus / STIX / built-in scanner
 * UAs) plus manual analyst entries are tiered by confidence: block-tier IOCs are
 * rejected at the edge, watch-tier IOCs add to the anomaly score. This page shows
 * the corpus, lets analysts curate it, and surfaces recent intel-driven blocks.
 */
import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { showToast } from "@/components/ui/Toast";
import { openModal } from "@/components/ui/Modal";
import {
  api,
  type IOC,
  type ThreatIntelSummary,
  type IOCQuery,
  type TIBlock,
  type IOCType,
} from "@/lib/api";
import { staggerContainer, fadeUp, cardVariants } from "@/lib/animations";

const TYPES: { v: IOCType; l: string }[] = [
  { v: "ip", l: "IP" },
  { v: "cidr", l: "CIDR" },
  { v: "user_agent", l: "User-Agent" },
  { v: "domain", l: "Domain" },
  { v: "url_substring", l: "URL substring" },
];
const typeLabel = (t: string) => TYPES.find((x) => x.v === t)?.l ?? t;

function fmtTime(ts: number) {
  return new Date(ts * 1000).toLocaleString();
}
function fmtAgo(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso).getTime();
  const s = (Date.now() - d) / 1000;
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
const closeModal = () => document.querySelector<HTMLElement>(".modal-bg")?.click();

export default function ThreatIntelPage() {
  const [summary, setSummary] = useState<ThreatIntelSummary | null>(null);
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [total, setTotal] = useState(0);
  const [recent, setRecent] = useState<TIBlock[]>([]);
  const [chOk, setChOk] = useState(true);
  const [loading, setLoading] = useState(true);

  const [q, setQ] = useState("");
  const [type, setType] = useState("");
  const [tier, setTier] = useState("");
  const [source, setSource] = useState("");

  const run = useCallback(
    async (override?: Partial<IOCQuery>) => {
      setLoading(true);
      const filter: IOCQuery = { q, type, tier, source, limit: 300, ...override };
      try {
        const [sm, ls, rb] = await Promise.all([
          api.threatIntel.stats(),
          api.threatIntel.list(filter),
          api.threatIntel.recentBlocks(50),
        ]);
        setSummary(sm);
        setIocs(ls.items ?? []);
        setTotal(ls.total ?? 0);
        setRecent(rb.blocks ?? []);
        setChOk(rb.clickhouse);
      } catch (e) {
        showToast(e instanceof Error ? e.message : "Load failed", "e");
      } finally {
        setLoading(false);
      }
    },
    [q, type, tier, source],
  );

  useEffect(() => {
    run();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const clearFilters = () => {
    setQ("");
    setType("");
    setTier("");
    setSource("");
    run({ q: "", type: "", tier: "", source: "" });
  };
  const hasFilters = !!(q || type || tier || source);
  const sourceCount = summary ? Object.keys(summary.by_source).length : 0;

  // --- Add indicator (openModal) ---
  function openCreate() {
    let value = "";
    let itype: IOCType = "ip";
    let itier = "block";
    let category = "";
    let days = "";
    openModal({
      title: "＋ Add Indicator",
      body: (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <div className="fg2">
            <label className="flbl2">Indicator value</label>
            <input
              className="fin2"
              placeholder="1.2.3.4 · 10.0.0.0/8 · sqlmap · evil.example · /wp-login"
              onChange={(e) => {
                value = e.target.value;
              }}
            />
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <div className="fg2">
              <label className="flbl2">Type</label>
              <select className="fsel" defaultValue="ip" onChange={(e) => { itype = e.target.value as IOCType; }}>
                {TYPES.map((t) => (
                  <option key={t.v} value={t.v}>{t.l}</option>
                ))}
              </select>
            </div>
            <div className="fg2">
              <label className="flbl2">Enforcement</label>
              <select className="fsel" defaultValue="block" onChange={(e) => { itier = e.target.value; }}>
                <option value="block">Block (high confidence)</option>
                <option value="watch">Watch (score only)</option>
              </select>
            </div>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <div className="fg2">
              <label className="flbl2">Category</label>
              <input className="fin2" placeholder="malware · scanner · botnet" onChange={(e) => { category = e.target.value; }} />
            </div>
            <div className="fg2">
              <label className="flbl2">Expires in (days)</label>
              <input className="fin2" type="number" min="0" placeholder="never" onChange={(e) => { days = e.target.value; }} />
            </div>
          </div>
        </div>
      ),
      footer: (
        <>
          <button className="btn bg-btn" onClick={closeModal}>Cancel</button>
          <button
            className="btn bp"
            onClick={async () => {
              if (!value.trim()) {
                showToast("Enter an indicator value", "e");
                return;
              }
              let expires_at: string | null = null;
              const n = parseInt(days, 10);
              if (Number.isFinite(n) && n > 0) {
                expires_at = new Date(Date.now() + n * 86400000).toISOString();
              }
              try {
                await api.threatIntel.create({
                  type: itype,
                  value: value.trim(),
                  tier: itier as "block" | "watch",
                  category: category.trim(),
                  expires_at,
                });
                closeModal();
                showToast("Indicator added", "s");
                run();
              } catch (err) {
                showToast(err instanceof Error ? err.message : "Add failed", "e");
              }
            }}
          >
            Add indicator
          </button>
        </>
      ),
    });
  }

  async function removeEntry(e: IOC) {
    if (!confirm(`Remove ${e.type} indicator "${e.value}" from the feed?`)) return;
    try {
      await api.threatIntel.remove(e.id);
      showToast("Indicator removed", "s");
      run();
    } catch (err) {
      showToast(err instanceof Error ? err.message : "Remove failed", "e");
    }
  }

  return (
    <motion.div className="sec" variants={staggerContainer} initial="hidden" animate="visible">
      {/* Header */}
      <motion.div
        variants={fadeUp}
        style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 14 }}
      >
        <div>
          <div className="sec-title">Threat Intelligence</div>
          <div className="sec-sub">
            Managed IOC corpus feeding the data plane
            {summary ? ` · ${summary.total_active.toLocaleString()} active · block ≥ ${summary.threshold}% confidence` : " · loading…"}
            {summary?.newest_seen ? ` · updated ${fmtAgo(summary.newest_seen)}` : ""}
          </div>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <button className="btn bg-btn btn-sm" onClick={() => run()}>⟳ Refresh</button>
          <button className="btn bp btn-sm" onClick={openCreate}>＋ Add Indicator</button>
        </div>
      </motion.div>

      {/* KPI row */}
      <motion.div variants={staggerContainer} style={{ display: "grid", gridTemplateColumns: "repeat(5,minmax(0,1fr))", gap: 12 }}>
        <div className="kpi kc"><div className="kpi-lbl">Active IOCs</div><div className="kpi-val">{summary?.total_active?.toLocaleString() ?? "—"}</div></div>
        <div className="kpi"><div className="kpi-lbl">Block tier</div><div className="kpi-val" style={{ color: "var(--red)" }}>{summary?.block_tier?.toLocaleString() ?? "—"}</div></div>
        <div className="kpi ka"><div className="kpi-lbl">Watch tier</div><div className="kpi-val" style={{ color: "var(--amber)" }}>{summary?.watch_tier?.toLocaleString() ?? "—"}</div></div>
        <div className="kpi kg"><div className="kpi-lbl">Feed sources</div><div className="kpi-val">{summary ? sourceCount : "—"}</div></div>
        <div className="kpi kc"><div className="kpi-lbl">Freshness</div><div className="kpi-val" style={{ fontSize: 20 }}>{fmtAgo(summary?.newest_seen ?? null)}</div></div>
      </motion.div>

      {/* Filter bar */}
      <motion.div className="panel" variants={fadeUp}>
        <div className="pb" style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <input
            className="fi2"
            placeholder="search indicator value…"
            style={{ flex: 1, minWidth: 200 }}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && run()}
          />
          <select className="fsel" value={type} onChange={(e) => { setType(e.target.value); run({ type: e.target.value }); }}>
            <option value="">All types</option>
            {TYPES.map((t) => (<option key={t.v} value={t.v}>{t.l}</option>))}
          </select>
          <select className="fsel" value={tier} onChange={(e) => { setTier(e.target.value); run({ tier: e.target.value }); }}>
            <option value="">All tiers</option>
            <option value="block">Block</option>
            <option value="watch">Watch</option>
          </select>
          <input
            className="fi2"
            placeholder="source"
            style={{ width: 130 }}
            value={source}
            onChange={(e) => setSource(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && run()}
          />
          <button className="btn bc btn-sm" onClick={() => run()}>Search</button>
          {hasFilters && <button className="btn bg-btn btn-sm" onClick={clearFilters}>✕ Clear</button>}
        </div>
      </motion.div>

      {/* Facets + IOC table */}
      <div style={{ display: "grid", gridTemplateColumns: "260px 1fr", gap: 14 }}>
        <motion.div variants={cardVariants} style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <Facet title="By Type" data={summary?.by_type ?? {}} render={typeLabel} onPick={(k) => { setType(k); run({ type: k }); }} />
          <Facet title="By Source" data={summary?.by_source ?? {}} onPick={(k) => { setSource(k); run({ source: k }); }} />
          <Facet title="By Category" data={summary?.by_category ?? {}} />
        </motion.div>

        <motion.div className="panel" variants={cardVariants}>
          <div className="ph">
            <div className="ptitle">Indicators</div>
            <span className="panel-badge pb-cyan">
              {loading ? "loading…" : `${iocs.length}${total > iocs.length ? ` of ${total.toLocaleString()}` : ""}`}
            </span>
          </div>
          <div className="tw" style={{ maxHeight: 520, overflow: "auto" }}>
            {iocs.length === 0 ? (
              <Empty text={loading ? "Loading…" : "No indicators match these filters."} />
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Type</th><th>Indicator</th><th>Tier</th><th>Category</th><th>Source</th>
                    <th>Conf</th><th>Last seen</th><th>Expires</th><th></th>
                  </tr>
                </thead>
                <tbody>
                  {iocs.map((e) => (
                    <tr key={e.id}>
                      <td className="td3"><span className="bdg bcy">{typeLabel(e.type)}</span></td>
                      <td className="td2" style={{ fontFamily: "var(--font-mono)", wordBreak: "break-all" }}>{e.value}</td>
                      <td><span className={`bdg ${e.tier === "block" ? "br" : "ba"}`}>{e.tier.toUpperCase()}</span></td>
                      <td className="td3">{e.category || "—"}</td>
                      <td className="td3">{e.source}</td>
                      <td className="td3">{e.confidence}%</td>
                      <td className="td3" style={{ whiteSpace: "nowrap" }}>{fmtAgo(e.last_seen)}</td>
                      <td className="td3" style={{ whiteSpace: "nowrap" }}>{e.expires_at ? new Date(e.expires_at).toLocaleDateString() : "never"}</td>
                      <td><button className="btn bg-btn btn-xs" title="Remove indicator" onClick={() => removeEntry(e)}>✕</button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </motion.div>
      </div>

      {/* Recent intel-driven blocks */}
      <motion.div className="panel" variants={cardVariants}>
        <div className="ph">
          <div className="ptitle">Recent Intel Blocks</div>
          <span className={`panel-badge ${chOk ? "pb-live" : ""}`}>{chOk ? "● from ClickHouse" : "ClickHouse off"}</span>
        </div>
        <div className="tw" style={{ maxHeight: 340, overflow: "auto" }}>
          {!chOk ? (
            <div style={{ padding: 28, textAlign: "center" }}>
              <Icon name="activity" size={28} style={{ marginBottom: 8, color: "var(--text3)" }} />
              <div style={{ fontSize: 15, fontWeight: 700, color: "var(--text2)", marginBottom: 6 }}>Block history not available</div>
              <div style={{ fontSize: 14, color: "var(--text3)", lineHeight: 1.7, fontFamily: "var(--font-mono)", maxWidth: 520, margin: "0 auto" }}>
                Set <span style={{ color: "var(--cyan)" }}>SENTINEL_CLICKHOUSE_URL</span> on the control plane to record and search intel-driven blocks. Enforcement still works without it.
              </div>
            </div>
          ) : recent.length === 0 ? (
            <Empty text="No intel-driven blocks in the last 24h." />
          ) : (
            <table>
              <thead><tr><th>Time</th><th>Source IP</th><th>Site</th><th>Path</th><th>Reason</th></tr></thead>
              <tbody>
                {recent.map((b, i) => (
                  <tr key={i}>
                    <td className="td3" style={{ whiteSpace: "nowrap" }}>{fmtTime(b.ts)}</td>
                    <td className="td2">{b.ip}{b.country ? ` (${b.country})` : ""}</td>
                    <td className="td3">{b.site}</td>
                    <td className="td3" style={{ fontFamily: "var(--font-mono)", maxWidth: 240, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{b.path}</td>
                    <td><span className="bdg br">{b.reason || "threat intel"}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </motion.div>
    </motion.div>
  );
}

// Facet bar list fed a Record<string,number>; optional click filters the table.
function Facet({
  title,
  data,
  onPick,
  render,
}: {
  title: string;
  data: Record<string, number>;
  onPick?: (k: string) => void;
  render?: (k: string) => string;
}) {
  const rows = Object.entries(data).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const max = Math.max(1, ...rows.map(([, v]) => v));
  return (
    <div className="panel">
      <div className="ph"><div className="ptitle">{title}</div></div>
      <div className="pb" style={{ display: "flex", flexDirection: "column", gap: 7 }}>
        {rows.length === 0 ? (
          <div style={{ fontSize: 13, color: "var(--text3)", fontFamily: "var(--font-sans)" }}>—</div>
        ) : (
          rows.map(([k, v]) => (
            <div key={k} onClick={() => onPick?.(k)} style={{ cursor: onPick ? "pointer" : "default" }} title={onPick ? "Filter by this" : undefined}>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13, marginBottom: 2 }}>
                <span style={{ color: "var(--text2)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 160, fontFamily: "var(--font-sans)" }}>{render ? render(k) : k}</span>
                <span style={{ color: "var(--text)", fontFamily: "var(--font-sans)" }}>{v.toLocaleString()}</span>
              </div>
              <div style={{ height: 4, background: "var(--bg3)", borderRadius: 2, overflow: "hidden" }}>
                <div style={{ height: "100%", width: `${(v / max) * 100}%`, background: "var(--accent-tint-h)", borderRadius: 2 }} />
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function Empty({ text }: { text: string }) {
  return (
    <div style={{ padding: "22px 12px", textAlign: "center", fontSize: 13, color: "var(--text3)", fontFamily: "var(--font-sans)", width: "100%" }}>
      {text}
    </div>
  );
}
