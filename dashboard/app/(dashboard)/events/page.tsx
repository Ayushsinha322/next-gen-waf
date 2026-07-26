"use client";
/**
 * Threat Search — searchable WAF event history backed by ClickHouse.
 * Live tail lives on /logs; this page is the durable, queryable record:
 * time-range filters, facets, a timeline, and a results table. Honest empty
 * state when ClickHouse isn't configured.
 */
import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { showToast } from "@/components/ui/Toast";
import { api, type WafEvent, type TimelineBucket, type EventQuery, type Site } from "@/lib/api";
import EventDrawer from "@/components/events/EventDrawer";
import { staggerContainer, fadeUp, cardVariants } from "@/lib/animations";

const RANGES: { label: string; secs: number }[] = [
  { label: "1h", secs: 3600 },
  { label: "24h", secs: 86400 },
  { label: "7d", secs: 604800 },
  { label: "30d", secs: 2592000 },
];

function fmtTime(ts: number) { return new Date(ts * 1000).toLocaleString(); }

export default function EventsPage() {
  const [status, setStatus] = useState<{ configured: boolean; reachable: boolean; events?: number; error?: string } | null>(null);
  const [events, setEvents] = useState<WafEvent[]>([]);
  const [timeline, setTimeline] = useState<TimelineBucket[]>([]);
  const [ruleFacets, setRuleFacets] = useState<{ key: string; count: number }[]>([]);
  const [ipFacets, setIpFacets] = useState<{ key: string; count: number }[]>([]);
  const [protocolFacets, setProtocolFacets] = useState<{ key: string; count: number }[]>([]);
  const [loading, setLoading] = useState(true);
  const [rangeSecs, setRangeSecs] = useState(86400);
  // Row drill-down. Sites are fetched once so the drawer can map an event's
  // site NAME onto the site ID the exclusion endpoint is keyed by.
  const [selected, setSelected] = useState<WafEvent | null>(null);
  const [sites, setSites] = useState<Site[]>([]);

  // active filters
  const [q, setQ] = useState("");
  const [site, setSite] = useState("");
  const [rule, setRule] = useState("");
  const [action, setAction] = useState("");
  const [ip, setIp] = useState("");
  const [protocol, setProtocol] = useState("");

  // `override` lets callers search with a value they just set this render —
  // `setRule(k); run()` would otherwise search with the *previous* rule because
  // state updates and this captured closure both lag a render behind.
  const run = useCallback(async (override?: Partial<EventQuery>) => {
    setLoading(true);
    const to = Math.floor(Date.now() / 1000) + 60;
    const from = to - rangeSecs - 60;
    const filter: EventQuery = { from, to, limit: 300, q, site, rule, action, ip, protocol, ...override };
    try {
      const st = await api.events.status();
      setStatus(st);
      if (!st.configured || !st.reachable) { setLoading(false); return; }
      const [s, t, rf, ipf, pf] = await Promise.all([
        api.events.search(filter),
        api.events.timeline(from, to, rangeSecs > 86400 ? 3600 : 60),
        api.events.facets("rule", from, to, 8),
        api.events.facets("ip", from, to, 8),
        api.events.facets("protocol", from, to, 8),
      ]);
      setEvents(s.events ?? []);
      setTimeline(t.buckets ?? []);
      setRuleFacets(rf.facets ?? []);
      setIpFacets(ipf.facets ?? []);
      setProtocolFacets(pf.facets ?? []);
    } catch (e) { showToast(e instanceof Error ? e.message : "Search failed", "e", "⚠️"); }
    finally { setLoading(false); }
  }, [rangeSecs, q, site, rule, action, ip, protocol]);

  useEffect(() => { run(); }, [rangeSecs]); // eslint-disable-line react-hooks/exhaustive-deps

  // Site list for the detail drawer. Events carry a site NAME; the exclusion
  // endpoint is keyed by site ID, so the drawer needs the mapping. Fetched once
  // and deliberately non-fatal — a failure here must not break Threat Search,
  // it only disables the policy action in the drawer.
  useEffect(() => {
    let alive = true;
    api.sites.list()
      .then(r => { if (alive) setSites(r.sites ?? []); })
      .catch(() => { /* drawer degrades to read-only */ });
    return () => { alive = false; };
  }, []);

  const maxBucket = Math.max(1, ...timeline.map(b => b.total));
  const clearFilters = () => { setQ(""); setSite(""); setRule(""); setAction(""); setIp(""); setProtocol(""); run({ q: "", site: "", rule: "", action: "", ip: "", protocol: "" }); };
  const activeFilters = [["site", site], ["rule", rule], ["action", action], ["ip", ip], ["protocol", protocol], ["q", q]].filter(([, v]) => v) as [string, string][];

  return (
    <motion.div className="sec" variants={staggerContainer} initial="hidden" animate="visible">
      <motion.div variants={fadeUp} style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 14 }}>
        <div>
          <div className="sec-title">🔎 Threat Search</div>
          <div className="sec-sub">
            Searchable WAF history (ClickHouse) · {status?.reachable ? `${(status.events ?? 0).toLocaleString()} events stored` : "durable event store"}
          </div>
        </div>
        <div style={{ display: "flex", gap: 4, padding: 4, background: "var(--bg3)", borderRadius: 10 }}>
          {RANGES.map(r => (
            <button key={r.label} onClick={() => setRangeSecs(r.secs)} style={{
              padding: "6px 14px", borderRadius: 7, border: "none", cursor: "pointer", fontSize: 14, fontWeight: 600,
              background: rangeSecs === r.secs ? "var(--cyan)" : "transparent", color: rangeSecs === r.secs ? "#021018" : "var(--text2)",
            }}>{r.label}</button>
          ))}
        </div>
      </motion.div>

      {/* not-configured state */}
      {status && !status.configured ? (
        <motion.div className="panel" variants={fadeUp}><div className="pb" style={{ textAlign: "center", padding: 40 }}>
          <div style={{ fontSize: 34, marginBottom: 10 }}>🗄️</div>
          <div style={{ fontSize: 16, fontWeight: 700, color: "var(--text2)", marginBottom: 6 }}>ClickHouse not configured</div>
          <div style={{ fontSize: 14, color: "var(--text3)", lineHeight: 1.7, fontFamily: "var(--font-mono)", maxWidth: 520, margin: "0 auto" }}>
            Set <span style={{ color: "var(--cyan)" }}>SENTINEL_CLICKHOUSE_URL</span> on the control plane and run the ClickHouse container to enable durable, searchable WAF history. Live events still stream on the <strong>Logs</strong> page.
          </div>
        </div></motion.div>
      ) : status && !status.reachable ? (
        <motion.div className="panel" variants={fadeUp}><div className="pb" style={{ textAlign: "center", padding: 30, fontSize: 14, color: "var(--text3)", fontFamily: "var(--font-mono)" }}>
          ClickHouse configured but unreachable{status.error ? ` — ${status.error}` : ""}.
        </div></motion.div>
      ) : (
        <>
          {/* filter bar */}
          <motion.div className="panel" variants={fadeUp}><div className="pb" style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
            <input className="fi2" placeholder="🔍 search path / attack / rule…" style={{ flex: 1, minWidth: 200 }} value={q}
              onChange={e => setQ(e.target.value)} onKeyDown={e => e.key === "Enter" && run()} />
            <input className="fi2" placeholder="site" style={{ width: 130 }} value={site} onChange={e => setSite(e.target.value)} onKeyDown={e => e.key === "Enter" && run()} />
            <input className="fi2" placeholder="rule" style={{ width: 90 }} value={rule} onChange={e => setRule(e.target.value)} onKeyDown={e => e.key === "Enter" && run()} />
            <input className="fi2" placeholder="IP" style={{ width: 120 }} value={ip} onChange={e => setIp(e.target.value)} onKeyDown={e => e.key === "Enter" && run()} />
            <select className="fsel" value={protocol} onChange={e => { setProtocol(e.target.value); run({ protocol: e.target.value }); }}>
              <option value="">All protocols</option><option value="h1">HTTP/1.x</option><option value="h2">HTTP/2</option><option value="h3">HTTP/3</option>
            </select>
            <select className="fsel" value={action} onChange={e => setAction(e.target.value)}>
              <option value="">All actions</option><option value="BLOCK">BLOCK</option><option value="DETECT">DETECT</option>
            </select>
            <button className="btn bc btn-sm" onClick={() => run()}>Search</button>
            {activeFilters.length > 0 && <button className="btn bg-btn btn-sm" onClick={clearFilters}>✕ Clear</button>}
          </div></motion.div>

          {/* timeline */}
          <motion.div className="panel" variants={cardVariants}>
            <div className="ph"><div className="ptitle">Event Timeline</div><span className="panel-badge">{timeline.reduce((a, b) => a + b.total, 0).toLocaleString()} req · {timeline.reduce((a, b) => a + b.blocked, 0).toLocaleString()} blocked</span></div>
            <div className="pb" style={{ height: 120, display: "flex", alignItems: "flex-end", gap: 2 }}>
              {timeline.length === 0 ? <Empty text="No traffic in this window." /> : timeline.map((b, i) => (
                <div key={i} title={`${fmtTime(b.ts)} · ${b.total} req · ${b.blocked} blocked`}
                  style={{ flex: 1, display: "flex", flexDirection: "column", justifyContent: "flex-end", height: "100%", minWidth: 2 }}>
                  <div style={{ height: `${(b.blocked / maxBucket) * 100}%`, background: "rgba(255,69,96,.85)", borderRadius: "2px 2px 0 0" }} />
                  <div style={{ height: `${((b.total - b.blocked) / maxBucket) * 100}%`, background: "rgba(0,229,255,.4)", borderRadius: timeline[i].blocked ? 0 : "2px 2px 0 0" }} />
                </div>
              ))}
            </div>
          </motion.div>

          {/* facets + results */}
          <div style={{ display: "grid", gridTemplateColumns: "260px 1fr", gap: 14 }}>
            <motion.div variants={cardVariants} style={{ display: "flex", flexDirection: "column", gap: 14 }}>
              <FacetCard title="Top Rules" facets={ruleFacets} onPick={k => { setRule(k); run({ rule: k }); }} />
              <FacetCard title="Top Source IPs" facets={ipFacets} onPick={k => { setIp(k); run({ ip: k }); }} />
              <FacetCard title="Top Protocols" facets={protocolFacets} onPick={k => { setProtocol(k); run({ protocol: k }); }} />
            </motion.div>

            <motion.div className="panel" variants={cardVariants}>
              <div className="ph"><div className="ptitle">Events ({events.length})</div>{loading && <span className="panel-badge">searching…</span>}</div>
              <div className="tw" style={{ maxHeight: 520, overflow: "auto" }}>
                {events.length === 0 ? <Empty text={loading ? "Searching…" : "No events match these filters in this window."} /> : (
                  <table>
                    <thead><tr><th>Time</th><th>IP</th><th>Site</th><th>Method</th><th>Proto</th><th>Path</th><th>Rule</th><th>Sev</th><th>Action</th><th>Status</th><th aria-label="detail" /></tr></thead>
                    <tbody>{events.map((e, i) => (
                      <tr key={i}
                          onClick={() => setSelected(e)}
                          style={{ cursor: "pointer" }}
                          title="Open event detail">
                        <td className="td3" style={{ whiteSpace: "nowrap" }}>{fmtTime(e.ts)}</td>
                        <td className="td2">{e.ip}{e.country ? ` (${e.country})` : ""}</td>
                        <td className="td3">{e.site}</td>
                        <td className="td3">{e.method}</td>
                        <td className="td3"><span className="bdg bcy">{e.protocol || "—"}</span></td>
                        <td style={{ maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={`${e.path} — ${e.attack}`}>{e.path}</td>
                        <td className="td3">{e.rule}</td>
                        <td><span className={`bdg ${e.severity === "CRITICAL" ? "br" : e.severity === "HIGH" ? "ba" : "bcy"}`}>{e.severity || "—"}</span></td>
                        <td><span className={`bdg ${e.action === "BLOCK" ? "br" : "ba"}`}>{e.action}</span></td>
                        <td className="td3">{e.status || "—"}</td>
                        <td className="td3" style={{ color: "var(--text3)" }} aria-hidden>›</td>
                      </tr>
                    ))}</tbody>
                  </table>
                )}
              </div>
            </motion.div>
          </div>
        </>
      )}
      <EventDrawer event={selected} sites={sites} onClose={() => setSelected(null)} />
    </motion.div>
  );
}

function FacetCard({ title, facets, onPick }: { title: string; facets: { key: string; count: number }[]; onPick: (k: string) => void }) {
  const max = Math.max(1, ...facets.map(f => f.count));
  return (
    <div className="panel">
      <div className="ph"><div className="ptitle">{title}</div></div>
      <div className="pb" style={{ display: "flex", flexDirection: "column", gap: 7 }}>
        {facets.length === 0 ? <div style={{ fontSize: 13, color: "var(--text3)", fontFamily: "var(--font-mono)" }}>—</div> :
          facets.map(f => (
            <div key={f.key} onClick={() => onPick(f.key)} style={{ cursor: "pointer" }} title="Filter by this">
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13, marginBottom: 2 }}>
                <span style={{ color: "var(--text2)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 160, fontFamily: "var(--font-mono)" }}>{f.key}</span>
                <span style={{ color: "var(--text)", fontFamily: "var(--font-mono)" }}>{f.count.toLocaleString()}</span>
              </div>
              <div style={{ height: 4, background: "var(--bg3)", borderRadius: 2, overflow: "hidden" }}>
                <div style={{ height: "100%", width: `${(f.count / max) * 100}%`, background: "rgba(0,229,255,.6)", borderRadius: 2 }} />
              </div>
            </div>
          ))}
      </div>
    </div>
  );
}

function Empty({ text }: { text: string }) {
  return <div style={{ padding: "22px 12px", textAlign: "center", fontSize: 13, color: "var(--text3)", fontFamily: "var(--font-mono)", width: "100%" }}>{text}</div>;
}
