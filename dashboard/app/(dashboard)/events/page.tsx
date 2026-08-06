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
import { api, type WafEvent, type TimelineBucket, type EventQuery, type Site, type LogProfile } from "@/lib/api";
import EventDrawer from "@/components/events/EventDrawer";
import LogProfilePanel, { type ProfileFilters } from "@/components/events/LogProfilePanel";
import { staggerContainer, fadeUp, cardVariants } from "@/lib/animations";

const RANGES: { label: string; secs: number }[] = [
  { label: "1h", secs: 3600 },
  { label: "24h", secs: 86400 },
  { label: "7d", secs: 604800 },
  { label: "30d", secs: 2592000 },
];

function fmtTime(ts: number) { return new Date(ts * 1000).toLocaleString(); }

/** Format a unix timestamp for a <input type="datetime-local">, which wants
 *  local wall-clock with no zone suffix. */
function toLocalInput(ts: number): string {
  const d = new Date(ts * 1000);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** Seconds since epoch for a datetime-local value, interpreted as local time —
 *  the operator types the customer's date in their own clock. */
function fromLocalInput(v: string): number {
  return Math.floor(new Date(v).getTime() / 1000);
}

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

  // Time window. "relative" is the rolling last-N presets; "absolute" is the
  // explicit From/To a customer asks for ("logs for 3 August"), which the
  // presets cannot express at all.
  const [mode, setMode] = useState<"relative" | "absolute">("relative");
  const [absFrom, setAbsFrom] = useState("");
  const [absTo, setAbsTo] = useState("");
  // The window the results on screen actually cover. Export reuses it so the
  // file the customer receives matches the preview the operator just checked.
  const [win, setWin] = useState<{ from: number; to: number }>(() => {
    const to = Math.floor(Date.now() / 1000) + 60;
    return { from: to - 86400 - 60, to };
  });

  // Support ID lookup — the operator's entry point when a customer calls
  // quoting the id from a block page.
  const [supportId, setSupportId] = useState("");
  const [lookingUp, setLookingUp] = useState(false);

  // Saved per-application views.
  const [profiles, setProfiles] = useState<LogProfile[]>([]);
  const [activeProfileId, setActiveProfileId] = useState("");
  const [exporting, setExporting] = useState(false);

  // active filters
  const [q, setQ] = useState("");
  const [site, setSite] = useState("");
  const [rule, setRule] = useState("");
  const [action, setAction] = useState("");
  const [ip, setIp] = useState("");
  const [protocol, setProtocol] = useState("");
  const [severity, setSeverity] = useState("");
  // No filter-bar control of its own — a profile can still carry one, and it is
  // applied to the query and shown as an active-filter chip.
  const [country, setCountry] = useState("");

  // `override` lets callers search with a value they just set this render —
  // `setRule(k); run()` would otherwise search with the *previous* rule because
  // state updates and this captured closure both lag a render behind.
  const run = useCallback(async (override?: Partial<EventQuery>) => {
    let from: number, to: number;
    if (mode === "absolute" && absFrom && absTo) {
      from = fromLocalInput(absFrom);
      to = fromLocalInput(absTo);
      if (!Number.isFinite(from) || !Number.isFinite(to) || to <= from) {
        showToast("'To' must be after 'From'", "e", "⚠️");
        return;
      }
    } else {
      to = Math.floor(Date.now() / 1000) + 60;
      from = to - rangeSecs - 60;
    }
    setLoading(true);
    setWin({ from, to });
    const spanSecs = to - from;
    const filter: EventQuery = { from, to, limit: 300, q, site, rule, action, ip, protocol, severity, country, ...override };
    try {
      const st = await api.events.status();
      setStatus(st);
      if (!st.configured || !st.reachable) { setLoading(false); return; }
      const [s, t, rf, ipf, pf] = await Promise.all([
        api.events.search(filter),
        api.events.timeline(from, to, spanSecs > 86400 ? 3600 : 60),
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
  }, [mode, absFrom, absTo, rangeSecs, q, site, rule, action, ip, protocol, severity, country]);

  // Re-run whenever the window changes — a preset click, or a complete
  // From/To pair. Filter edits still wait for Search, so typing an IP does not
  // fire a query per keystroke.
  useEffect(() => {
    if (mode === "absolute" && !(absFrom && absTo)) return;
    run();
  }, [rangeSecs, mode, absFrom, absTo]); // eslint-disable-line react-hooks/exhaustive-deps

  /** Look up a Support ID. Replaces the results table with the single matching
   *  request and opens it, since that is the only thing the operator wants. */
  async function lookupSupportId() {
    const id = supportId.trim();
    if (!id) return;
    setLookingUp(true);
    try {
      const r = await api.events.bySupportID(id);
      const found = r.events ?? [];
      setEvents(found);
      // Detach from any saved view: the table no longer reflects its filters.
      setActiveProfileId("");
      if (found.length === 0) {
        showToast(
          "No request found with that Support ID — check it was copied in full, or that the event store still retains that date",
          "e", "🔍");
      } else {
        setSelected(found[0]);
      }
    } catch (e) {
      showToast(e instanceof Error ? e.message : "Lookup failed", "e", "⚠️");
    } finally {
      setLookingUp(false);
    }
  }

  const loadProfiles = useCallback(() => {
    api.logProfiles.list()
      .then(r => setProfiles(r.profiles ?? []))
      // Non-fatal: Threat Search itself must keep working without saved views.
      .catch(() => { /* leaves the picker empty */ });
  }, []);

  useEffect(() => { loadProfiles(); }, [loadProfiles]);

  /** Apply a saved view: its filters, its site, and its default window. */
  function loadProfile(p: LogProfile | null) {
    setActiveProfileId(p?.id ?? "");
    if (!p) return;
    setSite(p.site); setRule(p.rule); setAction(p.action); setIp(p.ip);
    setCountry(p.country); setProtocol(p.protocol); setSeverity(p.severity); setQ(p.q);
    // Opening a profile puts you on its default rolling window; the operator
    // then narrows to the date the customer actually asked for.
    setMode("relative");
    setRangeSecs(p.default_range_secs);
    run({
      site: p.site, rule: p.rule, action: p.action, ip: p.ip,
      country: p.country, protocol: p.protocol, severity: p.severity, q: p.q,
    });
  }

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
  const clearFilters = () => {
    setQ(""); setSite(""); setRule(""); setAction(""); setIp(""); setProtocol("");
    setSeverity(""); setCountry("");
    // Clearing the filters detaches from the saved view — leaving the profile
    // selected while its filters are gone would misreport what is on screen.
    setActiveProfileId("");
    run({ q: "", site: "", rule: "", action: "", ip: "", protocol: "", severity: "", country: "" });
  };
  const activeFilters = [["site", site], ["rule", rule], ["action", action], ["ip", ip],
    ["protocol", protocol], ["severity", severity], ["country", country], ["q", q]]
    .filter(([, v]) => v) as [string, string][];
  const filters: ProfileFilters = { site, rule, action, ip, country, protocol, severity, q };

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
            <button key={r.label} onClick={() => { setMode("relative"); setRangeSecs(r.secs); }} style={{
              padding: "6px 14px", borderRadius: 7, border: "none", cursor: "pointer", fontSize: 14, fontWeight: 600,
              background: mode === "relative" && rangeSecs === r.secs ? "var(--cyan)" : "transparent",
              color: mode === "relative" && rangeSecs === r.secs ? "#021018" : "var(--text2)",
            }}>{r.label}</button>
          ))}
          <button
            onClick={() => {
              // Seed the pickers from the window already on screen so switching
              // to Custom never blanks the view.
              if (!absFrom) setAbsFrom(toLocalInput(win.from));
              if (!absTo) setAbsTo(toLocalInput(win.to));
              setMode("absolute");
            }}
            title="Pick exact dates — for when a customer asks for a specific day"
            style={{
              padding: "6px 14px", borderRadius: 7, border: "none", cursor: "pointer", fontSize: 14, fontWeight: 600,
              background: mode === "absolute" ? "var(--cyan)" : "transparent",
              color: mode === "absolute" ? "#021018" : "var(--text2)",
            }}>Custom</button>
        </div>
      </motion.div>

      {mode === "absolute" && (
        <motion.div className="panel" variants={fadeUp}>
          <div className="pb" style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "flex-end" }}>
            <div className="fg2">
              <label className="flbl2">Whole day</label>
              <input
                className="fi2" type="date"
                title="The common ask — pick one date and get midnight to midnight"
                onChange={e => {
                  if (!e.target.value) return;
                  setAbsFrom(`${e.target.value}T00:00`);
                  const next = new Date(`${e.target.value}T00:00`);
                  next.setDate(next.getDate() + 1);
                  setAbsTo(toLocalInput(Math.floor(next.getTime() / 1000)));
                }}
              />
            </div>
            <div className="fg2">
              <label className="flbl2">From</label>
              <input className="fi2" type="datetime-local" value={absFrom} onChange={e => setAbsFrom(e.target.value)} />
            </div>
            <div className="fg2">
              <label className="flbl2">To</label>
              <input className="fi2" type="datetime-local" value={absTo} onChange={e => setAbsTo(e.target.value)} />
            </div>
            <div style={{ fontSize: 12, color: "var(--text3)", paddingBottom: 6, maxWidth: 320 }}>
              Times are your local clock. Timestamps inside the exported file are
              UTC, and its name states the window it covers.
            </div>
          </div>
        </motion.div>
      )}

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
          {/* Support ID lookup — deliberately above the filters and outside the
              time range, because it answers a phone call rather than a search. */}
          <motion.div className="panel" variants={fadeUp}>
            <div className="ph">
              <div className="ptitle">🎫 Support ID lookup</div>
              <span className="panel-badge">ignores time range</span>
            </div>
            <div className="pb" style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
              <input
                className="fi2"
                style={{ flex: 1, minWidth: 320, fontFamily: "var(--font-mono)" }}
                placeholder="Paste the Support ID from the customer's block page…"
                value={supportId}
                onChange={e => setSupportId(e.target.value)}
                onKeyDown={e => e.key === "Enter" && lookupSupportId()}
              />
              <button className="btn bc btn-sm" onClick={lookupSupportId} disabled={lookingUp || !supportId.trim()}>
                {lookingUp ? "Looking up…" : "Find request"}
              </button>
              {supportId && (
                <button className="btn bg-btn btn-sm" onClick={() => { setSupportId(""); run(); }}>✕ Clear</button>
              )}
            </div>
          </motion.div>

          {/* saved per-application views + the export handed to a customer */}
          <motion.div variants={fadeUp}>
            <LogProfilePanel
              profiles={profiles}
              sites={sites}
              activeId={activeProfileId}
              filters={filters}
              from={win.from}
              to={win.to}
              busy={loading || exporting}
              onLoad={loadProfile}
              onChanged={loadProfiles}
              onExporting={setExporting}
            />
          </motion.div>

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
            <select className="fsel" value={severity} onChange={e => { setSeverity(e.target.value); run({ severity: e.target.value }); }}>
              <option value="">All severities</option>
              {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map(s => <option key={s} value={s}>{s}</option>)}
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
