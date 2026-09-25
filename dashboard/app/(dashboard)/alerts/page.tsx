"use client";
import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { showToast } from "@/components/ui/Toast";
import EmptyState from "@/components/ui/EmptyState";
import { announceAlertsChanged } from "@/lib/alertEvents";
import { api, type Alert, type NotificationChannel } from "@/lib/api";
import { staggerContainer, cardVariants, fadeUp, spring } from "@/lib/animations";
import Icon from "@/components/ui/Icon";

export default function AlertsPage() {
  const [alerts, setAlerts]       = useState<Alert[]>([]);
  const [loading, setLoading]     = useState(true);
  const [search, setSearch]       = useState("");
  const [sevFilter, setSevFilter] = useState("");
  const [stateFilter, setStateFilter] = useState("");
  // Delivery channels, loaded alongside the queue: an alert nobody is paged
  // about is a log line with a badge. The page says so instead of pretending.
  const [channels, setChannels]   = useState<NotificationChannel[] | null>(null);
  const [expanded, setExpanded]   = useState<Set<string>>(new Set());
  const [blocking, setBlocking]   = useState<string | null>(null);

  async function loadAlerts() {
    setLoading(true);
    try {
      // Two fetches on purpose. The unfiltered list is capped at 200 rows by
      // recency, so on a deployment with history the OPEN rows fall off the end
      // of it: this page reported "0 open" while eleven criticals raised in July
      // were still open in the database, because the count was derived from a
      // list that no longer contained them. Ask for the open set explicitly,
      // merge it in for display, and count from it.
      const [recent, open] = await Promise.all([
        api.alerts.list(),
        api.alerts.list("open"),
      ]);
      const byID = new Map<string, Alert>();
      for (const a of [...(open.alerts ?? []), ...(recent.alerts ?? [])]) byID.set(a.id, a);
      setAlerts([...byID.values()].sort(
        (x, y) => new Date(y.created_at).getTime() - new Date(x.created_at).getTime()));
    } catch {
      showToast("Failed to load alerts","e");
    } finally {
      setLoading(false);
    }
    try { setChannels((await api.notifications.list()).channels ?? []); } catch { setChannels(null); }
  }

  useEffect(() => { loadAlerts(); }, []);

  // Live SOC feed: the alert engine publishes "alert" entries to the hub as it
  // raises them — surface them instantly without waiting for a refresh.
  const [live, setLive] = useState(false);
  useEffect(() => {
    let es: EventSource | null = null;
    try {
      es = new EventSource(api.logs.streamURL("alert"));
      es.onopen = () => setLive(true);
      es.onerror = () => setLive(false);
      es.onmessage = (evt) => {
        try {
          const e: { data: Record<string, unknown> } = JSON.parse(evt.data);
          if (!e.data || !e.data.id) return;
          const incoming = {
            id: String(e.data.id),
            tenant_id: "",
            site_id: null,
            severity: String(e.data.severity ?? "medium") as Alert["severity"],
            kind: String(e.data.kind ?? "alert"),
            summary: String(e.data.summary ?? ""),
            details: {} as Record<string, unknown>,
            state: (String(e.data.state ?? "open")) as Alert["state"],
            created_at: String(e.data.ts ?? new Date().toISOString()),
            resolved_at: null,
          };
          // De-dupe against existing (the SSE replays recent buffer on connect).
          setAlerts(p => p.some(a => a.id === incoming.id) ? p : [incoming, ...p].slice(0, 300));
        } catch { /* */ }
      };
    } catch { /* */ }
    return () => { es?.close(); };
  }, []);

  const needle = search.toLowerCase();
  const filtered = alerts.filter(a => {
    // Only pay for the JSON.stringify scan when there's actually a search term.
    const matchSearch = !needle || JSON.stringify(a).toLowerCase().includes(needle);
    const matchSev    = !sevFilter   || a.severity.toUpperCase() === sevFilter;
    const matchState  = !stateFilter || a.state === stateFilter;
    return matchSearch && matchSev && matchState;
  });

  // Group repeats of the same condition. The engine re-raises an ongoing
  // attack every throttle interval, so one incident used to be forty rows; the
  // operator reads one row with ×40 and can expand it.
  type Group = { key: string; head: Alert; items: Alert[]; first: string; last: string; open: number };
  const groups: Group[] = (() => {
    const m = new Map<string, Group>();
    for (const a of filtered) {
      const det = (a.details ?? {}) as Record<string, unknown>;
      const key = `${a.kind}|${a.site_id ?? det.site ?? ""}|${det.ip ?? ""}`;
      const g = m.get(key);
      if (g) {
        g.items.push(a);
        if (a.created_at < g.first) g.first = a.created_at;
        if (a.created_at > g.last)  { g.last = a.created_at; g.head = a; }
        if (a.state === "open") g.open++;
      } else {
        m.set(key, { key, head: a, items: [a], first: a.created_at, last: a.created_at, open: a.state === "open" ? 1 : 0 });
      }
    }
    return Array.from(m.values()).sort((x, y) => (y.last > x.last ? 1 : -1));
  })();
  const toggleGroup = (k: string) => setExpanded(p => { const n = new Set(p); n.has(k) ? n.delete(k) : n.add(k); return n; });

  async function ackGroup(g: Group) {
    const open = g.items.filter(a => a.state === "open");
    await Promise.allSettled(open.map(a => api.alerts.ack(a.id)));
    showToast(`${open.length} acknowledged`,"s");
    setAlerts(p => p.map(a => open.some(o => o.id === a.id) ? { ...a, state: "acked" } : a));
    announceAlertsChanged();
  }
  async function closeGroup(g: Group) {
    const todo = g.items.filter(a => a.state !== "resolved");
    await Promise.allSettled(todo.map(a => api.alerts.resolve(a.id)));
    showToast(`${todo.length} closed`,"s");
    setAlerts(p => p.map(a => todo.some(o => o.id === a.id) ? { ...a, state: "resolved" } : a));
    announceAlertsChanged();
  }

  /** Block a source for real: a manual block-tier indicator in the threat-intel
   *  corpus the data plane enforces. The previous button showed a toast that said
   *  "flagged" and did nothing. */
  async function blockIP(ip: string) {
    if (!confirm(`Block ${ip} on every site?\n\nAdds a manual block-tier indicator to the threat-intel corpus. Remove it from Threat Intel to unblock.`)) return;
    setBlocking(ip);
    try {
      await api.threatIntel.create({ type: "ip", value: ip, tier: "block", source: "console", category: "manual", confidence: 100 });
      showToast(`${ip} is now blocked (threat-intel, block tier)`, "s");
    } catch (e) {
      showToast(`Block failed: ${e instanceof Error ? e.message : String(e)}`, "e");
    } finally { setBlocking(null); }
  }

  const enabledChannels = channels?.filter(c => c.enabled) ?? [];
  // `alerts` now always contains the open rows (loadAlerts merges them in), so
  // deriving from it is correct again — and stays correct for alerts arriving
  // live over the event stream.
  const openAlerts = alerts.filter(a => a.state === "open");
  const openCount = openAlerts.length;
  const rel = (iso?: string | null) => {
    if (!iso) return "never";
    const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
    return s < 60 ? `${Math.round(s)}s ago` : s < 3600 ? `${Math.round(s/60)}m ago` : s < 86400 ? `${Math.round(s/3600)}h ago` : `${Math.round(s/86400)}d ago`;
  };

  const counts = {
    critical: openAlerts.filter(a => a.severity === "critical").length,
    high:     openAlerts.filter(a => a.severity === "high").length,
    medium:   openAlerts.filter(a => a.severity === "medium").length,
    low:      openAlerts.filter(a => a.severity === "low" || a.severity === "info").length,
  };

  async function ackAll() {
    const open = openAlerts;
    await Promise.allSettled(open.map(a => api.alerts.ack(a.id)));
    showToast(`${open.length} alerts acknowledged`,"s");
    loadAlerts();
    announceAlertsChanged();
  }

  async function resolveAlert(id: string) {
    try {
      await api.alerts.resolve(id);
      showToast("Alert resolved","s");
      setAlerts(p => p.map(a => a.id === id ? { ...a, state: "resolved" } : a));
      announceAlertsChanged();
    } catch {
      showToast("Failed to resolve","e");
    }
  }

  async function ackAlert(id: string) {
    try {
      await api.alerts.ack(id);
      showToast("Alert acknowledged","s");
      setAlerts(p => p.map(a => a.id === id ? { ...a, state: "acked" } : a));
      announceAlertsChanged();
    } catch {
      showToast("Failed to acknowledge","e");
    }
  }

  function sevBadge(sev: string) {
    const s = sev.toLowerCase();
    return <span className={`bdg ${s==="critical"?"br blink":s==="high"?"ba":s==="medium"?"bcy":"bgr"}`}><span className="bdr" />{sev.toUpperCase()}</span>;
  }

  return (
    <motion.div className="sec" variants={staggerContainer} initial="hidden" animate="visible">
      <motion.div variants={fadeUp} style={{display:"flex",alignItems:"flex-start",justifyContent:"space-between",gap:14}}>
        <div><div className="sec-title">Security Alerts</div><div className="sec-sub">Real-time incident queue · {alerts.filter(a=>a.state==="open").length} open · {live ? <span style={{color:"var(--green)"}}>● live</span> : <span style={{color:"var(--text3)"}}>○ offline</span>} · DB-backed</div></div>
        <div style={{display:"flex",gap:8}}>
          <motion.button className="btn bg-btn btn-sm" onClick={loadAlerts} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>⟳ Refresh</motion.button>
          <motion.a className="btn bg-btn btn-sm" href="/settings" whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>Channels</motion.a>
          <motion.button className="btn bc btn-sm" onClick={ackAll} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>Ack All Open</motion.button>
        </div>
      </motion.div>

      {channels !== null && enabledChannels.length === 0 && openCount > 0 && (
        <motion.div variants={fadeUp} className="code-block" style={{ borderLeft:"3px solid var(--red-b)", display:"flex", justifyContent:"space-between", alignItems:"center", gap:12, flexWrap:"wrap" }}>
          <span><span style={{ color:"var(--red-b)" }}>● NOBODY IS BEING PAGED.</span> {openCount} alert{openCount === 1 ? "" : "s"} open and no delivery channel is enabled — these stop at this screen.</span>
          <a className="btn bp btn-sm" href="/settings?tab=notifications">Add a channel →</a>
        </motion.div>
      )}
      {channels !== null && channels.length > 0 && (
        <motion.div variants={fadeUp} style={{ display:"flex", gap:10, flexWrap:"wrap", alignItems:"center", fontSize:12.5, fontFamily:"var(--font-mono)" }}>
          <span className="td3">DELIVERY</span>
          {channels.map(c => {
            const bad = c.enabled && c.last_status && c.last_status !== "ok";
            return (
              <span key={c.id} title={c.last_status ?? "not yet used"} className="bdg" style={{ textTransform:"none", background: !c.enabled ? "rgba(120,130,150,.12)" : bad ? "rgba(224,80,70,.15)" : "rgba(60,180,110,.14)", color: !c.enabled ? "var(--text3)" : bad ? "var(--red-b)" : "var(--green)" }}>
                {c.name} · {c.type} · {!c.enabled ? "off" : bad ? `FAILED ${rel(c.last_sent_at)}` : c.last_sent_at ? `ok ${rel(c.last_sent_at)}` : "never sent"}
              </span>
            );
          })}
        </motion.div>
      )}

      <motion.div variants={staggerContainer} initial="hidden" animate="visible" style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:12}}>
        {[{cls:"",lbl:"Critical",val:String(counts.critical),valCls:"r"},{cls:"ka",lbl:"High",val:String(counts.high),valCls:"a"},{cls:"kc",lbl:"Medium",val:String(counts.medium),valCls:"c"},{cls:"kg",lbl:"Low/Info",val:String(counts.low),valCls:"g"}].map((k,i)=>(
          <motion.div key={i} className={`kpi ${k.cls}`} variants={cardVariants}>
            <div className="kpi-lbl">{k.lbl}</div>
            <div className={`kpi-val ${k.valCls}`}>{k.val}</div>
          </motion.div>
        ))}
      </motion.div>

      <motion.div className="panel" variants={fadeUp}>
        <div className="ph">
          <div className="ptitle">Alert Queue ({groups.length} incident{groups.length === 1 ? "" : "s"} · {filtered.length} alerts)</div>
          <div style={{display:"flex",gap:8,flexWrap:"wrap",alignItems:"center"}}>
            <div style={{position:"relative"}}><span style={{position:"absolute",left:10,top:"50%",transform:"translateY(-50%)",color:"var(--text3)",fontSize: 14,pointerEvents:"none"}}><Icon name="search" size={14} /></span><input className="fi2" type="text" placeholder="Search alerts..." style={{width:180}} value={search} onChange={e=>setSearch(e.target.value)} /></div>
            <select className="fsel" value={sevFilter} onChange={e=>setSevFilter(e.target.value)}><option value="">All Severity</option><option value="CRITICAL">CRITICAL</option><option value="HIGH">HIGH</option><option value="MEDIUM">MEDIUM</option><option value="LOW">LOW</option></select>
            <select className="fsel" value={stateFilter} onChange={e=>setStateFilter(e.target.value)}><option value="">All States</option><option value="open">Open</option><option value="acked">Acknowledged</option><option value="resolved">Resolved</option></select>
          </div>
        </div>
        <div className="tw">
          {loading ? (
            <div style={{padding:"24px",textAlign:"center",fontFamily:"var(--font-mono)",fontSize: 13,color:"var(--text3)"}}>Loading alerts…</div>
          ) : filtered.length === 0 ? (
            <EmptyState icon="bell" title={alerts.length === 0 ? "No alerts" : "No alerts match this filter"}
              hint={alerts.length === 0 ? "Alerts are raised from live detections: attack spikes, repeat offenders, node and certificate problems. A quiet queue with traffic flowing is the good state." : "Change the severity or state filter to see the rest."}
              action={alerts.length === 0 ? { label: "Set up a delivery channel", href: "/settings?tab=notifications" } : undefined} />
          ) : (
            <table>
              <thead><tr><th>Severity</th><th>Last seen</th><th>Kind</th><th>Summary</th><th>State</th><th>Actions</th></tr></thead>
              <tbody>
                {groups.map((g, idx) => {
                  const a = g.head;
                  const det = (a.details ?? {}) as Record<string, unknown>;
                  const ip = typeof det.ip === "string" ? det.ip : "";
                  const many = g.items.length > 1;
                  const isOpen = expanded.has(g.key);
                  const row = (x: Alert, sub: boolean) => {
                    const d = (x.details ?? {}) as Record<string, unknown>;
                    return (
                      <motion.tr key={x.id} className={`sev-${x.severity[0].toLowerCase()}`} initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: sub ? 0 : idx * 0.015 }}
                        style={sub ? { opacity: .8, background:"rgba(255,255,255,.015)" } : undefined}>
                        <td>{sevBadge(x.severity)}</td>
                        <td className="td3" title={new Date(x.created_at).toLocaleString()}>{sub ? new Date(x.created_at).toLocaleTimeString() : rel(g.last)}</td>
                        <td><span className="bdg bcy"><span className="bdr" />{x.kind}</span></td>
                        <td style={{maxWidth:300,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}} title={x.summary}>
                          {!sub && many && (
                            <button className="btn bg-btn btn-xs" style={{ marginRight:8 }} onClick={() => toggleGroup(g.key)} title={`${g.items.length} alerts for this condition since ${new Date(g.first).toLocaleString()}`}>
                              {isOpen ? "▾" : "▸"} ×{g.items.length}
                            </button>
                          )}
                          {x.summary}
                        </td>
                        <td>
                          <span className={`bdg ${x.state==="open"?"br":x.state==="acked"?"ba":x.state==="resolved"?"bgg":"bgr"}`}>
                            {sub || !many ? x.state.toUpperCase() : g.open > 0 ? `${g.open} OPEN` : x.state.toUpperCase()}
                          </span>
                          {d.auto_resolved === true && <span className="td3" style={{ fontSize:10, marginLeft:6 }} title="Closed automatically: no recurrence within the quiet window">auto</span>}
                        </td>
                        <td><div style={{display:"flex",gap:4}}>
                          {!sub && ip && (
                            <motion.button className="btn bgn btn-xs" disabled={blocking === ip} whileHover={{ scale: 1.06 }} whileTap={{ scale: 0.95 }}
                              onClick={() => blockIP(ip)} title="Add a manual block-tier indicator for this IP to the threat-intel corpus">
                              {blocking === ip ? "…" : "Block IP"}
                            </motion.button>
                          )}
                          {sub ? (<>
                            {x.state === "open" && <motion.button className="btn bg-btn btn-xs" whileHover={{ scale: 1.06 }} whileTap={{ scale: 0.95 }} onClick={() => ackAlert(x.id)}>✓ Ack</motion.button>}
                            {x.state !== "resolved" && <motion.button className="btn bg-btn btn-xs" whileHover={{ scale: 1.06 }} whileTap={{ scale: 0.95 }} onClick={() => resolveAlert(x.id)}>✓ Close</motion.button>}
                          </>) : (<>
                            {g.open > 0 && <motion.button className="btn bg-btn btn-xs" whileHover={{ scale: 1.06 }} whileTap={{ scale: 0.95 }} onClick={() => many ? ackGroup(g) : ackAlert(a.id)}>✓ Ack{many ? " all" : ""}</motion.button>}
                            {g.items.some(i => i.state !== "resolved") && <motion.button className="btn bg-btn btn-xs" whileHover={{ scale: 1.06 }} whileTap={{ scale: 0.95 }} onClick={() => many ? closeGroup(g) : resolveAlert(a.id)}>✓ Close{many ? " all" : ""}</motion.button>}
                          </>)}
                        </div></td>
                      </motion.tr>
                    );
                  };
                  return [row(a, false), ...(many && isOpen ? g.items.filter(i => i.id !== a.id).map(i => row(i, true)) : [])];
                })}
              </tbody>
            </table>
          )}
        </div>
      </motion.div>
    </motion.div>
  );
}