"use client";
import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { showToast } from "@/components/ui/Toast";
import { api, type Alert } from "@/lib/api";
import { staggerContainer, cardVariants, fadeUp, spring } from "@/lib/animations";

export default function AlertsPage() {
  const [alerts, setAlerts]       = useState<Alert[]>([]);
  const [loading, setLoading]     = useState(true);
  const [search, setSearch]       = useState("");
  const [sevFilter, setSevFilter] = useState("");
  const [stateFilter, setStateFilter] = useState("");

  async function loadAlerts() {
    setLoading(true);
    try {
      const res = await api.alerts.list();
      setAlerts(res.alerts ?? []);
    } catch {
      showToast("Failed to load alerts","e","⚠️");
    } finally {
      setLoading(false);
    }
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

  const counts = {
    critical: alerts.filter(a => a.severity === "critical" && a.state === "open").length,
    high:     alerts.filter(a => a.severity === "high"     && a.state === "open").length,
    medium:   alerts.filter(a => a.severity === "medium"   && a.state === "open").length,
    low:      alerts.filter(a => (a.severity === "low" || a.severity === "info") && a.state === "open").length,
  };

  async function ackAll() {
    const open = alerts.filter(a => a.state === "open");
    await Promise.allSettled(open.map(a => api.alerts.ack(a.id)));
    showToast(`${open.length} alerts acknowledged`,"s","✅");
    loadAlerts();
  }

  async function resolveAlert(id: string) {
    try {
      await api.alerts.resolve(id);
      showToast("Alert resolved","s","✅");
      setAlerts(p => p.map(a => a.id === id ? { ...a, state: "resolved" } : a));
    } catch {
      showToast("Failed to resolve","e","⚠️");
    }
  }

  async function ackAlert(id: string) {
    try {
      await api.alerts.ack(id);
      showToast("Alert acknowledged","s","✅");
      setAlerts(p => p.map(a => a.id === id ? { ...a, state: "acked" } : a));
    } catch {
      showToast("Failed to acknowledge","e","⚠️");
    }
  }

  function sevBadge(sev: string) {
    const s = sev.toLowerCase();
    return <span className={`bdg ${s==="critical"?"br blink":s==="high"?"ba":s==="medium"?"bcy":"bgr"}`}><span className="bdr" />{sev.toUpperCase()}</span>;
  }

  return (
    <motion.div className="sec" variants={staggerContainer} initial="hidden" animate="visible">
      <motion.div variants={fadeUp} style={{display:"flex",alignItems:"flex-start",justifyContent:"space-between",gap:14}}>
        <div><div className="sec-title">🔴 Security Alerts</div><div className="sec-sub">Real-time incident queue · {alerts.filter(a=>a.state==="open").length} open · {live ? <span style={{color:"var(--green)"}}>● live</span> : <span style={{color:"var(--text3)"}}>○ offline</span>} · DB-backed</div></div>
        <div style={{display:"flex",gap:8}}>
          <motion.button className="btn bg-btn btn-sm" onClick={loadAlerts} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>⟳ Refresh</motion.button>
          <motion.a className="btn bg-btn btn-sm" href="/settings" whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>🔔 Channels</motion.a>
          <motion.button className="btn bc btn-sm" onClick={ackAll} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>✅ Ack All Open</motion.button>
        </div>
      </motion.div>

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
          <div className="ptitle">🔴 Alert Queue ({filtered.length})</div>
          <div style={{display:"flex",gap:8,flexWrap:"wrap",alignItems:"center"}}>
            <div style={{position:"relative"}}><span style={{position:"absolute",left:10,top:"50%",transform:"translateY(-50%)",color:"var(--text3)",fontSize: 14,pointerEvents:"none"}}>🔍</span><input className="fi2" type="text" placeholder="Search alerts..." style={{width:180}} value={search} onChange={e=>setSearch(e.target.value)} /></div>
            <select className="fsel" value={sevFilter} onChange={e=>setSevFilter(e.target.value)}><option value="">All Severity</option><option value="CRITICAL">CRITICAL</option><option value="HIGH">HIGH</option><option value="MEDIUM">MEDIUM</option><option value="LOW">LOW</option></select>
            <select className="fsel" value={stateFilter} onChange={e=>setStateFilter(e.target.value)}><option value="">All States</option><option value="open">Open</option><option value="acked">Acknowledged</option><option value="resolved">Resolved</option></select>
          </div>
        </div>
        <div className="tw">
          {loading ? (
            <div style={{padding:"24px",textAlign:"center",fontFamily:"'Share Tech Mono',monospace",fontSize: 13,color:"var(--text3)"}}>Loading alerts…</div>
          ) : filtered.length === 0 ? (
            <div style={{padding:"24px",textAlign:"center",fontFamily:"'Share Tech Mono',monospace",fontSize: 13,color:"var(--text3)"}}>No alerts found</div>
          ) : (
            <table>
              <thead><tr><th>Severity</th><th>Time</th><th>Kind</th><th>Summary</th><th>State</th><th>Actions</th></tr></thead>
              <tbody>
                {filtered.map((a, idx) => {
                  const det = a.details as Record<string, unknown>;
                  return (
                    <motion.tr key={a.id} className={`sev-${a.severity[0].toLowerCase()}`} initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: idx * 0.015 }}>
                      <td>{sevBadge(a.severity)}</td>
                      <td className="td3">{new Date(a.created_at).toLocaleTimeString()}</td>
                      <td><span className="bdg bcy"><span className="bdr" />{a.kind}</span></td>
                      <td style={{maxWidth:260,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{a.summary}</td>
                      <td><span className={`bdg ${a.state==="open"?"br":a.state==="acked"?"ba":a.state==="resolved"?"bgg":"bgr"}`}>{a.state.toUpperCase()}</span></td>
                      <td><div style={{display:"flex",gap:4}}>
                        {det?.ip && <motion.button className="btn bgn btn-xs" whileHover={{ scale: 1.06 }} whileTap={{ scale: 0.95 }} onClick={() => showToast(`${det.ip} flagged`,"s","🛡️")}>Block IP</motion.button>}
                        {a.state === "open" && <motion.button className="btn bg-btn btn-xs" whileHover={{ scale: 1.06 }} whileTap={{ scale: 0.95 }} onClick={() => ackAlert(a.id)}>✓ Ack</motion.button>}
                        {a.state !== "resolved" && <motion.button className="btn bg-btn btn-xs" whileHover={{ scale: 1.06 }} whileTap={{ scale: 0.95 }} onClick={() => resolveAlert(a.id)}>✓ Close</motion.button>}
                        <button className="btn bc btn-xs" onClick={() => showToast("Analysing with AI...","i","🤖")}>🤖</button>
                      </div></td>
                    </motion.tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </motion.div>
    </motion.div>
  );
}