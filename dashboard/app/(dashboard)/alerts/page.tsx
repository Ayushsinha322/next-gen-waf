"use client";
import { useState, useEffect } from "react";
import { showToast } from "@/components/ui/Toast";
import { api, type Alert } from "@/lib/api";

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

  const filtered = alerts.filter(a => {
    const hay = JSON.stringify(a).toLowerCase();
    const matchSearch = !search || hay.includes(search.toLowerCase());
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
    <div className="sec">
      <div style={{display:"flex",alignItems:"flex-start",justifyContent:"space-between",gap:14}}>
        <div><div className="sec-title">🔴 Security Alerts</div><div className="sec-sub">Real-time incident queue · {alerts.filter(a=>a.state==="open").length} open · DB-backed</div></div>
        <div style={{display:"flex",gap:8}}>
          <button className="btn bg-btn btn-sm" onClick={loadAlerts}>⟳ Refresh</button>
          <button className="btn bc btn-sm" onClick={ackAll}>✅ Ack All Open</button>
        </div>
      </div>

      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:12}}>
        {[{cls:"",lbl:"Critical",val:String(counts.critical),valCls:"r"},{cls:"ka",lbl:"High",val:String(counts.high),valCls:"a"},{cls:"kc",lbl:"Medium",val:String(counts.medium),valCls:"c"},{cls:"kg",lbl:"Low/Info",val:String(counts.low),valCls:"g"}].map((k,i)=>(
          <div key={i} className={`kpi ${k.cls}`}><div className="kpi-lbl">{k.lbl}</div><div className={`kpi-val ${k.valCls}`}>{k.val}</div></div>
        ))}
      </div>

      <div className="panel">
        <div className="ph">
          <div className="ptitle">🔴 Alert Queue ({filtered.length})</div>
          <div style={{display:"flex",gap:8,flexWrap:"wrap",alignItems:"center"}}>
            <div style={{position:"relative"}}><span style={{position:"absolute",left:10,top:"50%",transform:"translateY(-50%)",color:"var(--text3)",fontSize:12,pointerEvents:"none"}}>🔍</span><input className="fi2" type="text" placeholder="Search alerts..." style={{width:180}} value={search} onChange={e=>setSearch(e.target.value)} /></div>
            <select className="fsel" value={sevFilter} onChange={e=>setSevFilter(e.target.value)}><option value="">All Severity</option><option value="CRITICAL">CRITICAL</option><option value="HIGH">HIGH</option><option value="MEDIUM">MEDIUM</option><option value="LOW">LOW</option></select>
            <select className="fsel" value={stateFilter} onChange={e=>setStateFilter(e.target.value)}><option value="">All States</option><option value="open">Open</option><option value="acked">Acknowledged</option><option value="resolved">Resolved</option></select>
          </div>
        </div>
        <div className="tw">
          {loading ? (
            <div style={{padding:"24px",textAlign:"center",fontFamily:"'Share Tech Mono',monospace",fontSize:11,color:"var(--text3)"}}>Loading alerts…</div>
          ) : filtered.length === 0 ? (
            <div style={{padding:"24px",textAlign:"center",fontFamily:"'Share Tech Mono',monospace",fontSize:11,color:"var(--text3)"}}>No alerts found</div>
          ) : (
            <table>
              <thead><tr><th>Severity</th><th>Time</th><th>Kind</th><th>Summary</th><th>State</th><th>Actions</th></tr></thead>
              <tbody>
                {filtered.map(a => {
                  const det = a.details as Record<string, unknown>;
                  return (
                    <tr key={a.id} className={`sev-${a.severity[0].toLowerCase()}`}>
                      <td>{sevBadge(a.severity)}</td>
                      <td className="td3">{new Date(a.created_at).toLocaleTimeString()}</td>
                      <td><span className="bdg bcy"><span className="bdr" />{a.kind}</span></td>
                      <td style={{maxWidth:260,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{a.summary}</td>
                      <td><span className={`bdg ${a.state==="open"?"br":a.state==="acked"?"ba":a.state==="resolved"?"bgg":"bgr"}`}>{a.state.toUpperCase()}</span></td>
                      <td><div style={{display:"flex",gap:4}}>
                        {det?.ip && <button className="btn bgn btn-xs" onClick={() => showToast(`${det.ip} flagged`,"s","🛡️")}>Block IP</button>}
                        {a.state === "open" && <button className="btn bg-btn btn-xs" onClick={() => ackAlert(a.id)}>✓ Ack</button>}
                        {a.state !== "resolved" && <button className="btn bg-btn btn-xs" onClick={() => resolveAlert(a.id)}>✓ Close</button>}
                        <button className="btn bc btn-xs" onClick={() => showToast("Analysing with AI...","i","🤖")}>🤖</button>
                      </div></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
