"use client";
/**
 * Audit Log — tamper-evident, HMAC-chained activity trail from the control
 * plane (audit_logs table). Real data via GET /api/v1/audit. Compliance/
 * forensics view: who did what, when, from where.
 */
import { useState, useEffect, useMemo } from "react";
import { motion } from "framer-motion";
import { showToast } from "@/components/ui/Toast";
import { api, type AuditEntry } from "@/lib/api";
import { staggerContainer, cardVariants, fadeUp } from "@/lib/animations";

// Coarse category + icon from the dot-notation action (e.g. "site.create").
function actionMeta(action: string): { icon: string; cls: string } {
  const head = action.split(".")[0];
  switch (head) {
    case "site":         return { icon: "🌐", cls: "bcy" };
    case "rule":         return { icon: "📜", cls: "bcy" };
    case "notification": return { icon: "🔔", cls: "ba" };
    case "alert":        return { icon: "🔴", cls: "br" };
    case "user":         return { icon: "👤", cls: "bgr" };
    case "apikey":       return { icon: "🔑", cls: "ba" };
    case "auth":         return { icon: "🔓", cls: "bgr" };
    case "cert":         return { icon: "🔐", cls: "bgg" };
    default:             return { icon: "•",  cls: "bgr" };
  }
}

export default function AuditPage() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch]   = useState("");
  const [kind, setKind]       = useState("");

  async function load() {
    setLoading(true);
    try { setEntries((await api.audit.list()).entries ?? []); }
    catch { showToast("Failed to load audit log", "e", "⚠️"); }
    finally { setLoading(false); }
  }
  useEffect(() => { load(); }, []);

  const kinds = useMemo(
    () => Array.from(new Set(entries.map(e => e.action.split(".")[0]))).sort(),
    [entries]
  );
  const filtered = entries.filter(e => {
    const matchSearch = !search || JSON.stringify(e).toLowerCase().includes(search.toLowerCase());
    const matchKind   = !kind   || e.action.startsWith(kind + ".");
    return matchSearch && matchKind;
  });

  return (
    <motion.div className="sec" variants={staggerContainer} initial="hidden" animate="visible">
      <motion.div variants={fadeUp} style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 14 }}>
        <div>
          <div className="sec-title">📋 Audit Log</div>
          <div className="sec-sub">Tamper-evident HMAC-chained activity trail · {entries.length} recent events · compliance-grade</div>
        </div>
        <motion.button className="btn bg-btn btn-sm" onClick={load} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>⟳ Refresh</motion.button>
      </motion.div>

      <motion.div className="panel" variants={fadeUp}>
        <div className="ph">
          <div className="ptitle">Activity ({filtered.length})</div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
            <div style={{ position: "relative" }}>
              <span style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)", color: "var(--text3)", fontSize: 14, pointerEvents: "none" }}>🔍</span>
              <input className="fi2" type="text" placeholder="Search actions, IPs…" style={{ width: 200 }} value={search} onChange={e => setSearch(e.target.value)} />
            </div>
            <select className="fsel" value={kind} onChange={e => setKind(e.target.value)}>
              <option value="">All categories</option>
              {kinds.map(k => <option key={k} value={k}>{k}</option>)}
            </select>
          </div>
        </div>
        <div className="tw">
          {loading ? (
            <div style={{ padding: 24, textAlign: "center", fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--text3)" }}>Loading audit log…</div>
          ) : filtered.length === 0 ? (
            <div style={{ padding: 24, textAlign: "center", fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--text3)" }}>No audit events recorded yet. Administrative actions (site/rule/channel changes, logins) appear here.</div>
          ) : (
            <table>
              <thead><tr><th>Time</th><th>Action</th><th>Target</th><th>Actor</th><th>Source IP</th></tr></thead>
              <tbody>
                {filtered.map((e, idx) => {
                  const m = actionMeta(e.action);
                  return (
                    <motion.tr key={e.id} initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: Math.min(idx * 0.012, 0.4) }}>
                      <td className="td3">{new Date(e.created_at).toLocaleString()}</td>
                      <td><span className={`bdg ${m.cls}`}>{m.icon} {e.action}</span></td>
                      <td className="td2" style={{ maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {e.target_kind}{e.target_id ? ` · ${e.target_id.slice(0, 8)}…` : ""}
                      </td>
                      <td className="td3">{e.actor_user_id ? e.actor_user_id.slice(0, 8) + "…" : "system"}</td>
                      <td className="td3">{e.ip || "—"}</td>
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
