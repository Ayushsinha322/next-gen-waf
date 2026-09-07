"use client";
/**
 * Audit Log — tamper-evident, HMAC-chained activity trail from the control
 * plane (audit_logs table). Real data via GET /api/v1/audit. Compliance/
 * forensics view: who did what, when, from where.
 */
import { useState, useEffect, useMemo } from "react";
import { motion } from "framer-motion";
import { showToast } from "@/components/ui/Toast";
import EmptyState from "@/components/ui/EmptyState";
import { api, type AuditEntry, type AuditVerifyResult } from "@/lib/api";
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
  // Chain verification is EXPLICITLY unknown until it has been run. The page
  // used to assert "compliance-grade" unconditionally while the verifier was
  // reachable from nothing at all — an unverifiable claim in the one view whose
  // whole purpose is being trustworthy.
  const [verify, setVerify]   = useState<AuditVerifyResult | null>(null);
  const [verifying, setVerifying] = useState(false);
  // Distinguishes "the store is down" from "there is no activity". A 503 used
  // to arrive as 200 + an empty list, so an outage rendered as a clean log.
  const [loadError, setLoadError] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    try {
      setEntries((await api.audit.list()).entries ?? []);
      setLoadError(null);
    } catch (e) {
      setEntries([]);
      setLoadError(e instanceof Error ? e.message : "audit log unavailable");
      showToast("Failed to load audit log", "e", "⚠️");
    } finally { setLoading(false); }
  }

  async function runVerify() {
    setVerifying(true);
    try {
      const r = await api.audit.verify();
      setVerify(r);
      showToast(r.verified ? "Audit chain verified" : "Audit chain DID NOT verify",
                r.verified ? "s" : "e", r.verified ? "🔒" : "🚨");
    } catch (e) {
      // A throw means the chain did not verify (409) or the check could not run
      // (503). Either way the honest state is "not verified" — never "unknown,
      // assume fine".
      setVerify({ verified: false, checked: 0, altered: [], chain_broken: [],
                  seq_gaps: [], unchained_rows: 0,
                  error: e instanceof Error ? e.message : "verification failed" });
      showToast("Audit chain verification failed", "e", "🚨");
    } finally { setVerifying(false); }
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
          <div className="sec-sub">
            HMAC-chained activity trail · {entries.length} recent events ·{" "}
            {verify === null
              ? "chain not yet verified"
              : verify.verified
                ? `chain verified — ${verify.checked} rows recomputed, none missing or reordered`
                : `⚠ chain DID NOT verify${verify.error ? `: ${verify.error}` : ""}`}
            {verify?.verified && verify.unchained_rows > 0 &&
              ` (${verify.unchained_rows} pre-chain rows checked individually)`}
          </div>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <motion.button className="btn bg-btn btn-sm" onClick={runVerify} disabled={verifying}
            title="Recompute every row's HMAC and check the chain for gaps or reordering"
            whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>
            {verifying ? "Verifying…" : "🔒 Verify chain"}
          </motion.button>
          <motion.button className="btn bg-btn btn-sm" onClick={load} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>⟳ Refresh</motion.button>
        </div>
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
          ) : loadError ? (
            /* An unreadable audit store must never render as an empty log —
               that is the most reassuring possible display of the least
               reassuring possible state. */
            <div style={{ padding: 24, textAlign: "center", fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--red)" }}>
              ⚠ The audit log could not be read — this is NOT the same as “no activity”.
              <div style={{ marginTop: 8, color: "var(--text3)" }}>{loadError}</div>
            </div>
          ) : filtered.length === 0 ? (
            <EmptyState icon="🧾" title="No audit events yet" hint="Every administrative action — site, rule and channel changes, logins, settings — is written here in a hash-chained log. Make a change and it appears within a second." />
          ) : (
            <table>
              <thead><tr><th>Time</th><th>Result</th><th>Action</th><th>Target</th><th>Actor</th><th>Source IP</th></tr></thead>
              <tbody>
                {filtered.map((e, idx) => {
                  const m = actionMeta(e.action);
                  return (
                    <motion.tr key={e.id} initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: Math.min(idx * 0.012, 0.4) }}>
                      <td className="td3">{new Date(e.created_at).toLocaleString()}</td>
                      {/* A failed login must be visibly different from a
                          successful one. The stream used to report SUCCESS for
                          everything, so they were indistinguishable here. */}
                      <td>
                        <span className={`bdg ${e.result === "FAILURE" ? "br" : "bgg"}`}>
                          {e.result === "FAILURE" ? "FAILURE" : "SUCCESS"}
                        </span>
                      </td>
                      <td><span className={`bdg ${m.cls}`}>{m.icon} {e.action}</span></td>
                      <td className="td2" style={{ maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {e.target_kind}{e.target_id ? ` · ${e.target_id.slice(0, 8)}…` : ""}
                      </td>
                      {/* Prefer the resolved email: a compliance view whose
                          "who" column is a UUID cannot answer who did it. */}
                      <td className="td3" title={e.actor_user_id ?? "system"}>
                        {e.actor_email || (e.actor_user_id ? e.actor_user_id.slice(0, 8) + "…" : "system")}
                      </td>
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
