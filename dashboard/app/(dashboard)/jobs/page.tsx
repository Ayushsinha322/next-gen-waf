"use client";
import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { showToast } from "@/components/ui/Toast";
import { api, type JobsResponse, type JobStatus } from "@/lib/api";
import { staggerContainer, fadeUp } from "@/lib/animations";

// ---------------------------------------------------------------------------
// System Jobs — what runs in the background, when it last ran, how it went,
// and a button to run it now. Until this page the threat-intel refresh, the
// certificate-expiry check, the node-health sweep, the disk-pressure check and
// alert auto-resolve ran with no trace but a log line; "freshness 59m ago" on
// the Threat Intel page was the only hint any of it existed.
// ---------------------------------------------------------------------------

const rel = (iso?: string) => {
  if (!iso) return "never";
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  const a = Math.abs(s); const past = s >= 0;
  const t = a < 60 ? `${Math.round(a)}s` : a < 3600 ? `${Math.round(a/60)}m` : a < 86400 ? `${Math.round(a/3600)}h` : `${Math.round(a/86400)}d`;
  return past ? `${t} ago` : `in ${t}`;
};

export default function JobsPage() {
  const [data, setData] = useState<JobsResponse | null>(null);
  const [err, setErr]   = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  async function load() {
    try { setData(await api.jobs.list()); setErr(null); }
    catch (e) { setErr(e instanceof Error ? e.message : String(e)); }
  }
  useEffect(() => { load(); const t = setInterval(load, 10_000); return () => clearInterval(t); }, []);

  async function run(j: JobStatus) {
    setBusy(j.name);
    try {
      const r = await api.jobs.run(j.name);
      if (r.ok) showToast(`${j.name}: ${r.job.last_note || "done"} (${r.job.last_duration_ms} ms)`, "s");
      else showToast(`${j.name} failed: ${r.job?.last_error || r.error || "unknown"}`, "e");
      await load();
    } catch (e) {
      showToast(`Could not run ${j.name}: ${e instanceof Error ? e.message : String(e)}`, "e");
    } finally { setBusy(null); }
  }

  const ti = data?.dataplane?.threat_intel;

  return (
    <motion.div className="sec" variants={staggerContainer} initial="hidden" animate="visible">
      <motion.div variants={fadeUp} style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 14 }}>
        <div>
          <div className="sec-title">System Jobs</div>
          <div className="sec-sub">
            Background work on the control plane and the data plane · last run, outcome, next due
            {data && ` · this control-plane node is the ${data.node.role}${data.node.runs_jobs ? "" : " — jobs run on the leader"}`}
          </div>
        </div>
        <button className="btn bg-btn btn-sm" onClick={load}>⟳ Refresh</button>
      </motion.div>

      {err && <motion.div variants={fadeUp} className="code-block" style={{ borderLeft: "3px solid var(--red-b)" }}><span style={{ color: "var(--red-b)" }}>● COULD NOT LOAD</span> — {err}</motion.div>}
      {data && !data.node.runs_jobs && (
        <motion.div variants={fadeUp} className="code-block" style={{ borderLeft: "3px solid var(--amber)" }}>
          <span style={{ color: "var(--amber)" }}>● THIS NODE IS A FOLLOWER</span> — the jobs below run on the Raft leader. Counts here are from this node&apos;s last term as leader; Run now is forwarded to the leader.
        </motion.div>
      )}

      <motion.div className="panel" variants={fadeUp}>
        <div className="ph"><div className="ptitle">Control plane ({data?.jobs.length ?? "…"})</div><span className="td3" style={{ fontSize: 12.5 }}>{data?.note}</span></div>
        <div className="tw">
          {!data ? <div style={{ padding: 24, textAlign: "center", fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--text3)" }}>Loading…</div> : (
            <table>
              <thead><tr><th>Job</th><th>Every</th><th>Last run</th><th>Result</th><th>Next due</th><th>Runs</th><th></th></tr></thead>
              <tbody>
                {data.jobs.map(j => {
                  const bad = !!j.last_error;
                  return (
                    <tr key={j.name}>
                      <td>
                        <div style={{ fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--cyan)" }}>{j.name}</div>
                        <div className="td3" style={{ fontSize: 12.5, whiteSpace: "normal", lineHeight: 1.45, marginTop: 2, maxWidth: 420 }}>{j.description}</div>
                      </td>
                      <td className="td3" style={{ fontFamily: "var(--font-mono)" }}>{j.interval}</td>
                      <td className="td3" title={j.last_end ?? ""}>{j.running ? <span style={{ color: "var(--cyan)" }}>running…</span> : rel(j.last_end)}{j.last_end && !j.running ? <div style={{ fontSize: 11 }}>{j.last_duration_ms} ms</div> : null}</td>
                      <td style={{ maxWidth: 300, whiteSpace: "normal" }}>
                        {j.runs === 0 ? <span className="td3">not yet run</span>
                          : bad ? <span style={{ color: "var(--red-b)", fontFamily: "var(--font-mono)", fontSize: 12.5 }} title={j.last_error}>✗ {j.last_error}</span>
                          : <span style={{ color: "var(--green)", fontFamily: "var(--font-mono)", fontSize: 12.5 }}>✓ {j.last_note || "ok"}</span>}
                      </td>
                      <td className="td3" title={j.next_due ?? ""}>{j.running ? "—" : rel(j.next_due)}</td>
                      <td className="td3" style={{ fontVariantNumeric: "tabular-nums" }}>{j.runs}{j.failures ? <span style={{ color: "var(--red-b)" }}> · {j.failures} failed</span> : ""}</td>
                      <td>{j.can_run_now && (
                        <motion.button className="btn bg-btn btn-xs" disabled={busy === j.name || j.running} whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }} onClick={() => run(j)}>
                          {busy === j.name ? "…" : "▶ Run now"}
                        </motion.button>
                      )}</td>
                    </tr>
                  );
                })}
                {data.jobs.length === 0 && <tr><td colSpan={7} className="td3" style={{ textAlign: "center", padding: 18 }}>no jobs registered on this node</td></tr>}
              </tbody>
            </table>
          )}
        </div>
      </motion.div>

      <motion.div className="panel" variants={fadeUp}>
        <div className="ph"><div className="ptitle">Data plane</div>
          <span className="td3" style={{ fontSize: 12.5 }}>{data?.dataplane?.reachable ? `version ${data.dataplane.version} · up ${Math.round((data.dataplane.uptime_secs ?? 0)/3600)}h` : data?.dataplane ? "unreachable" : ""}</span></div>
        <div className="tw">
          {!data?.dataplane ? <div style={{ padding: 18 }} className="td3">…</div>
          : !data.dataplane.reachable ? <div className="code-block" style={{ margin: 12, borderLeft: "3px solid var(--red-b)" }}><span style={{ color: "var(--red-b)" }}>● DATA PLANE UNREACHABLE</span> — {data.dataplane.error}</div>
          : (
            <table>
              <thead><tr><th>Job</th><th>State</th><th>Detail</th></tr></thead>
              <tbody>
                <tr>
                  <td><div style={{ fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--cyan)" }}>threat-intel.poll</div><div className="td3" style={{ fontSize: 12.5, whiteSpace: "normal", maxWidth: 420, lineHeight: 1.45 }}>Pull the indicator corpus from the control plane and swap it into the enforcement path.</div></td>
                  <td>{ti ? <span className={`bdg ${ti.active ? "bgg" : "ba"}`}>{ti.poller}</span> : <span className="td3">—</span>}</td>
                  <td className="td3" style={{ whiteSpace: "normal" }}>{ti ? `${ti.entries.toLocaleString()} indicators enforced · last sync HTTP ${ti.last_sync_status} · corpus version ${ti.version}${ti.inert_reason ? ` · ${ti.inert_reason}` : ""}` : "not reported"}</td>
                </tr>
                <tr>
                  <td><div style={{ fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--cyan)" }}>config.sync</div><div className="td3" style={{ fontSize: 12.5, whiteSpace: "normal", maxWidth: 420, lineHeight: 1.45 }}>Poll the control plane for site configuration and hot-reload the rule engines.</div></td>
                  <td><span className="bdg bgg">running</span></td>
                  <td className="td3" style={{ whiteSpace: "normal" }}>See each site&apos;s Effective Config tab for what this node holds.</td>
                </tr>
              </tbody>
            </table>
          )}
        </div>
      </motion.div>
    </motion.div>
  );
}
