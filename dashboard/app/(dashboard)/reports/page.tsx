"use client";
import { useCallback, useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import { api, type ReportSchedule, type ReportScheduleInput, type NotificationChannel, type Site } from "@/lib/api";
import { showToast } from "@/components/ui/Toast";
import EmptyState from "@/components/ui/EmptyState";
import { staggerContainer, fadeUp, cardVariants } from "@/lib/animations";
import Icon from "@/components/ui/Icon";

/**
 * Scheduled security reports.
 *
 * The customer deck claimed these in August 2026 and source checks disproved it:
 * everything a report needs was in ClickHouse and nothing produced one. A
 * schedule builds the last period for one site (or all), renders HTML or CSV,
 * and delivers to a webhook/Slack channel or a mailbox. "Build now" downloads
 * the same report on demand without any schedule at all, so an operator can see
 * exactly what would be sent before committing to a cadence.
 *
 * PDF is not offered: the HTML prints to PDF from any browser, and a PDF
 * renderer would be the largest dependency in the control-plane binary. Saying
 * so here is better than a disabled "PDF" radio nobody can explain.
 */

const DAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

function emptyInput(): ReportScheduleInput {
  return { name: "", site: "", cadence: "weekly", day_of_week: 1, hour_utc: 6, format: "html", channel_id: null, recipients: [], enabled: true };
}

function describe(s: ReportSchedule): string {
  const when = s.cadence === "daily" ? `every day at ${String(s.hour_utc).padStart(2, "0")}:00 UTC`
    : `every ${DAYS[s.day_of_week] ?? "Monday"} at ${String(s.hour_utc).padStart(2, "0")}:00 UTC`;
  return `${s.cadence === "daily" ? "Previous day" : "Previous 7 days"} · ${when}`;
}

export default function ReportsPage() {
  const [schedules, setSchedules] = useState<ReportSchedule[] | null>(null);
  const [channels, setChannels] = useState<NotificationChannel[]>([]);
  const [sites, setSites] = useState<Site[]>([]);
  const [mailConfigured, setMailConfigured] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [editing, setEditing] = useState<{ id: string | null; input: ReportScheduleInput } | null>(null);
  const [problems, setProblems] = useState<string[]>([]);
  // On-demand build
  const [pvSite, setPvSite] = useState("");
  const [pvDays, setPvDays] = useState(7);
  const [pvBusy, setPvBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const r = await api.reports.list();
      setSchedules(r.schedules);
      setMailConfigured(r.mail_configured);
      setError(null);
    } catch (e) {
      setSchedules([]);
      setError(e instanceof Error ? e.message : "could not load schedules");
    }
  }, []);

  useEffect(() => {
    void load();
    api.notifications.list().then(r => setChannels(r.channels ?? [])).catch(() => setChannels([]));
    api.sites.list().then(r => setSites(r.sites ?? [])).catch(() => setSites([]));
  }, [load]);

  const deliverable = useMemo(() => channels.filter(c => c.type === "webhook" || c.type === "slack"), [channels]);

  const save = useCallback(async () => {
    if (!editing) return;
    setBusy("save");
    setProblems([]);
    try {
      const r = editing.id
        ? await api.reports.update(editing.id, editing.input)
        : await api.reports.create(editing.input);
      showToast(`Schedule "${r.schedule.name}" saved`, "s");
      setEditing(null);
      await load();
    } catch (e) {
      const msg = e instanceof Error ? e.message : "save failed";
      // The API answers 400 with a problems[] list; surface each line.
      const m = msg.match(/\{.*\}$/);
      if (m) {
        try {
          const parsed = JSON.parse(m[0]) as { problems?: string[]; error?: string };
          setProblems(parsed.problems ?? [parsed.error ?? msg]);
        } catch { setProblems([msg]); }
      } else setProblems([msg]);
    } finally { setBusy(null); }
  }, [editing, load]);

  const runNow = useCallback(async (s: ReportSchedule) => {
    setBusy(s.id);
    try {
      const r = await api.reports.run(s.id);
      const ok = r.results.filter(x => x.ok).length;
      showToast(r.ok ? `Sent to ${ok}/${r.results.length} target(s)` : `Delivery failed: ${r.error ?? r.results.map(x => x.err).join("; ")}`,
        r.ok ? "s" : "e");
      await load();
    } catch (e) {
      showToast(e instanceof Error ? e.message : "run failed", "e");
    } finally { setBusy(null); }
  }, [load]);

  const remove = useCallback(async (s: ReportSchedule) => {
    if (!window.confirm(`Delete the schedule "${s.name}"? Reports already delivered are unaffected.`)) return;
    setBusy(s.id);
    try {
      await api.reports.remove(s.id);
      showToast("Schedule deleted", "s");
      await load();
    } catch (e) {
      showToast(e instanceof Error ? e.message : "delete failed", "e");
    } finally { setBusy(null); }
  }, [load]);

  const buildNow = useCallback(async (format: "open" | "html" | "csv") => {
    setPvBusy(true);
    try {
      if (format === "open") await api.reports.open({ site: pvSite, days: pvDays });
      else await api.reports.download({ site: pvSite, days: pvDays, format });
    } catch (e) {
      showToast(e instanceof Error ? e.message : "report failed", "e");
    } finally { setPvBusy(false); }
  }, [pvSite, pvDays]);

  const input = editing?.input;
  const upd = (patch: Partial<ReportScheduleInput>) => editing && setEditing({ ...editing, input: { ...editing.input, ...patch } });

  return (
    <motion.div className="sec" variants={staggerContainer} initial="hidden" animate="visible">
      <motion.div variants={fadeUp} style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 14, flexWrap: "wrap" }}>
        <div>
          <div className="sec-title">Reports</div>
          <div className="sec-sub">Scheduled security summaries per site · built from the event store · delivered to a channel or mailbox</div>
        </div>
        <button className="btn bp btn-sm" onClick={() => { setProblems([]); setEditing({ id: null, input: emptyInput() }); }}>＋ New schedule</button>
      </motion.div>

      {/* Build now — the same renderer the schedule uses, on demand. */}
      <motion.div variants={cardVariants} className="panel">
        <div className="ph"><div className="ptitle">Build one now</div></div>
        <div className="pb" style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "flex-end" }}>
          <div style={{ display: "grid", gap: 4 }}>
            <label style={{ fontSize: 12, color: "var(--text3)", fontFamily: "var(--font-mono)" }}>Site</label>
            <select className="fsel" value={pvSite} onChange={e => setPvSite(e.target.value)} style={{ minWidth: 200 }}>
              <option value="">All sites</option>
              {sites.map(s => <option key={s.id} value={s.name}>{s.name}</option>)}
            </select>
          </div>
          <div style={{ display: "grid", gap: 4 }}>
            <label style={{ fontSize: 12, color: "var(--text3)", fontFamily: "var(--font-mono)" }}>Period</label>
            <select className="fsel" value={pvDays} onChange={e => setPvDays(Number(e.target.value))}>
              {[1, 7, 14, 30, 90].map(d => <option key={d} value={d}>Last {d} day{d === 1 ? "" : "s"}</option>)}
            </select>
          </div>
          <button className="btn bc btn-sm" disabled={pvBusy} onClick={() => void buildNow("open")}>{pvBusy ? "Building…" : "View"}</button>
          <button className="btn bg-btn btn-sm" disabled={pvBusy} onClick={() => void buildNow("html")}>HTML</button>
          <button className="btn bg-btn btn-sm" disabled={pvBusy} onClick={() => void buildNow("csv")}>CSV</button>
          <div style={{ fontSize: 12, color: "var(--text3)", flexBasis: "100%", lineHeight: 1.5 }}>
            Events by decision, per-day trend, attack categories, top rules, top sources and countries, and the
            learning-mode false-positive candidates. The HTML version prints to PDF from your browser.
          </div>
        </div>
      </motion.div>

      {editing && (
        <motion.div variants={cardVariants} className="panel">
          <div className="ph"><div className="ptitle">{editing.id ? "Edit schedule" : "New schedule"}</div></div>
          <div className="pb" style={{ display: "grid", gap: 12 }}>
            {problems.length > 0 && (
              <div style={{ border: "1px solid var(--red-b)", borderRadius: 8, padding: 10, fontSize: 13, color: "var(--red-b)" }}>
                {problems.map((p, i) => <div key={i}>• {p}</div>)}
              </div>
            )}
            <div style={{ display: "grid", gap: 10, gridTemplateColumns: "repeat(auto-fit,minmax(220px,1fr))" }}>
              <div style={{ display: "grid", gap: 4 }}>
                <label style={{ fontSize: 12, color: "var(--text3)" }}>Name</label>
                <input className="fin" value={input!.name} onChange={e => upd({ name: e.target.value })} placeholder="Weekly summary — Juice Shop" />
              </div>
              <div style={{ display: "grid", gap: 4 }}>
                <label style={{ fontSize: 12, color: "var(--text3)" }}>Site</label>
                <select className="fsel" value={input!.site} onChange={e => upd({ site: e.target.value })}>
                  <option value="">All sites</option>
                  {sites.map(s => <option key={s.id} value={s.name}>{s.name}</option>)}
                </select>
              </div>
              <div style={{ display: "grid", gap: 4 }}>
                <label style={{ fontSize: 12, color: "var(--text3)" }}>Cadence</label>
                <select className="fsel" value={input!.cadence} onChange={e => upd({ cadence: e.target.value as "daily" | "weekly" })}>
                  <option value="weekly">Weekly (previous 7 days)</option>
                  <option value="daily">Daily (previous day)</option>
                </select>
              </div>
              {input!.cadence === "weekly" && (
                <div style={{ display: "grid", gap: 4 }}>
                  <label style={{ fontSize: 12, color: "var(--text3)" }}>Day</label>
                  <select className="fsel" value={input!.day_of_week} onChange={e => upd({ day_of_week: Number(e.target.value) })}>
                    {DAYS.map((d, i) => <option key={d} value={i}>{d}</option>)}
                  </select>
                </div>
              )}
              <div style={{ display: "grid", gap: 4 }}>
                <label style={{ fontSize: 12, color: "var(--text3)" }}>Hour (UTC)</label>
                <select className="fsel" value={input!.hour_utc} onChange={e => upd({ hour_utc: Number(e.target.value) })}>
                  {Array.from({ length: 24 }, (_, h) => <option key={h} value={h}>{String(h).padStart(2, "0")}:00</option>)}
                </select>
              </div>
              <div style={{ display: "grid", gap: 4 }}>
                <label style={{ fontSize: 12, color: "var(--text3)" }}>Format</label>
                <select className="fsel" value={input!.format} onChange={e => upd({ format: e.target.value as "html" | "csv" })}>
                  <option value="html">HTML (prints to PDF)</option>
                  <option value="csv">CSV (spreadsheet)</option>
                </select>
              </div>
              <div style={{ display: "grid", gap: 4 }}>
                <label style={{ fontSize: 12, color: "var(--text3)" }}>Channel</label>
                <select className="fsel" value={input!.channel_id ?? ""} onChange={e => upd({ channel_id: e.target.value || null })}>
                  <option value="">None</option>
                  {deliverable.map(c => <option key={c.id} value={c.id}>{c.name} ({c.type})</option>)}
                </select>
              </div>
              <div style={{ display: "grid", gap: 4 }}>
                <label style={{ fontSize: 12, color: "var(--text3)" }}>Recipients (e-mail, comma separated)</label>
                <input className="fin" value={input!.recipients.join(", ")} placeholder="soc@example.com"
                  onChange={e => upd({ recipients: e.target.value.split(",").map(x => x.trim()).filter(Boolean) })} />
              </div>
            </div>
            {deliverable.length === 0 && channels.length > 0 && (
              <div style={{ fontSize: 12, color: "var(--amber)" }}>
                None of your notification channels is a webhook or Slack sink — syslog and CEF carry alerts, not reports. Use e-mail recipients, or add a webhook channel.
              </div>
            )}
            {!mailConfigured && input!.recipients.length > 0 && (
              <div style={{ fontSize: 12, color: "var(--amber)" }}>
                SMTP is not configured, so e-mail delivery will fail. Set it up in Settings → Notifications, or deliver to a channel instead.
              </div>
            )}
            <label style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 13 }}>
              <input type="checkbox" checked={input!.enabled} onChange={e => upd({ enabled: e.target.checked })} />
              Enabled — send on the schedule above
            </label>
            <div style={{ display: "flex", gap: 8 }}>
              <button className="btn bp btn-sm" disabled={busy === "save"} onClick={() => void save()}>{busy === "save" ? "Saving…" : "Save schedule"}</button>
              <button className="btn bg-btn btn-sm" onClick={() => { setEditing(null); setProblems([]); }}>Cancel</button>
            </div>
          </div>
        </motion.div>
      )}

      <motion.div variants={cardVariants} className="panel">
        <div className="ph"><div className="ptitle">Schedules</div>
          {schedules && <span className="bdg bgr">{schedules.length}</span>}
        </div>
        <div className="pb" style={{ padding: 0 }}>
          {error && <div style={{ padding: 16, color: "var(--red-b)", fontSize: 13 }}>{error}</div>}
          {!error && schedules === null && <div style={{ padding: 24, textAlign: "center", color: "var(--text3)", fontFamily: "var(--font-mono)", fontSize: 13 }}>Loading…</div>}
          {!error && schedules?.length === 0 && (
            <EmptyState icon="file-text" title="No scheduled reports"
              hint="A schedule sends the same summary you can build above, on a cadence, to a webhook/Slack channel or a mailbox. Nothing is sent until you create one."
              action={{ label: "＋ New schedule", onClick: () => setEditing({ id: null, input: emptyInput() }) }} />
          )}
          {!error && schedules && schedules.length > 0 && (
            <table>
              <thead><tr><th>Name</th><th>Scope</th><th>Schedule</th><th>Delivery</th><th>Last run</th><th>Next</th><th>Actions</th></tr></thead>
              <tbody>
                {schedules.map(s => {
                  const targets = [
                    s.channel_id ? (channels.find(c => c.id === s.channel_id)?.name ?? "channel") : null,
                    s.recipients.length ? `${s.recipients.length} e-mail${s.recipients.length === 1 ? "" : "s"}` : null,
                  ].filter(Boolean).join(" · ");
                  const failed = (s.last_status ?? "").startsWith("failed") || (s.last_status ?? "").includes("0/");
                  return (
                    <tr key={s.id}>
                      <td>
                        <div style={{ color: "var(--cyan)", fontWeight: 600 }}>{s.name}</div>
                        <div className="td3" style={{ fontSize: 11 }}>{s.format.toUpperCase()}</div>
                      </td>
                      <td>{s.site || <span className="td3">all sites</span>}</td>
                      <td style={{ fontSize: 12 }}>{describe(s)}</td>
                      <td style={{ fontSize: 12 }}>{targets || <span className="td3">none configured</span>}</td>
                      <td style={{ fontSize: 12, maxWidth: 260 }}>
                        {s.last_run_at
                          ? <><div>{new Date(s.last_run_at).toLocaleString()}</div><div className="td3" style={{ color: failed ? "var(--red-b)" : undefined }}>{s.last_status}</div></>
                          : <span className="td3">never</span>}
                      </td>
                      <td style={{ fontSize: 12 }}>
                        {s.enabled ? <>{new Date(s.next_run_at).toLocaleString()}{s.due && <span className="bdg ba" style={{ marginLeft: 6 }}>DUE</span>}</> : <span className="bdg bgr">DISABLED</span>}
                      </td>
                      <td>
                        <div style={{ display: "flex", gap: 4 }}>
                          <button className="btn bc btn-xs" disabled={busy === s.id} title="Build the last period now and deliver it to the targets above" onClick={() => void runNow(s)}>
                            {busy === s.id ? "…" : "Send now"}
                          </button>
                          <button className="btn bg-btn btn-xs" onClick={() => { setProblems([]); setEditing({ id: s.id, input: { name: s.name, site: s.site, cadence: s.cadence, day_of_week: s.day_of_week, hour_utc: s.hour_utc, format: s.format, channel_id: s.channel_id, recipients: s.recipients, enabled: s.enabled } }); }}><Icon name="edit" size={13} title="Edit schedule" /></button>
                          <button className="btn bg-btn btn-xs" onClick={() => void remove(s)}><Icon name="trash" size={13} title="Delete schedule" /></button>
                        </div>
                      </td>
                    </tr>
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
