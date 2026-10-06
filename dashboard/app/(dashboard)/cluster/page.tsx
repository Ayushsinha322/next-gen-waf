"use client";
/**
 * Cluster & Node Health — a fleet-wide operational view of the whole
 * deployment: the data-plane WAF fleet, control-plane membership, and a
 * live topology map showing traffic flow from clients through the load balancer
 * and WAF nodes to the origins. Everything degrades silently to placeholders
 * when the control plane is unreachable.
 */
import { useState, useEffect, Fragment } from "react";
import Icon, { type IconName } from "@/components/ui/Icon";
import { motion } from "framer-motion";
import { api, type ClusterHealth, type NotificationChannel } from "@/lib/api";
import { staggerContainer, cardVariants, fadeUp, spring } from "@/lib/animations";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function overallColor(o?: string): string {
  return o === "healthy" ? "var(--green)" : o === "degraded" ? "var(--amber)" : o === "critical" ? "var(--red)" : "var(--text3)";
}
function statusDot(s?: string): "g" | "a" | "r" {
  return s === "healthy" ? "g" : s === "degraded" ? "a" : "r";
}
function statusBadge(s?: string): "bgg" | "ba" | "br" {
  return s === "healthy" ? "bgg" : s === "degraded" ? "ba" : "br";
}
function fmtAgoSec(s: number): string {
  if (s == null || s < 0) return "—";
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
function fmtUptime(secs: number): string {
  if (!secs || secs < 60) return `${Math.max(0, Math.floor(secs || 0))}s`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m`;
  const hrs = Math.floor(mins / 60), rm = mins % 60;
  if (hrs < 24) return rm > 0 ? `${hrs}h ${rm}m` : `${hrs}h`;
  const days = Math.floor(hrs / 24), rh = hrs % 24;
  return rh > 0 ? `${days}d ${rh}h` : `${days}d`;
}
const ORB = "var(--font-display)";
const MONO = "var(--font-mono)";

// ---------------------------------------------------------------------------
// Big status KPI figure (Orbitron numbers on a glass card)
// ---------------------------------------------------------------------------
function StatFigure({ label, value, sub, accent, accentCls }: { label: string; value: React.ReactNode; sub?: React.ReactNode; accent?: string; accentCls?: string }) {
  return (
    <motion.div className={`kpi ${accentCls ?? ""}`} variants={cardVariants}>
      <div className="kpi-lbl">{label}</div>
      <div className="kpi-val" style={{ color: accent ?? "var(--text)", fontFamily: ORB }}>{value}</div>
      {sub != null && <div className="kpi-delta">{sub}</div>}
    </motion.div>
  );
}

// ---------------------------------------------------------------------------
// Topology stage box (Clients / Load balancer / Origins) + connector
// ---------------------------------------------------------------------------
function StageBox({ icon, title, sub, tone }: { icon: IconName; title: string; sub?: string; tone?: string }) {
  return (
    <div style={{
      display: "flex", flexDirection: "column", alignItems: "center", gap: 6,
      padding: "16px 18px", borderRadius: "var(--r)", minWidth: 108,
      background: "var(--glass-w)", border: `1px solid ${tone ?? "var(--border)"}`,
    }}>
      <Icon name={icon} size={22} style={{ color: "var(--text2)" }} />
      <div style={{ fontSize: 13, fontWeight: 700, color: "var(--text)", fontFamily: "var(--font-sans)", textAlign: "center" }}>{title}</div>
      {sub && <div style={{ fontSize: 12, color: "var(--text3)", fontFamily: MONO }}>{sub}</div>}
    </div>
  );
}

function Connector({ color }: { color?: string }) {
  return (
    <div style={{ flex: "0 0 auto", display: "flex", alignItems: "center", minWidth: 34 }} aria-hidden>
      <div style={{ height: 2, flex: 1, background: `linear-gradient(90deg, ${color ?? "var(--cyan-ring)"}, ${color ?? "var(--cyan)"})`, borderRadius: 2 }} />
      <span style={{ color: color ?? "var(--cyan)", fontSize: 13, marginLeft: -2 }}>▸</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Cluster health page
// ---------------------------------------------------------------------------
export default function ClusterPage() {
  const [health, setHealth] = useState<ClusterHealth | null>(null);
  const [openNode, setOpenNode] = useState<string | null>(null);
  const [channels, setChannels] = useState<NotificationChannel[] | null>(null);

  // ── Cluster health (10s poll) — same silent-degrade pattern as overview ──
  useEffect(() => {
    let cancelled = false;
    async function f() {
      try { const r = await api.cluster.health(); if (!cancelled) setHealth(r); }
      catch { /* control plane may be down — keep last-known / placeholder */ }
    }
    f(); const t = setInterval(f, 10_000); return () => { cancelled = true; clearInterval(t); };
  }, []);

  // ── Notification channels (lightweight, non-blocking) ──
  useEffect(() => {
    let cancelled = false;
    async function f() {
      try { const r = await api.notifications.list(); if (!cancelled) setChannels(r.channels ?? []); }
      catch { if (!cancelled) setChannels(null); }
    }
    f(); const t = setInterval(f, 60_000); return () => { cancelled = true; clearInterval(t); };
  }, []);

  const dp = health?.data_plane;
  const cp = health?.control_plane;
  const dpNodes = dp?.nodes ?? [];
  const cpNodes = cp?.nodes ?? [];

  // Version drift across healthy nodes.
  const healthyVersions = Array.from(new Set(dpNodes.filter(n => n.status === "healthy").map(n => n.version)));
  const versionDrift = healthyVersions.length > 1;

  // Enabled alert channels.
  const enabledChannels = (channels ?? []).filter(c => c.enabled);

  return (
    <motion.div className="sec" variants={staggerContainer} initial="hidden" animate="visible">

      {/* ── Header ── */}
      <motion.div variants={fadeUp} style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 14 }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          <div className="sec-title">Cluster &amp; Node Health</div>
          <div className="sec-sub">
Fleet-wide health of the WAF data plane and control plane — live topology, failover budget, and node status
          </div>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexShrink: 0 }}>
          {health && <span className="panel-badge pb-live">● Live</span>}
          <motion.button className="btn bg-btn btn-sm" whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}
            onClick={() => api.cluster.health().then(setHealth).catch(() => {})}>⟳ Refresh</motion.button>
        </div>
      </motion.div>

      {/* ── (a) HEALTH HEADER BAND ── */}
      <motion.div variants={fadeUp} className="panel">
        <div className="pb" style={{ display: "flex", alignItems: "center", gap: 18, flexWrap: "wrap" }}>
          {/* Overall pill */}
          <div style={{
            display: "flex", flexDirection: "column", gap: 8, paddingRight: 18,
            borderRight: "1px solid var(--bg4)", minWidth: 220,
          }}>
            <div style={{
              display: "inline-flex", alignItems: "center", gap: 10, alignSelf: "flex-start",
              padding: "8px 18px", borderRadius: 24, fontFamily: ORB, fontWeight: 700, fontSize: 22, letterSpacing: 1,
              color: overallColor(health?.overall),
              background: `color-mix(in srgb, ${overallColor(health?.overall)} 14%, transparent)`,
              border: `1px solid color-mix(in srgb, ${overallColor(health?.overall)} 40%, transparent)`,
            }}>
              <span className={`sd ${statusDot(health?.overall === "critical" ? "down" : health?.overall === "degraded" ? "degraded" : health?.overall === "healthy" ? "healthy" : undefined)}`} />
              {health ? health.overall.toUpperCase() : "—"}
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 14, fontFamily: MONO, color: health?.protection_active ? "var(--green)" : "var(--red)" }}>
              <span className={`sd ${health?.protection_active ? "g" : "r"}`} />
              Protection: {health ? (health.protection_active ? "ACTIVE" : "AT RISK") : "—"}
            </div>
            {/* A fleet is most often degraded because the APPLICATION behind it is
                unreachable, not because the WAF is unwell — inspection carries on
                either way. Say which it is here, rather than leaving the operator
                to open a node to find out. */}
            {/* A node that rejects config keeps enforcing its previous one, so
                every change saved since is not in force there. Said here, in
                the headline, because the per-node badge alone went unnoticed
                while the whole fleet was frozen. */}
            {dp && (dp.rejecting_config ?? 0) > 0 && (
              <div style={{ display: "flex", alignItems: "flex-start", gap: 8, fontSize: 13, fontFamily: MONO, color: "var(--red-b)" }}>
                <span className="sd r" style={{ marginTop: 5 }} />
                <span>
                  {dp.rejecting_config} node{dp.rejecting_config === 1 ? " is" : "s are"} not taking configuration — changes saved here are not in force there.{" "}
                  {dp.nodes.find(n => n.config_rejecting)?.config_sync_problem}
                </span>
              </div>
            )}
            {dp && dp.upstreams_total > 0 && dp.upstreams_healthy < dp.upstreams_total && (
              <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, fontFamily: MONO, color: "var(--amber)" }}>
                <span className="sd a" />
                {dp.upstreams_healthy} of {dp.upstreams_total} origin{dp.upstreams_total === 1 ? "" : "s"} reachable — traffic is inspected, the application is not answering
              </div>
            )}
          </div>

          {/* KPI figures */}
          <div style={{ flex: 1, display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 12, minWidth: 320 }}>
            <StatFigure
              accentCls="kg" accent="var(--green)"
              label="Data plane"
              value={dp ? `${dp.healthy}/${dp.total}` : "—"}
              sub={dp ? `${dp.healthy} healthy · ${dp.degraded} degraded · ${dp.down} down${dp.stale ? ` · ${dp.stale} stale (not counted)` : ""}` : "waiting…"} />
            <StatFigure
              accentCls={cp?.enabled ? (cp?.write_available ? "kc" : "ka") : "kp"}
              accent={cp?.enabled ? (cp?.write_available ? "var(--cyan)" : "var(--red)") : "var(--text3)"}
              label="Control plane"
              value={cp?.enabled ? `${cp.healthy}/${cp.total}` : (cp ? "N/A" : "—")}
              sub={cp?.enabled ? (cp.write_available ? "writes available" : "NO WRITE LEADER") : "standalone"} />
            <StatFigure
              accentCls="ka" accent="var(--amber)"
              label="Resilience budget"
              value={dp ? dp.resilience_budget : "—"}
              sub={dp ? `survives ${dp.resilience_budget} more node ${dp.resilience_budget === 1 ? "failure" : "failures"}` : "waiting…"} />
          </div>
        </div>
      </motion.div>

      {/* ── (b) LIVE TOPOLOGY MAP — the centerpiece ── */}
      <motion.div variants={fadeUp} className="panel">
        <div className="ph">
          <div className="ptitle">Live Topology</div>
          <span className="panel-badge pb-cyan">Client → LB → WAF fleet → Origins</span>
        </div>
        <div className="pb" style={{ overflowX: "auto" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 4, minWidth: 620, padding: "8px 4px" }}>
            <StageBox icon="users" title="Clients" sub="internet" />
            <Connector color="var(--cyan)" />
            <StageBox icon="scale" title="Load Balancer" sub={dp ? `${dp.healthy} up` : undefined} tone="var(--cyan-ring)" />
            <Connector color={dp && dp.healthy > 0 ? "var(--green)" : "var(--red)"} />

            {/* WAF fleet — one chip per data-plane node */}
            <div style={{
              display: "flex", flexDirection: "column", gap: 8, padding: "14px 14px", borderRadius: "var(--r)",
              background: "var(--cyan-dim)", border: "1px dashed var(--cyan-ring)", minWidth: 150,
            }}>
              <div style={{ fontSize: 12, fontFamily: MONO, color: "var(--text3)", textTransform: "uppercase", letterSpacing: 1, textAlign: "center" }}>WAF Fleet</div>
              {dpNodes.length === 0 ? (
                <div style={{ fontSize: 13, fontFamily: MONO, color: "var(--text3)", textAlign: "center", padding: "8px 0" }}>—</div>
              ) : dpNodes.map(n => {
                const down = n.status === "down";
                // A stale node is a former container id, not a member of the fleet —
                // shown dimmed so the operator can see it, never red.
                const stale = n.status === "stale";
                return (
                  <div key={n.id} title={`${n.hostname} · ${n.status}${stale ? " (not heard from in over a day)" : ""} · ${n.version}`} style={{
                    opacity: stale ? 0.45 : 1,
                    display: "flex", alignItems: "center", gap: 8, padding: "7px 11px", borderRadius: 8,
                    background: down ? "color-mix(in srgb, var(--red) 12%, transparent)" : "var(--glass-w)",
                    border: `1px solid ${down ? "color-mix(in srgb, var(--red) 45%, transparent)" : n.status === "degraded" ? "color-mix(in srgb, var(--amber) 40%, transparent)" : "var(--border)"}`,
                  }}>
                    <span className={`sd ${statusDot(n.status)}`} />
                    <span style={{ fontSize: 13, fontFamily: MONO, color: down ? "var(--red)" : "var(--text2)", fontWeight: 600, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{n.id}</span>
                  </div>
                );
              })}
            </div>

            <Connector color={dp && dp.healthy > 0 ? "var(--green)" : "var(--red)"} />
            <StageBox icon="database" title="Origins" sub="upstreams" tone="var(--border)" />
          </div>
        </div>
      </motion.div>

      {/* ── (c) CONTROL PLANE (leader election) + (e) NOTIFICATION READINESS ── */}
      <motion.div variants={fadeUp} style={{ display: "grid", gridTemplateColumns: "1.6fr 1fr", gap: 14 }}>

        {/* Control plane */}
        <div className="panel">
          <div className="ph">
            <div className="ptitle">Control Plane</div>
            {cp?.enabled
              ? <span className={`panel-badge ${cp.write_available ? "pb-cyan" : "pb-live"}`}>{cp.write_available ? `${cp.healthy}/${cp.total} online` : "NO WRITE LEADER"}</span>
              : <span className="panel-badge pb-info">standalone</span>}
          </div>
          <div className="pb">
            {!cp || !cp.enabled ? (
              <div style={{ padding: "22px 12px", textAlign: "center" }}>
                <Icon name="puzzle" size={28} style={{ marginBottom: 8, color: "var(--text3)" }} />
                <div style={{ fontSize: 15, fontWeight: 700, color: "var(--text2)", marginBottom: 6 }}>Standalone (HA not enabled)</div>
                <div style={{ fontSize: 14, color: "var(--text3)", fontFamily: MONO, lineHeight: 1.6, maxWidth: 440, margin: "0 auto" }}>
                  Running a single control-plane node. Add replicas for spare capacity — write leadership
                  fails over automatically via a Postgres advisory lock, with no quorum to maintain.
                </div>
              </div>
            ) : (
              <>
                {/* Write availability. There is deliberately no quorum meter:
                    leadership is a Postgres advisory lock, so a single surviving
                    node still serves writes and a control-plane majority is not
                    required. Showing a quorum bar would imply a constraint that
                    does not exist. */}
                <div style={{ marginBottom: 14 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13, fontFamily: MONO, marginBottom: 6 }}>
                    <span style={{ color: "var(--text3)" }}>
                      Nodes online{cp.leader_id ? ` · leader ${cp.leader_id}` : ""}
                    </span>
                    <span style={{ color: cp.write_available ? "var(--green)" : "var(--red)", fontWeight: 700 }}>
                      {cp.healthy}/{cp.total} — {cp.write_available ? "WRITES AVAILABLE" : "NO WRITE LEADER"}
                    </span>
                  </div>
                  <div style={{ display: "flex", gap: 4 }}>
                    {Array.from({ length: cp.total }).map((_, i) => (
                      <div key={i} style={{
                        flex: 1, height: 8, borderRadius: 3,
                        background: i < cp.healthy ? (cp.write_available ? "var(--green)" : "var(--amber)") : "var(--bg4)",
                      }} />
                    ))}
                  </div>
                </div>

                {/* Nodes */}
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  {cpNodes.length === 0 ? (
                    <div style={{ fontSize: 13, fontFamily: MONO, color: "var(--text3)" }}>—</div>
                  ) : cpNodes.map(n => (
                    <div key={n.node_id} style={{
                      display: "flex", alignItems: "center", gap: 10, padding: "10px 12px", borderRadius: 8,
                      background: "var(--glass-w)", border: `1px solid ${n.is_leader ? "var(--cyan-ring)" : "var(--border)"}`,
                    }}>
                      <span className={`sd ${n.reachable ? "g" : "r"}`} />
                      <span style={{ fontSize: 14, fontFamily: MONO, color: "var(--text)", fontWeight: 600 }}>node {n.node_id}</span>
                      {n.is_leader
                        ? <span className="bdg bcy">LEADER</span>
                        : <span className="bdg bgr">{n.role}</span>}
                      {n.is_self && <span className="bdg bgr">this node</span>}
                      <span style={{ marginLeft: "auto", fontSize: 13, fontFamily: MONO, color: n.reachable ? "var(--text3)" : "var(--red)" }}>
                        {n.reachable ? fmtAgoSec(n.last_seen_sec) : "unreachable"}
                      </span>
                    </div>
                  ))}
                </div>

                <div style={{ marginTop: 14, fontSize: 13, fontFamily: MONO, color: "var(--text3)", display: "flex", gap: 8, alignItems: "center" }}>
                  <span style={{ color: "var(--cyan)" }}>ℹ</span>
                  If the leader fails, a follower is elected in under a second.
                </div>
              </>
            )}
          </div>
        </div>

        {/* Notification readiness */}
        <div className="panel">
          <div className="ph">
            <div className="ptitle">Alerting</div>
            {channels != null && <span className={`panel-badge ${enabledChannels.length > 0 ? "pb-cyan" : "pb-info"}`}>{enabledChannels.length} active</span>}
          </div>
          <div className="pb">
            {channels == null ? (
              <div style={{ fontSize: 14, color: "var(--text3)", fontFamily: MONO, lineHeight: 1.7 }}>
                Configure alert channels in Settings to be paged on node failures.
              </div>
            ) : enabledChannels.length === 0 ? (
              <div style={{ textAlign: "center", padding: "12px 4px" }}>
                <Icon name="bell-off" size={26} style={{ marginBottom: 8, color: "var(--text3)" }} />
                <div style={{ fontSize: 14, fontWeight: 700, color: "var(--text2)", marginBottom: 6 }}>No alert channels active</div>
                <div style={{ fontSize: 13, color: "var(--text3)", fontFamily: MONO, lineHeight: 1.6 }}>
                  Configure alert channels in Settings to be paged on node failures.
                </div>
              </div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                <div style={{ fontSize: 13, color: "var(--text3)", fontFamily: MONO, marginBottom: 2 }}>
                  You will be paged on node failures via:
                </div>
                {enabledChannels.slice(0, 6).map(c => (
                  <div key={c.id} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span className="sd g" />
                    <span style={{ fontSize: 14, fontFamily: MONO, color: "var(--text2)" }}>{c.name}</span>
                    <span className="bdg bgr" style={{ marginLeft: "auto" }}>{c.type}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </motion.div>

      {/* ── (d) DATA PLANE FLEET PANEL ── */}
      <motion.div variants={fadeUp} className="panel">
        <div className="ph">
          <div className="ptitle">Data Plane · WAF Fleet</div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            {versionDrift && <span className="bdg ba">⚠ version drift</span>}
            <span className="panel-badge pb-info">{dp ? `${dp.total} node${dp.total === 1 ? "" : "s"}` : "—"}</span>
          </div>
        </div>
        <div className="tw">
          {dpNodes.length === 0 ? (
            <div style={{ padding: "22px 12px", textAlign: "center", fontSize: 13, color: "var(--text3)", fontFamily: MONO }}>
              {health ? "No data-plane nodes reporting." : "Waiting for data plane…"}
            </div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th></th><th>Node</th><th>Status</th><th>Version</th><th>Config</th><th>Uptime</th>
                  <th>Sites</th><th>Rules</th><th>Upstreams</th><th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {dpNodes.map(n => {
                  const upDown = n.upstreams_total > 0 && n.upstreams_healthy < n.upstreams_total;
                  const cur = health?.config_version ?? 0;
                  const applied = n.config_version_applied ?? 0;
                  const stale = cur > 0 && applied > 0 && applied < cur;
                  const neverSynced = cur > 0 && applied === 0 && n.status !== "down";
                  const open = openNode === n.id;
                  return (
                    <Fragment key={n.id}>
                    <tr className={n.status === "down" ? "sev-c" : ""} onClick={() => setOpenNode(open ? null : n.id)} style={{ cursor: "pointer", opacity: n.status === "stale" ? 0.5 : 1 }}>
                      <td className="td3" style={{ width: 18 }}>{open ? "▾" : "▸"}</td>
                      <td className="td2">
                        <div style={{ display: "flex", flexDirection: "column" }}>
                          <span style={{ color: "var(--text)", fontWeight: 600 }}>{n.hostname || n.id}</span>
                          <span className="td3" style={{ fontSize: 12 }}>{n.id} · {n.role}</span>
                        </div>
                      </td>
                      <td>
                        <span className={`bdg ${statusBadge(n.status)}`}>
                          <span className={`sd ${statusDot(n.status)}`} />{n.status.toUpperCase()}
                        </span>
                      </td>
                      <td className="td3">{n.version || "—"}</td>
                      <td>
                        {n.config_rejecting ? <span className="bdg br" title={n.config_sync_problem}>REJECTING · v{applied}</span>
                          : applied === 0 && !neverSynced ? <span className="td3">—</span>
                          : stale ? <span className="bdg ba" title={`Node applied config version ${applied}; the control plane serves ${cur}. Changes made since have not reached this node.`}>STALE · v{applied}</span>
                          : neverSynced ? <span className="bdg br" title="This node has never applied a configuration from the control plane">NEVER SYNCED</span>
                          : <span className="bdg bgg" title={`Config version ${applied}, current`}>v{applied}</span>}
                      </td>
                      <td className="td3">{fmtUptime(n.uptime_secs)}</td>
                      <td className="td3">{n.sites}</td>
                      <td className="td3" style={{ fontVariantNumeric: "tabular-nums" }}>{n.rules_compiled ? `${n.rules_enforced ?? n.rules_compiled}/${n.rules_compiled}` : "—"}</td>
                      <td className={upDown ? "" : "td3"} style={{ color: upDown ? "var(--amber)" : undefined }}>
                        {n.upstreams_healthy}/{n.upstreams_total}
                      </td>
                      <td className="td3">{fmtAgoSec(n.seconds_since_seen)}</td>
                    </tr>
                    {open && (
                      <tr>
                        <td colSpan={10} style={{ background: "rgba(255,255,255,.015)", padding: "12px 18px" }}>
                          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))", gap: 12 }}>
                            {([
                              ["Listeners", (n.listeners && n.listeners.length) ? n.listeners.join("  ") : "not reported"],
                              ["HTTP/3", n.http3_enabled === undefined ? "not reported" : n.http3_enabled ? "enabled" : "off"],
                              ["Config version applied", applied ? `v${applied}${stale ? ` — control plane is at v${cur}` : " (current)"}` : "never synced"],
                              ["Compiled rules", n.rules_compiled ? `${n.rules_enforced} enforcing of ${n.rules_compiled}` : "not reported"],
                              ["eBPF / XDP", n.ebpf_mode ? `${n.ebpf_mode} · ${(n.ebpf_drops ?? 0).toLocaleString()} drops` : "not reported"],
                              ["Threat intel", n.threat_intel_entries !== undefined ? `${n.threat_intel_entries.toLocaleString()} indicators · corpus v${n.threat_intel_version ?? 0}${n.threat_intel_problem ? ` · ${n.threat_intel_problem}` : ""}` : "not reported"],
                              ["Upstreams", `${n.upstreams_healthy} healthy of ${n.upstreams_total}`],
                              ["Last heartbeat", `${fmtAgoSec(n.seconds_since_seen)} · uptime ${fmtUptime(n.uptime_secs)}`],
                            ] as [string, string][]).map(([k, v]) => (
                              <div key={k} style={{ border: "1px solid var(--border)", borderRadius: 6, padding: "8px 10px" }}>
                                <div className="td3" style={{ fontSize: 11, letterSpacing: ".04em", textTransform: "uppercase" }}>{k}</div>
                                <div style={{ fontFamily: MONO, fontSize: 12.5, marginTop: 3, wordBreak: "break-word" }}>{v}</div>
                              </div>
                            ))}
                          </div>
                          {stale && <div style={{ marginTop: 10, fontSize: 12.5, color: "var(--amber)", fontFamily: MONO }}>⚠ This node is enforcing an older configuration than the control plane holds. It polls every few seconds; if this persists, check the node&apos;s config-sync log.</div>}
                        </td>
                      </tr>
                    )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
        {versionDrift && (
          <div style={{ padding: "0 18px 14px", fontSize: 13, fontFamily: MONO, color: "var(--amber)" }}>
            ⚠ Healthy nodes are running mixed versions ({healthyVersions.join(", ")}). Roll the fleet to a single version.
          </div>
        )}
      </motion.div>

    </motion.div>
  );
}
