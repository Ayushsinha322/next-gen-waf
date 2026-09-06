"use client";
import { useState, useEffect } from "react";
import { usePathname, useRouter } from "next/navigation";
import { motion } from "framer-motion";
import { api, type ClusterHealth } from "@/lib/api";
import { navGroupStagger, navItemVariants, spring } from "@/lib/animations";

// ── Inline SVG icons ─────────────────────────────────────────────────────────
const Icon = {
  Overview: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/>
      <rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/>
    </svg>
  ),
  Traffic: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
    </svg>
  ),
  Alerts: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/>
    </svg>
  ),
  Logs: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>
    </svg>
  ),
  Search: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
    </svg>
  ),
  Sites: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/>
      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
    </svg>
  ),
  Rules: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  ),
  Plugins: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/>
      <line x1="7" y1="7" x2="7.01" y2="7"/>
    </svg>
  ),
  Copilot: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 2a10 10 0 1 0 10 10H12V2z"/><path d="M12 2a10 10 0 0 1 10 10"/>
      <circle cx="12" cy="12" r="3"/>
    </svg>
  ),
  ML: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M4.22 4.22l2.83 2.83M16.95 16.95l2.83 2.83M1 12h4M19 12h4M4.22 19.78l2.83-2.83M16.95 7.05l2.83-2.83"/>
    </svg>
  ),
  Certificates: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="4" width="18" height="12" rx="2"/><circle cx="9" cy="10" r="2.2"/>
      <path d="M9 12.2V20l-1.6-1.2L5.8 20v-7.8"/><line x1="14" y1="9" x2="18" y2="9"/><line x1="14" y1="12" x2="17" y2="12"/>
    </svg>
  ),
  Audit: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M9 11l3 3L22 4"/>
      <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>
    </svg>
  ),
  Settings: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="3"/>
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06-.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
    </svg>
  ),
  ThreatIntel: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="3.5"/>
      <line x1="12" y1="1.5" x2="12" y2="5"/><line x1="12" y1="19" x2="12" y2="22.5"/>
      <line x1="1.5" y1="12" x2="5" y2="12"/><line x1="19" y1="12" x2="22.5" y2="12"/>
    </svg>
  ),
  Cluster: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="4" r="2.4"/><circle cx="5" cy="19" r="2.4"/><circle cx="19" cy="19" r="2.4"/>
      <line x1="12" y1="6.4" x2="6.3" y2="16.8"/><line x1="12" y1="6.4" x2="17.7" y2="16.8"/><line x1="7.4" y1="19" x2="16.6" y2="19"/>
    </svg>
  ),
};

const NAV = [
  { group: "MONITOR", items: [
    { id: "overview", Icon: Icon.Overview, label: "Overview" },
    { id: "traffic",  Icon: Icon.Traffic,  label: "Traffic",  badge: "LIVE", badgeCls: "nb-g" },
    { id: "alerts",   Icon: Icon.Alerts,   label: "Alerts" },
    { id: "logs",     Icon: Icon.Logs,     label: "Logs",     badge: "LIVE", badgeCls: "nb-g" },
    { id: "events",   Icon: Icon.Search,   label: "Threat Search" },
  ]},
  { group: "PROTECT", items: [
    { id: "sites",   Icon: Icon.Sites,   label: "Sites" },
    { id: "rules",   Icon: Icon.Rules,   label: "Rules" },
    { id: "certificates", Icon: Icon.Certificates, label: "Certificates", badge: "TLS", badgeCls: "nb-g" },
    { id: "plugins", Icon: Icon.Plugins, label: "Plugins" },
  ]},
  { group: "INTELLIGENCE", items: [
    { id: "threat-intel", Icon: Icon.ThreatIntel, label: "Threat Intel", badge: "NEW", badgeCls: "nb-c" },
    { id: "copilot", Icon: Icon.Copilot, label: "AI Copilot", badge: "AI",   badgeCls: "nb-a", badgeStyle: { background: "rgba(124,58,237,.18)", color: "#a78bfa", borderColor: "rgba(124,58,237,.3)" } },
    { id: "ml",      Icon: Icon.ML,      label: "ML Engine",  badge: "LIVE", badgeCls: "nb-g" },
  ]},
  { group: "SYSTEM", items: [
    { id: "cluster",  Icon: Icon.Cluster,  label: "Cluster" },
    { id: "audit",    Icon: Icon.Audit,    label: "Audit Log" },
    { id: "global-settings", Icon: Icon.Settings, label: "Global Settings" },
    { id: "settings", Icon: Icon.Settings, label: "Settings" },
  ]},
];

type Counts = { sites: number | null; rules: number | null; plugins: number | null; alerts: number | null };

export default function SideBar() {
  const pathname = usePathname();
  const router   = useRouter();
  const current  = pathname.split("/").pop() || "overview";

  // Live nav counts + cluster footer — never hard-coded. Any endpoint that
  // fails leaves its value null so the badge is simply hidden rather than
  // showing a stale/fabricated number.
  const [counts, setCounts] = useState<Counts>({ sites: null, rules: null, plugins: null, alerts: null });
  const [health, setHealth] = useState<ClusterHealth | null>(null);
  const [healthErr, setHealthErr] = useState(false);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      const [sites, rules, plugins, alerts, inv] = await Promise.allSettled([
        api.sites.list(), api.rules.list(), api.plugins.list(), api.alerts.list(),
        api.rules.inventory({ summary: true }),
      ]);
      if (cancelled) return;
      // The Rules badge is the number of rules the data plane ENFORCES (compiled
      // CRS + custom + patches), not the size of the authored store. When the data
      // plane is unreachable fall back to the store count rather than showing 0.
      const enforced = inv.status === "fulfilled" && inv.value.dataplane_reachable
        ? inv.value.totals.enforced : null;
      setCounts({
        sites:   sites.status   === "fulfilled" ? (sites.value.sites?.length     ?? 0) : null,
        rules:   enforced ?? (rules.status === "fulfilled" ? (rules.value.rules?.length ?? 0) : null),
        plugins: plugins.status === "fulfilled" ? (plugins.value.plugins?.length ?? 0) : null,
        alerts:  alerts.status  === "fulfilled" ? (alerts.value.alerts?.filter(a => a.state === "open").length ?? 0) : null,
      });
    }
    load();
    const t = setInterval(load, 60_000);
    return () => { cancelled = true; clearInterval(t); };
  }, []);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try { const r = await api.cluster.health(); if (!cancelled) { setHealth(r); setHealthErr(false); } }
      catch { if (!cancelled) setHealthErr(true); }
    }
    load();
    const t = setInterval(load, 15_000);
    return () => { cancelled = true; clearInterval(t); };
  }, []);

  // Resolve the live badge for the four count-driven nav items.
  const liveBadge: Record<string, { value: string; cls: string }> = {};
  if (counts.sites   != null) liveBadge.sites   = { value: String(counts.sites),         cls: "nb-g" };
  if (counts.rules   != null) liveBadge.rules   = { value: counts.rules.toLocaleString(), cls: "nb-c" };
  if (counts.plugins != null) liveBadge.plugins = { value: String(counts.plugins),       cls: "nb-a" };
  if (counts.alerts  != null && counts.alerts > 0) liveBadge.alerts = { value: String(counts.alerts), cls: "nb-r" };

  // Cluster footer state.
  const cp = health?.control_plane;
  const dp = health?.data_plane;
  const versions = dp ? Array.from(new Set(dp.nodes.filter(n => n.status === "healthy").map(n => n.version).filter(Boolean))) : [];
  const fleetVersion = versions.length === 1 ? versions[0] : null;

  let footTitle: string, footSub: string, footDot: string;
  if (!health) {
    footTitle = "Cluster";
    footSub   = healthErr ? "control plane unreachable" : "connecting…";
    footDot   = healthErr ? "r" : "a";
  } else if (cp?.enabled) {
    footTitle = cp.leader_id != null ? `${cp.leader_id} · leader` : "no leader elected";
    footSub   = `${cp.healthy}/${cp.total} online${fleetVersion ? ` · ${fleetVersion}` : ""}`;
    footDot   = cp.write_available ? "g" : "r";
  } else {
    footTitle = "Standalone";
    footSub   = `${dp?.total ?? 0} WAF node${(dp?.total ?? 0) === 1 ? "" : "s"}${fleetVersion ? ` · ${fleetVersion}` : ""}`;
    footDot   = dp && dp.healthy > 0 ? "g" : "r";
  }

  return (
    <motion.nav
      className="sidebar"
      initial={{ x: -240, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      transition={{ ...spring, stiffness: 200, damping: 22 }}
    >
      <div style={{ flex: 1, overflowY: "auto", padding: "8px 8px" }}>
        {NAV.map(g => (
          <motion.div key={g.group} variants={navGroupStagger} initial="hidden" animate="visible">
            <span className="sb-lbl">{g.group}</span>
            {g.items.map((item, idx) => (
              <motion.div
                key={item.id}
                variants={navItemVariants}
                custom={idx}
                className={`nv ${current === item.id ? "active" : ""}`}
                onClick={() => router.push(`/${item.id}`)}
                whileHover={{ x: 3 }}
                whileTap={{ scale: 0.98 }}
              >
                <span className="nv-ico"><item.Icon /></span>
                <span className="nv-lbl">{item.label}</span>
                {(() => {
                  const lb = liveBadge[item.id];
                  const badgeText = lb ? lb.value : item.badge;
                  const badgeCls  = lb ? lb.cls : item.badgeCls;
                  return badgeText ? (
                    <span className={`nv-b ${badgeCls}`} style={(item as any).badgeStyle}>
                      {badgeText}
                    </span>
                  ) : null;
                })()}
              </motion.div>
            ))}
          </motion.div>
        ))}
      </div>

      {/* Cluster status footer */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4, ...spring }}
        style={{
          padding: "10px 12px",
          borderTop: "1px solid rgba(0,212,255,.08)",
          display: "flex", flexDirection: "column", gap: 4,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span className={`sd ${footDot}`} style={footDot === "g" ? { boxShadow: "0 0 6px var(--green)" } : undefined} />
          <span style={{ fontSize: 14, fontFamily: "var(--font-mono)", color: "var(--text2)", fontWeight: 600 }}>
            {footTitle}
          </span>
        </div>
        <div style={{ fontSize: 13, fontFamily: "var(--font-mono)", color: "var(--text3)", letterSpacing: ".4px" }}>
          {footSub}
        </div>
      </motion.div>
    </motion.nav>
  );
}