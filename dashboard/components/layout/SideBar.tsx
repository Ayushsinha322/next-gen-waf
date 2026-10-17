"use client";
import { useState, useEffect } from "react";
import { usePathname, useRouter } from "next/navigation";
import { motion } from "framer-motion";
import { api, type ClusterHealth } from "@/lib/api";
import { onAlertsChanged } from "@/lib/alertEvents";
import { navGroupStagger, navItemVariants } from "@/lib/animations";
import { useT } from "@/lib/i18n";

// Deployment-specific help links. Inlined by Next at BUILD time, so they are
// baked per bundle; unset means the link is not rendered at all.
const DOCS_URL = process.env.NEXT_PUBLIC_DOCS_URL ?? "";
const SUPPORT_URL = process.env.NEXT_PUBLIC_SUPPORT_URL ?? "";

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
  Jobs: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="9"/><polyline points="12 7 12 12 15.5 14"/>
    </svg>
  ),
  Reports: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>
      <line x1="8" y1="17" x2="8" y2="13"/><line x1="12" y1="17" x2="12" y2="10"/><line x1="16" y1="17" x2="16" y2="15"/>
    </svg>
  ),
  Cluster: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="4" r="2.4"/><circle cx="5" cy="19" r="2.4"/><circle cx="19" cy="19" r="2.4"/>
      <line x1="12" y1="6.4" x2="6.3" y2="16.8"/><line x1="12" y1="6.4" x2="17.7" y2="16.8"/><line x1="7.4" y1="19" x2="16.6" y2="19"/>
    </svg>
  ),
};

// One badge policy. The right-hand column carries a LIVE COUNT where one exists
// (sites, enforced rules, plugins, open alerts) and nothing else; pages fed by a
// live stream get a small pulsing dot instead of a "LIVE" word. The mix of tier
// tags ("NEW", "AI", "TLS"), counts and status chips in one column is gone.
const NAV: Array<{ group: string; items: Array<{ id: string; Icon: () => React.JSX.Element; live?: boolean }> }> = [
  { group: "monitor", items: [
    { id: "overview", Icon: Icon.Overview },
    { id: "traffic",  Icon: Icon.Traffic, live: true },
    { id: "alerts",   Icon: Icon.Alerts },
    { id: "logs",     Icon: Icon.Logs, live: true },
    { id: "events",   Icon: Icon.Search },
    { id: "reports",  Icon: Icon.Reports },
  ]},
  { group: "protect", items: [
    { id: "sites",        Icon: Icon.Sites },
    { id: "rules",        Icon: Icon.Rules },
    { id: "certificates", Icon: Icon.Certificates },
    { id: "blocked",      Icon: Icon.ThreatIntel },
    { id: "plugins",      Icon: Icon.Plugins },
  ]},
  { group: "intelligence", items: [
    { id: "threat-intel", Icon: Icon.ThreatIntel },
    { id: "ml",           Icon: Icon.ML, live: true },
  ]},
  { group: "system", items: [
    { id: "cluster",         Icon: Icon.Cluster },
    { id: "audit",           Icon: Icon.Audit },
    { id: "jobs",            Icon: Icon.Jobs },
    { id: "global-settings", Icon: Icon.Settings },
    { id: "settings",        Icon: Icon.Settings },
  ]},
];

type Counts = { sites: number | null; rules: number | null; plugins: number | null; alerts: number | null };

export default function SideBar() {
  const pathname = usePathname();
  const router   = useRouter();
  const { t }    = useT();
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
        // "open" only: counting the open rows of an unfiltered list counted the
        // open rows of whatever PAGE of alert history came back.
        api.sites.list(), api.rules.list(), api.plugins.list(), api.alerts.list("open"),
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
    // The Alerts badge must move the moment an alert is closed, not a minute later.
    const off = onAlertsChanged(load);
    return () => { cancelled = true; clearInterval(t); off(); };
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
    footTitle = t("nav.cluster");
    footSub   = healthErr ? t("cluster.unreachable") : t("cluster.connecting");
    footDot   = healthErr ? "r" : "a";
  } else if (cp?.enabled) {
    footTitle = cp.leader_id != null ? t("cluster.leader", { id: cp.leader_id }) : t("cluster.no_leader");
    footSub   = `${t("cluster.online", { healthy: cp.healthy, total: cp.total })}${fleetVersion ? ` · ${fleetVersion}` : ""}`;
    footDot   = cp.write_available ? "g" : "r";
  } else {
    const n = dp?.total ?? 0;
    footTitle = t("cluster.standalone");
    footSub   = `${t(n === 1 ? "cluster.nodes" : "cluster.nodes_plural", { n })}${fleetVersion ? ` · ${fleetVersion}` : ""}`;
    footDot   = dp && dp.healthy > 0 ? "g" : "r";
  }

  return (
    <motion.nav
      className="sidebar"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.2 }}
    >
      <div className="sb-scroll" style={{ flex: 1, overflowY: "auto", padding: "8px 8px" }}>
        {NAV.map(g => (
          <motion.div key={g.group} variants={navGroupStagger} initial="hidden" animate="visible">
            <span className="sb-lbl">{t(`nav.group.${g.group}`)}</span>
            {g.items.map((item, idx) => (
              <motion.div
                key={item.id}
                variants={navItemVariants}
                custom={idx}
                className={`nv ${current === item.id ? "active" : ""}`}
                onClick={() => router.push(`/${item.id}`)}
                whileTap={{ scale: 0.97 }}
              >
                <span className="nv-ico"><item.Icon /></span>
                <span className="nv-lbl">{t(`nav.${item.id}`)}</span>
                {item.live && <span className="nv-live" title={t("nav.live")} aria-label={t("nav.live")} />}
                {liveBadge[item.id] && (
                  <span className={`nv-b ${liveBadge[item.id].cls}`}>{liveBadge[item.id].value}</span>
                )}
              </motion.div>
            ))}
          </motion.div>
        ))}
      </div>

      {/* Cluster status footer */}
      <motion.div
        className="sb-foot"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.15, duration: 0.2 }}
        style={{
          padding: "10px 12px",
          borderTop: "1px solid var(--sep-chrome)",
          display: "flex", flexDirection: "column", gap: 4,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span className={`sd ${footDot}`} />
          <span style={{ fontSize: 13, fontFamily: "var(--font-sans)", color: "var(--text)", fontWeight: 600 }}>
            {footTitle}
          </span>
        </div>
        <div style={{ fontSize: 12, fontFamily: "var(--font-sans)", color: "var(--text3)", fontVariantNumeric: "tabular-nums" }}>
          {footSub}
        </div>

        {/* Help links. The console showed a version string and nothing else: an
            operator who did not already know where the manual lived had no way to
            find it from inside the product. Both are DEPLOYMENT-SPECIFIC URLs and
            are rendered only when set — an ESDS internal documentation host is not
            something this repository can know, and a link that 404s is worse than
            no link. Set NEXT_PUBLIC_DOCS_URL / NEXT_PUBLIC_SUPPORT_URL at build
            time to show them; with neither set the row is not drawn at all. */}
        {(DOCS_URL || SUPPORT_URL) && (
        <div style={{ display: "flex", flexWrap: "wrap", gap: 10, marginTop: 8, paddingTop: 8,
                      borderTop: "1px solid var(--sep-chrome)" }}>
          {DOCS_URL && (
            <a href={DOCS_URL} target="_blank" rel="noreferrer"
               style={{ fontSize: 12, color: "var(--text3)", textDecoration: "none" }}
               title="Product documentation">Documentation ↗</a>
          )}
          {SUPPORT_URL && (
            <a href={SUPPORT_URL} target="_blank" rel="noreferrer"
               style={{ fontSize: 12, color: "var(--text3)", textDecoration: "none" }}
               title="Raise a support request">Get support ↗</a>
          )}
        </div>
        )}
      </motion.div>
    </motion.nav>
  );
}