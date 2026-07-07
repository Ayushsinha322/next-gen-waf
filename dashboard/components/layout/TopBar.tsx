"use client";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import { logout } from "@/lib/auth";
import { api } from "@/lib/api";
import { spring } from "@/lib/animations";

// ── SVG icons ────────────────────────────────────────────────────────────────
const BellIcon = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>
    <path d="M13.73 21a2 2 0 0 1-3.46 0"/>
  </svg>
);
const GearIcon = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="3"/>
    <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06-.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
  </svg>
);
const PowerIcon = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/>
  </svg>
);
const ShieldIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
  </svg>
);
const SearchIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
  </svg>
);
const SunIcon = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="5"/>
    <line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/>
    <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
    <line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/>
    <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
  </svg>
);
const MoonIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
  </svg>
);

export default function TopBar() {
  const router = useRouter();
  const [rps, setRps]   = useState<number | null>(null);
  const [p99, setP99]   = useState<number | null>(null);
  const [alerts, setAlerts] = useState(0);
  const [theme, setTheme] = useState<"dark" | "light">("dark");

  useEffect(() => {
    const saved = (localStorage.getItem("sentinel-theme") as "dark" | "light") || "dark";
    setTheme(saved);
  }, []);

  function toggleTheme() {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("sentinel-theme", next);
  }

  useEffect(() => {
    let cancelled = false;
    async function poll() {
      try {
        const snap = await api.metrics.snapshot();
        if (!cancelled) {
          setRps(snap.rps ?? 0);
          setP99(snap.p99_latency_ms ?? 0);
        }
      } catch { /* control plane may be offline */ }
    }
    poll();
    const t = setInterval(poll, 2000);
    return () => { cancelled = true; clearInterval(t); };
  }, []);

  useEffect(() => {
    api.alerts.list("open")
      .then(r => setAlerts((r.alerts ?? []).length))
      .catch(() => {});
  }, []);

  const rpsDisplay = rps !== null ? rps.toLocaleString() : "—";
  const p99Display = p99 !== null ? (p99 > 0 ? p99.toFixed(1) + "ms" : "<1ms") : "—";

  return (
    <motion.header
      className="topbar"
      initial={{ y: -60, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={spring}
    >
      <a className="tb-logo-area" onClick={() => router.push("/overview")}>
        <motion.div
          className="tb-emb"
          whileHover={{ scale: 1.08, rotate: 3 }}
          transition={spring}
        >
          <ShieldIcon />
        </motion.div>
        <div>
          <div className="tb-nm">
            <span className="s">NEXT-GEN ESDS</span>
            <span className="w">WAF</span>
          </div>
          <div className="tb-ver">ENTERPRISE v3.1.0</div>
        </div>
      </a>

      <div style={{ flex: 1, display: "flex", alignItems: "center", gap: 12, padding: "0 18px" }}>
        <div style={{ position: "relative" }}>
          <span style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)", color: "var(--text3)", pointerEvents: "none" }}>
            <SearchIcon />
          </span>
          <input className="sinp" type="text" placeholder="Search sites, rules, IPs, alerts…" />
        </div>

        <motion.div
          style={{
            display: "flex", alignItems: "center", gap: 7,
            padding: "5px 12px", borderRadius: 6,
            background: "rgba(0,212,255,.06)", border: "1px solid rgba(0,212,255,.14)",
            fontSize: 15, fontFamily: "'JetBrains Mono',monospace", color: "var(--text2)",
          }}
          whileHover={{ scale: 1.03, borderColor: "rgba(0,212,255,.3)" }}
        >
          <span className="tb-dot" />
          <span>{rpsDisplay} req/s</span>
          <span style={{ color: "var(--text3)" }}>·</span>
          <span style={{ color: p99 !== null && p99 > 5 ? "var(--amber)" : "var(--green)" }}>
            p99 {p99Display}
          </span>
        </motion.div>

        <div style={{
          display: "flex", alignItems: "center", gap: 5,
          padding: "4px 10px", borderRadius: 6,
          background: "rgba(0,200,122,.06)", border: "1px solid rgba(0,200,122,.18)",
          fontSize: 14, fontFamily: "'Inter',sans-serif", fontWeight: 500, color: "var(--green)",
          whiteSpace: "nowrap",
        }}>
          <div className="sd g" style={{ width: 5, height: 5 }} />
          All systems operational
        </div>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "0 14px", marginLeft: "auto" }}>
        <motion.div className="tb-btn" onClick={() => router.push("/alerts")} title="Alerts" whileHover={{ scale: 1.1 }} whileTap={{ scale: 0.95 }}>
          <BellIcon />
          {alerts > 0 && <span className="tb-badge">{alerts > 9 ? "9+" : alerts}</span>}
        </motion.div>

        <motion.div className="tb-btn" onClick={() => router.push("/settings")} title="Settings" whileHover={{ scale: 1.1 }} whileTap={{ scale: 0.95 }}>
          <GearIcon />
        </motion.div>

        <motion.div
          className="tb-btn"
          onClick={toggleTheme}
          title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
          whileHover={{ scale: 1.1 }}
          whileTap={{ scale: 0.95 }}
          style={{ color: theme === "light" ? "var(--amber)" : "var(--text2)" }}
        >
          {theme === "dark" ? <SunIcon /> : <MoonIcon />}
        </motion.div>

        <div style={{ width: 1, height: 22, background: "var(--border2)", margin: "0 2px" }} />

        <motion.div className="uchip" whileHover={{ scale: 1.03 }}>
          <div className="uav">A</div>
          <div>
            <div className="uname">admin</div>
            <div className="urole">OWNER</div>
          </div>
        </motion.div>

        <motion.div
          className="tb-btn"
          title="Sign out"
          onClick={() => { logout(); router.push("/login"); }}
          style={{ color: "var(--red-b)" }}
          whileHover={{ scale: 1.1 }}
          whileTap={{ scale: 0.95 }}
        >
          <PowerIcon />
        </motion.div>
      </div>
    </motion.header>
  );
}