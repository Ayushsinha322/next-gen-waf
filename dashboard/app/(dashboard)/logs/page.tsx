"use client";
import { useState, useEffect, useRef, Suspense } from "react";
import { motion } from "framer-motion";
import { api } from "@/lib/api";
import { spring } from "@/lib/animations";

type LogKind = "access" | "waf" | "error" | "audit" | "modsec" | "ml";
interface LogRow { _lid: number; [k: string]: unknown; }
type LogStore = Record<LogKind, LogRow[]>;

interface LogFile { id: LogKind; label: string; group: string; }

const LOG_FILES: LogFile[] = [
  { id: "access", label: "access.log",       group: "WAF Logs"     },
  { id: "waf",    label: "waf.log",          group: "WAF Logs"     },
  { id: "error",  label: "error.log",        group: "WAF Logs"     },
  { id: "audit",  label: "audit.log",        group: "System Logs"  },
  { id: "modsec", label: "modsec.log",       group: "System Logs"  },
  { id: "ml",     label: "ml.log",           group: "Intelligence" },
];

const MAX = 500;
const GROUPS = Array.from(new Set(LOG_FILES.map(f => f.group)));

function escHtml(s: string) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function fmt(kind: LogKind, r: Record<string, unknown>): string {
  const ts = String(r.ts ?? "");
  switch (kind) {
    case "access":
      return `${ts} [${Number(r.status ?? 200) >= 400 ? "BLOCK" : "PASS"}] ${r.ip} ${r.method} ${r.path} ${r.status} proto=${r.protocol ?? "-"} latency=${r.latency}ms bytes=${r.bytes} site=${r.site} ua="${r.ua ?? "-"}"`;
    case "waf":
      return `${ts} [${r.action ?? "BLOCK"}] ${r.ip} ${r.method} ${r.path} rule=${r.rule ?? r.rule_id} score=${r.score} sev=${r.sev} attack="${r.attack}" proto=${r.protocol ?? "-"} site=${r.site}`;
    case "error":
      return `${ts} [${r.lvl ?? "ERROR"}] component=${r.subsystem ?? r.component} code=${r.code ?? "-"} msg="${r.msg}"`;
    case "audit":
      return `${ts} [AUDIT] user=${r.user} action=${r.action} resource=${r.resource} ip=${r.ip} result=${r.result} session=${r.session}`;
    case "modsec":
      return `${ts} [CRS] txid=${r.txId} phase=${r.phase} rule=${r.ruleId ?? r.rule_id} sev=${r.sev} ip=${r.ip} uri=${r.uri ?? r.path} action=${r.action} msg="${r.msg}" site=${r.site}`;
    case "ml":
      return `${ts} [ML] model=${r.model} ip=${r.ip} path=${r.path} verdict=${r.verdict} conf=${r.conf}% latency=${r.latency}ms site=${r.site}`;
    default:
      return JSON.stringify(r);
  }
}

function hl(raw: string): string {
  return escHtml(raw)
    .replace(/(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\d.Z]*)/g, '<span class="hl-ts">$1</span>')
    .replace(/\[(PASS)\]/g,                           '[<span class="hl-pass">$1</span>]')
    .replace(/\[(BLOCK|BLOCKED)\]/g,                  '[<span class="hl-blk">$1</span>]')
    .replace(/\[(ERROR|FATAL)\]/g,                    '[<span class="hl-err">$1</span>]')
    .replace(/\[(WARN)\]/g,                           '[<span class="hl-warn">$1</span>]')
    .replace(/\[(AUDIT|ML|CRS|INFO)\]/g,              '[<span class="hl-info">$1</span>]')
    .replace(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g,'<span class="hl-ip">$1</span>')
    .replace(/\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b/g, '<span class="hl-method">$1</span>')
    .replace(/\b(403|429|400|401|405|500|502|503)\b/g,'<span class="hl-block">$1</span>')
    .replace(/\b(200|201|204|301|302|304)\b/g,        '<span class="hl-ok">$1</span>')
    .replace(/ (\/[^\s"&;]+)/g,                       ' <span class="hl-path">$1</span>')
    .replace(/proto=(h[123]|-)/g,                     'proto=<span class="hl-method">$1</span>')
    .replace(/score=(\d+)/g,                          'score=<span class="hl-score">$1</span>');
}

function rowClass(kind: LogKind, r: Record<string, unknown>): string {
  switch (kind) {
    case "access": return Number(r.status ?? 200) >= 500 ? "ll-err" : Number(r.status ?? 200) >= 400 ? "ll-block" : "ll-pass";
    case "waf":    return r.sev === "CRITICAL" ? "ll-critical" : (r.action === "BLOCKED" || r.action === "BLOCK") ? "ll-block" : "ll-warn";
    case "error":  return r.lvl === "FATAL" ? "ll-critical" : r.lvl === "ERROR" ? "ll-err" : r.lvl === "WARN" ? "ll-warn" : "ll-info";
    case "audit":  return r.result === "FAILURE" ? "ll-err" : "ll-info";
    case "modsec": return r.action === "blocked" ? "ll-block" : parseInt(String(r.sev)) <= 2 ? "ll-critical" : "ll-warn";
    case "ml":     return /BLOCK|INJECT|CRITICAL/.test(String(r.verdict ?? "")) ? "ll-critical" : /ANOMALY|SUSPECT/.test(String(r.verdict ?? "")) ? "ll-warn" : "ll-info";
    default:       return "ll-info";
  }
}

export default function LogsPage() {
  return (
    <Suspense fallback={<div className="lgw-loading">Loading log viewer…</div>}>
      <LogsInner />
    </Suspense>
  );
}

function LogsInner() {
  const [kind, setKind]     = useState<LogKind>("access");
  const [ddOpen, setDdOpen] = useState(false);
  const [follow, setFollow] = useState(true);
  const [search, setSearch] = useState("");
  const [connected, setCon] = useState(false);
  const [logs, setLogs]     = useState<LogStore>({ access:[], waf:[], error:[], audit:[], modsec:[], ml:[] });

  const pausedRef = useRef(false);
  const lid       = useRef(0);
  const bodyRef   = useRef<HTMLDivElement>(null);
  const esRef     = useRef<EventSource | null>(null);
  const ddRef     = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function connect() {
      const es = new EventSource(api.logs.streamURL());
      esRef.current = es;
      es.onopen    = () => setCon(true);
      es.onmessage = (evt) => {
        if (pausedRef.current) return;
        try {
          const e: { kind: LogKind; data: Record<string, unknown> } = JSON.parse(evt.data);
          if (!e.kind || !e.data) return;
          const row: LogRow = { ...e.data, _lid: lid.current++ };
          setLogs(prev => ({ ...prev, [e.kind]: [...prev[e.kind], row].slice(-MAX) }));
        } catch { /* ignore malformed */ }
      };
      es.onerror = () => { setCon(false); es.close(); setTimeout(connect, 3000); };
    }
    connect();
    return () => esRef.current?.close();
  }, []);

  useEffect(() => {
    if (follow && bodyRef.current) {
      bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
    }
  }, [logs, follow, kind]);

  useEffect(() => {
    function onDown(e: MouseEvent) {
      if (ddRef.current && !ddRef.current.contains(e.target as Node)) setDdOpen(false);
    }
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, []);

  const rows     = logs[kind];
  const filtered = search
    ? rows.filter(r => fmt(kind, r).toLowerCase().includes(search.toLowerCase()))
    : rows;

  const currFile = LOG_FILES.find(f => f.id === kind)!;
  const threats  = logs.waf.filter(r => r.action === "BLOCKED" || r.action === "BLOCK").length;
  const errors   = logs.error.filter(r => r.lvl === "ERROR" || r.lvl === "FATAL").length;

  function copyAll() {
    const text = filtered.map(r => fmt(kind, r)).join("\n");
    navigator.clipboard.writeText(text).catch(() => {});
  }

  function exportLog() {
    const text = filtered.map(r => fmt(kind, r)).join("\n");
    const blob = new Blob([text], { type: "text/plain" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href = url; a.download = currFile.label;
    a.click(); URL.revokeObjectURL(url);
  }

  return (
    <div className="lgw">
      <div className="lgw-hd">
        <div className="lgw-bc">/ <span>Operations</span> / <span>Logs</span></div>
        <div className="lgw-acts">
          <motion.button className="lgw-btn" onClick={copyAll} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
            Copy
          </motion.button>
          <motion.button className="lgw-btn" onClick={exportLog} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
            Download
          </motion.button>
          <motion.button
            className={`lgw-btn${follow ? " lgw-flw-on" : ""}`}
            onClick={() => setFollow(f => !f)}
            whileHover={{ scale: 1.03 }}
            whileTap={{ scale: 0.97 }}
          >
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M5 3l14 9-14 9V3z"/></svg>
            {follow ? "Unfollow" : "Follow"}
          </motion.button>
        </div>
      </div>

      <div className="lgw-ctrl">
        <div className="lgw-sf-wrap" ref={ddRef}>
          <motion.button className="lgw-sfbtn" onClick={() => setDdOpen(o => !o)} whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M13 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>
            Select File
            <span className="lgw-sf-cur">{currFile.label}</span>
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ marginLeft: "auto", opacity: .6 }}><path d="M6 9l6 6 6-6"/></svg>
          </motion.button>

          {ddOpen && (
            <motion.div className="lgw-dd" initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.15 }}>
              {GROUPS.map(g => (
                <div key={g}>
                  <div className="lgw-dd-grp">{g}</div>
                  {LOG_FILES.filter(f => f.group === g).map(f => (
                    <button
                      key={f.id}
                      className={`lgw-dd-item${kind === f.id ? " on" : ""}`}
                      onClick={() => { setKind(f.id); setDdOpen(false); setSearch(""); }}
                    >
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M13 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>
                      {f.label}
                      <span className="lgw-dd-cnt">{logs[f.id].length}</span>
                    </button>
                  ))}
                </div>
              ))}
            </motion.div>
          )}
        </div>

        <div className="lgw-search">
          <svg className="lgw-sico" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
          <input className="lgw-si" placeholder="Search logs… IP, rule, path, status" value={search} onChange={e => setSearch(e.target.value)} />
          {search && (
            <button className="lgw-clr" onClick={() => setSearch("")}>
              <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 6L6 18M6 6l12 12"/></svg>
            </button>
          )}
        </div>

        <motion.button
          className={`lgw-btn lgw-pause${pausedRef.current ? " off" : ""}`}
          onClick={() => { pausedRef.current = !pausedRef.current; }}
          whileHover={{ scale: 1.03 }}
          whileTap={{ scale: 0.97 }}
        >
          <div className={`lgw-ldot${connected ? "" : " off"}`} />
          {connected ? "Live" : "Reconnecting"}
        </motion.button>
      </div>

      <div className="lgw-viewer">
        <div className="lgw-vhd">
          <div className="lgw-vfn">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="rgba(0,212,255,.7)" strokeWidth="1.5"><path d="M13 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>
            {currFile.label}
            <span className="lgw-vbdg">{filtered.length} lines</span>
            {threats > 0 && <span className="lgw-vbdg lgw-vbdg-r">{threats} threats</span>}
            {errors  > 0 && <span className="lgw-vbdg lgw-vbdg-a">{errors} errors</span>}
          </div>
          <span className={`lgw-vbdg${connected ? " lgw-vbdg-g" : " lgw-vbdg-a"}`}>
            {connected ? "● live" : "⟳ reconnecting"}
          </span>
        </div>

        <div className="lgw-body" ref={bodyRef}>
          {filtered.length === 0 ? (
            <div className="lgw-empty">
              <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,.12)" strokeWidth="1"><path d="M13 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>
              {connected ? `Waiting for ${currFile.label} entries…` : "Connecting to log stream…"}
            </div>
          ) : (
            filtered.map((r, i) => (
              <motion.div
                key={r._lid as number}
                className={`ll ${rowClass(kind, r)}`}
                initial={{ opacity: 0, y: 2 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.12, delay: Math.min(i * 0.005, 0.15) }}
              >
                <div className="ll-n">{i + 1}</div>
                <div className="ll-t" dangerouslySetInnerHTML={{ __html: hl(fmt(kind, r)) }} />
              </motion.div>
            ))
          )}
        </div>

        <div className="lgw-ft">
          <span className="lgw-fstat">Lines: <b>{rows.length}</b></span>
          <span className="lgw-fstat">Shown: <b>{filtered.length}</b></span>
          <span className="lgw-fstat">Threats: <b className="lgw-r">{threats}</b></span>
          <span className="lgw-fstat">Errors: <b className="lgw-a">{errors}</b></span>
          <div style={{ flex: 1 }} />
          <motion.button className="lgw-pg" onClick={() => { if (bodyRef.current) bodyRef.current.scrollTop = 0; }} whileHover={{ color: "var(--cyan)" }}>↑ Top</motion.button>
          <motion.button className="lgw-pg" onClick={() => { if (bodyRef.current) bodyRef.current.scrollTop = bodyRef.current.scrollHeight; }} whileHover={{ color: "var(--cyan)" }}>↓ Bottom</motion.button>
        </div>
      </div>
    </div>
  );
}