"use client";
import { useState, useEffect, useRef, useCallback, useMemo, Suspense } from "react";
import Link from "next/link";
import { motion } from "framer-motion";
import { api } from "@/lib/api";
import { spring } from "@/lib/animations";
import { fmt, toneOf, lineCounts, attackByRequest, highlightLine, type LogKind, type LineTone } from "@/lib/logFormat";

interface LogRow { _lid: number; [k: string]: unknown; }
type LogStore = Record<LogKind, LogRow[]>;

interface LogFile { id: LogKind; label: string; group: string; }

// modsec.log and ml.log are NOT offered: nothing writes them. They came from
// sentinel-telemetry's EventLogger, which had no callers and was removed in
// 2026-08, so selecting either showed an empty pane forever — which reads as
// "the WAF has stopped logging", not as "this file does not exist".
const LOG_FILES: LogFile[] = [
  { id: "access", label: "access.log",       group: "WAF Logs"     },
  { id: "waf",    label: "waf.log",          group: "WAF Logs"     },
  { id: "error",  label: "error.log",        group: "WAF Logs"     },
  { id: "audit",  label: "audit.log",        group: "System Logs"  },
];

const MAX = 500;
const GROUPS = Array.from(new Set(LOG_FILES.map(f => f.group)));

const TONE_CLASS: Record<LineTone, string> = {
  block: "ll-block", warn: "ll-warn", err: "ll-err", critical: "ll-critical", pass: "ll-pass", info: "ll-info",
};

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
  const [logs, setLogs]     = useState<LogStore>({ access:[], waf:[], error:[], audit:[] });

  // Latches true the moment any fabricated entry arrives, and never resets for
  // the life of the view — a simulated stream must stay labelled even if live
  // entries start arriving afterwards.
  const [sawSimulated, setSawSimulated] = useState(false);

  // Pause is BOTH state and ref on purpose. The EventSource handler is created
  // once (empty dep array) so it closes over the initial render and can only
  // read the live value through a ref; the button needs state to re-render.
  // Previously only the ref existed, so the control never repainted and looked
  // dead. Paused lines are now buffered rather than dropped — a tail you pause
  // to read a stack trace must not silently lose the lines that arrive while
  // you are reading, which is the whole reason to pause.
  const [paused, setPaused] = useState(false);
  const [buffered, setBuffered] = useState(0);
  const pausedRef = useRef(false);
  const bufRef    = useRef<Array<{ kind: LogKind; row: LogRow }>>([]);
  const lid       = useRef(0);
  const bodyRef   = useRef<HTMLDivElement>(null);
  const esRef     = useRef<EventSource | null>(null);
  const ddRef     = useRef<HTMLDivElement>(null);

  // Append one row to its bucket.
  //
  // The bucket lookup MUST be guarded. LogStore is keyed by the six viewer tabs,
  // but the control plane publishes onto the same hub with other kinds — the
  // alerting engine emits Kind:"alert" — and Hub.Subscribe replays its recent
  // backlog to every new subscriber. The previous code spread prev[e.kind]
  // unguarded, so one alert anywhere in the backlog threw
  // "undefined is not iterable" during render and took the whole log viewer
  // down for anyone who opened it afterwards. Unknown kinds are dropped.
  const appendRow = useCallback((kind: LogKind, row: LogRow) => {
    setLogs(prev => {
      const bucket = prev[kind];
      if (!bucket) return prev;
      return { ...prev, [kind]: [...bucket, row].slice(-MAX) };
    });
  }, []);

  useEffect(() => {
    function connect() {
      const es = new EventSource(api.logs.streamURL());
      esRef.current = es;
      es.onopen    = () => setCon(true);
      es.onmessage = (evt) => {
        try {
          const e: { kind: LogKind; data: Record<string, unknown>; source?: string } =
            JSON.parse(evt.data);
          if (!e.kind || !e.data) return;
          // Provenance rides on every entry (control-plane logs.Entry.Source).
          // Anything not explicitly "live" is treated as fabricated: an unknown or
          // missing value must never be rendered as observed traffic.
          const simulated = e.source !== "live";
          if (simulated) setSawSimulated(true);
          const row: LogRow = { ...e.data, _lid: lid.current++, _simulated: simulated };

          if (pausedRef.current) {
            bufRef.current.push({ kind: e.kind, row });
            if (bufRef.current.length > MAX) bufRef.current.shift();
            setBuffered(bufRef.current.length);
            return;
          }
          appendRow(e.kind, row);
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
    // `search` too: clearing a filter while following used to leave the view at
    // the top of the full list instead of at the newest line.
  }, [logs, follow, kind, search]);

  useEffect(() => {
    function onDown(e: MouseEvent) {
      if (ddRef.current && !ddRef.current.contains(e.target as Node)) setDdOpen(false);
    }
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, []);

  // access.log rows carry the rule and score but not the attack's name; the
  // waf.log row for the same request id does. Join them so a block line says
  // what it blocked, and so searching "SQL Injection" finds access lines too.
  const attacks  = useMemo(() => attackByRequest(logs.waf), [logs.waf]);
  const rows     = useMemo(() => kind !== "access" ? logs[kind] : logs.access.map(r => {
    const a = typeof r.request_id === "string" ? attacks.get(r.request_id) : undefined;
    return a && !r.attack ? { ...r, attack: a } : r;
  }), [logs, kind, attacks]);
  const filtered = search
    ? rows.filter(r => fmt(kind, r).toLowerCase().includes(search.toLowerCase()))
    : rows;

  const currFile = LOG_FILES.find(f => f.id === kind)!;
  // Counted over the lines on screen — this file, this search — not over
  // waf.log/error.log as a whole. See lineCounts.
  const { blocked, errors } = lineCounts(kind, filtered);

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
          {/* This page is a live tail: in-memory, capped, and gone on refresh.
              An operator arriving here to answer "send me my logs for 3 August"
              is in the wrong place, and nothing else on screen says so. */}
          <Link href="/events" className="lgw-btn" title="Saved per-application log views and downloadable history">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
            Log Profiles &amp; history
          </Link>
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

      {sawSimulated && (
        <div className="lgw-simbanner" role="alert">
          <strong>SIMULATED DATA</strong>
          <span>
            This stream contains entries fabricated by the development simulator
            (SENTINEL_DEV_SIMULATOR=1). They do not represent real traffic, real attacks, or
            real blocks. Disable the simulator before showing this dashboard to anyone.
          </span>
        </div>
      )}

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
          className={`lgw-btn lgw-pause${paused ? " off" : ""}`}
          title={paused
            ? "Paused — new lines are being buffered, click to resume"
            : "Streaming live — click to pause"}
          onClick={() => {
            const next = !paused;
            setPaused(next);
            pausedRef.current = next;
            if (!next && bufRef.current.length) {
              // Resuming: flush what arrived while paused, in arrival order,
              // so pausing to read never costs the operator lines.
              const pending = bufRef.current;
              bufRef.current = [];
              setBuffered(0);
              setLogs(prev => {
                const next2 = { ...prev };
                for (const { kind: k, row } of pending) {
                  const bucket = next2[k];
                  if (!bucket) continue;
                  next2[k] = [...bucket, row].slice(-MAX);
                }
                return next2;
              });
            }
          }}
          whileHover={{ scale: 1.03 }}
          whileTap={{ scale: 0.97 }}
        >
          <div className={`lgw-ldot${connected && !paused ? "" : " off"}`} />
          {paused
            ? (buffered > 0 ? `Paused · ${buffered} buffered` : "Paused")
            : (connected ? "Live" : "Reconnecting")}
        </motion.button>
      </div>

      <div className="lgw-viewer">
        <div className="lgw-vhd">
          <div className="lgw-vfn">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="rgba(0,212,255,.7)" strokeWidth="1.5"><path d="M13 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>
            {currFile.label}
            <span className="lgw-vbdg">{filtered.length} lines</span>
            {blocked > 0 && <span className="lgw-vbdg lgw-vbdg-r">{blocked} blocked</span>}
            {errors  > 0 && <span className="lgw-vbdg lgw-vbdg-a">{errors} errors</span>}
            <span className="lgw-vbdg" title="Timestamps are UTC, exactly as the data plane writes them">UTC</span>
          </div>
          <span className={`lgw-vbdg${connected ? " lgw-vbdg-g" : " lgw-vbdg-a"}`}>
            {connected ? "● live" : "⟳ reconnecting"}
          </span>
        </div>

        <div className="lgw-body" ref={bodyRef}>
          {filtered.length === 0 ? (
            <div className="lgw-empty">
              <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,.12)" strokeWidth="1"><path d="M13 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>
              {rows.length > 0
                ? `No line in the last ${rows.length} of ${currFile.label} matches “${search}”.`
                : connected ? `Waiting for ${currFile.label} entries…` : "Connecting to log stream…"}
            </div>
          ) : (
            filtered.map((r, i) => (
              <motion.div
                key={r._lid as number}
                className={`ll ${TONE_CLASS[toneOf(kind, r)]}`}
                initial={{ opacity: 0, y: 2 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.12, delay: Math.min(i * 0.005, 0.15) }}
              >
                <div className="ll-n">{i + 1}</div>
                {r._simulated ? <span className="ll-sim" title="Fabricated by the development simulator — not real traffic">SIMULATED</span> : null}
                <div className="ll-t" dangerouslySetInnerHTML={{ __html: highlightLine(fmt(kind, r)) }} />
              </motion.div>
            ))
          )}
        </div>

        <div className="lgw-ft">
          <span className="lgw-fstat">Lines: <b>{rows.length}</b></span>
          <span className="lgw-fstat">Shown: <b>{filtered.length}</b></span>
          <span className="lgw-fstat">Blocked: <b className="lgw-r">{blocked}</b></span>
          <span className="lgw-fstat">Errors: <b className="lgw-a">{errors}</b></span>
          <div style={{ flex: 1 }} />
          <motion.button className="lgw-pg" onClick={() => { if (bodyRef.current) bodyRef.current.scrollTop = 0; }} whileHover={{ color: "var(--cyan)" }}>↑ Top</motion.button>
          <motion.button className="lgw-pg" onClick={() => { if (bodyRef.current) bodyRef.current.scrollTop = bodyRef.current.scrollHeight; }} whileHover={{ color: "var(--cyan)" }}>↓ Bottom</motion.button>
        </div>
      </div>
    </div>
  );
}