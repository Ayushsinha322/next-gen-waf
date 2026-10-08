"use client";
import { useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import { showToast } from "@/components/ui/Toast";
import FirstRunNote from "@/components/ui/FirstRunNote";
import { api, type BlocksResponse, type IOC } from "@/lib/api";
import { staggerContainer, fadeUp, cardVariants } from "@/lib/animations";

// ---------------------------------------------------------------------------
// Blocked Sources — who is blocked right now, why, until when, and one button to
// undo it. Five mechanisms used to live in five places (some in none): XDP
// auto-bans and the eBPF blocklist were visible nowhere and could only be
// lifted by restarting the data plane; repeat-offender escalation was a number
// inside the engine; block-tier indicators sat on Threat Intel; country blocks
// on the site wizard. This is the single table an operator asks for first.
// ---------------------------------------------------------------------------

type Kind = "autoban" | "ebpf" | "offender" | "indicator" | "country";
interface Row {
  kind: Kind;
  key: string;
  value: string;
  detail: string;
  since?: number | string | null;
  expires?: string | null;
  ioc?: IOC;
  unblock?: () => Promise<void>;
  note?: string;
}

const KIND_META: Record<Kind, { label: string; bg: string; fg: string; tip: string }> = {
  autoban:   { label: "Auto-ban",         bg: "rgba(224,80,70,.16)",   fg: "var(--red-b)", tip: "Banned from one site for 15–60 minutes after repeated attack verdicts; the client sees the block page, and Unblock lifts it on every node" },
  ebpf:      { label: "eBPF blocklist",   bg: "rgba(224,80,70,.10)",   fg: "var(--red-b)", tip: "In the kernel/software drop list: seeded from a site's IP-reputation block CIDRs or added by the auto-ban" },
  offender:  { label: "repeat offender",  bg: "rgba(224,166,58,.14)",  fg: "var(--amber)", tip: "Blocked several times inside the correlation window; extra anomaly score on every request until the window passes" },
  indicator: { label: "threat intel",     bg: "rgba(0,200,240,.12)",   fg: "var(--cyan)",  tip: "Block-tier indicator in the corpus the data plane enforces (feed or manual)" },
  country:   { label: "GeoIP country",    bg: "rgba(124,58,237,.16)",  fg: "#a78bfa",      tip: "Blocked by at least one site's GeoIP policy" },
};

const rel = (unix?: number | string | null) => {
  if (unix === null || unix === undefined || unix === "") return "—";
  const t = typeof unix === "number" ? unix * 1000 : new Date(unix).getTime();
  const s = Math.max(0, (Date.now() - t) / 1000);
  return s < 60 ? `${Math.round(s)}s ago` : s < 3600 ? `${Math.round(s/60)}m ago` : s < 86400 ? `${Math.round(s/3600)}h ago` : `${Math.round(s/86400)}d ago`;
};
const until = (iso?: string | null) => {
  if (!iso) return "never";
  const s = (new Date(iso).getTime() - Date.now()) / 1000;
  if (s <= 0) return "expired";
  return s < 3600 ? `in ${Math.round(s/60)}m` : s < 86400 ? `in ${Math.round(s/3600)}h` : `in ${Math.round(s/86400)}d`;
};

export default function BlockedSourcesPage() {
  const [data, setData]     = useState<BlocksResponse | null>(null);
  const [err, setErr]       = useState<string | null>(null);
  const [filter, setFilter] = useState<Kind | "">("");
  const [search, setSearch] = useState("");
  const [busy, setBusy]     = useState<string | null>(null);

  // Manual block form → a block-tier indicator, the mechanism the data plane
  // already enforces on every node.
  const [newVal, setNewVal]     = useState("");
  const [newWhy, setNewWhy]     = useState("");
  const [newHours, setNewHours] = useState<string>("");
  const [adding, setAdding]     = useState(false);

  async function load() {
    try { setData(await api.blocks.list()); setErr(null); }
    catch (e) { setErr(e instanceof Error ? e.message : String(e)); }
  }
  useEffect(() => { load(); const t = setInterval(load, 15_000); return () => clearInterval(t); }, []);

  async function act(key: string, fn: () => Promise<void>, ok: string) {
    setBusy(key);
    try { await fn(); showToast(ok, "s"); await load(); }
    catch (e) { showToast(`Failed: ${e instanceof Error ? e.message : String(e)}`, "e"); }
    finally { setBusy(null); }
  }

  async function addBlock() {
    const v = newVal.trim();
    if (!v) return;
    const isCIDR = v.includes("/");
    setAdding(true);
    try {
      const expires = newHours && Number(newHours) > 0 ? new Date(Date.now() + Number(newHours) * 3600_000).toISOString() : null;
      await api.threatIntel.create({ type: isCIDR ? "cidr" : "ip", value: v, tier: "block", source: "console", category: newWhy.trim() || "manual", confidence: 100, expires_at: expires });
      showToast(`${v} is now blocked on every site${expires ? ` until ${new Date(expires).toLocaleString()}` : ""}`, "s");
      setNewVal(""); setNewWhy(""); setNewHours("");
      await load();
    } catch (e) {
      showToast(`Block failed: ${e instanceof Error ? e.message : String(e)}`, "e");
    } finally { setAdding(false); }
  }

  const rows: Row[] = useMemo(() => {
    if (!data) return [];
    const out: Row[] = [];
    const dp = data.dataplane;
    const banned = new Set(dp.autoban?.banned ?? []);
    for (const ip of dp.autoban?.banned ?? []) {
      out.push({ kind: "autoban", key: `ab:${ip}`, value: ip,
        detail: `≥ ${dp.autoban?.threshold_blocks ?? "?"} blocks in ${dp.autoban?.window_secs ?? "?"}s · dropped in ${dp.ebpf?.mode ?? "eBPF"} mode`,
        expires: null, unblock: async () => { await api.blocks.unblockIP(ip); } });
    }
    for (const ip of dp.ebpf?.exact_ips ?? []) {
      if (banned.has(ip)) continue;
      out.push({ kind: "ebpf", key: `eb:${ip}`, value: ip, detail: "exact address in the drop list", expires: null,
        unblock: async () => { await api.blocks.unblockIP(ip); } });
    }
    for (const net of dp.ebpf?.ranges ?? []) {
      out.push({ kind: "ebpf", key: `er:${net}`, value: net, detail: "CIDR seeded from a site's IP-reputation block list", expires: null,
        note: "Edit the site's IP-reputation policy to remove a range" });
    }
    for (const o of dp.offenders?.entries ?? []) {
      if (banned.has(o.ip)) continue;
      out.push({ kind: "offender", key: `of:${o.ip}`, value: o.ip,
        detail: `${o.blocks_in_window} blocks in the last ${dp.offenders?.window_secs ?? 60}s${o.escalated ? " · escalated" : ""}${o.autoban_pending ? ` · auto-ban at ${dp.autoban?.threshold_blocks}` : ""}`,
        since: o.last_block_unix, expires: null,
        unblock: async () => { await api.blocks.unblockIP(o.ip); } });
    }
    for (const i of data.indicators) {
      out.push({ kind: "indicator", key: `ioc:${i.id}`, value: i.value, ioc: i,
        detail: `${i.source} · ${i.category} · confidence ${i.confidence}`, since: i.last_seen, expires: i.expires_at ?? null,
        unblock: async () => { await api.threatIntel.remove(i.id); } });
    }
    for (const c of data.countries) {
      out.push({ kind: "country", key: `cc:${c}`, value: c, detail: "blocked by site GeoIP policy", expires: null,
        unblock: async () => { await api.geoip.unblock(c); } });
    }
    const q = search.trim().toLowerCase();
    return out.filter(r => (!filter || r.kind === filter) && (!q || r.value.toLowerCase().includes(q) || r.detail.toLowerCase().includes(q)));
  }, [data, filter, search]);

  const counts = useMemo(() => {
    const c: Record<Kind, number> = { autoban: 0, ebpf: 0, offender: 0, indicator: 0, country: 0 };
    if (!data) return c;
    const dp = data.dataplane;
    c.autoban = dp.autoban?.banned.length ?? 0;
    c.ebpf = (dp.ebpf?.exact_ips.filter(ip => !(dp.autoban?.banned ?? []).includes(ip)).length ?? 0) + (dp.ebpf?.ranges.length ?? 0);
    c.offender = dp.offenders?.entries.filter(o => !(dp.autoban?.banned ?? []).includes(o.ip)).length ?? 0;
    // The API caps the indicator list at 500 per type; indicators_total is the
    // real match count. Counting rows made an 18,013-entry feed read as 500.
    c.indicator = data.indicators_total ?? data.indicators.length;
    c.country = data.countries.length;
    return c;
  }, [data]);

  // How many block-tier indicators exist beyond the page the API returned. The
  // tile counts the feed; the table can only list what was sent, and saying so
  // is the difference between a cap and a contradiction.
  const iocTruncated = data ? Math.max(0, (data.indicators_total ?? 0) - data.indicators.length) : 0;
  const dp = data?.dataplane;

  return (
    <motion.div className="sec" variants={staggerContainer} initial="hidden" animate="visible">
      <FirstRunNote id="blocked" title="Three separate mechanisms are merged into this list">
        A source can be blocked by the data plane&apos;s own kernel/XDP list (including automatic
        bans for repeated offences), by the threat-intelligence indicator feed, or by country
        policy. Each row is unblocked at whichever of those set it. Indicators are capped at 500
        per type for display, so the number listed here is not the size of the feed.
      </FirstRunNote>
      <motion.div variants={fadeUp} style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 14 }}>
        <div>
          <div className="sec-title">Blocked Sources</div>
          <div className="sec-sub">
            Every source currently blocked, from every mechanism, with one button to undo it
            {dp?.reachable && dp.ebpf ? ` · eBPF ${dp.ebpf.mode} · ${dp.ebpf.drops.toLocaleString()} packets dropped` : ""}
            {dp && !dp.reachable ? " · data plane unreachable — its bans are unknown" : ""}
          </div>
        </div>
        <button className="btn bg-btn btn-sm" onClick={load}>⟳ Refresh</button>
      </motion.div>

      {err && <motion.div variants={fadeUp} className="code-block" style={{ borderLeft: "3px solid var(--red-b)" }}><span style={{ color: "var(--red-b)" }}>● COULD NOT LOAD</span> — {err}</motion.div>}
      {dp && !dp.reachable && (
        <motion.div variants={fadeUp} className="code-block" style={{ borderLeft: "3px solid var(--red-b)" }}>
          <span style={{ color: "var(--red-b)" }}>● DATA PLANE UNREACHABLE</span> — auto-bans, the eBPF blocklist and repeat offenders cannot be listed. {dp.error}
        </motion.div>
      )}
      {dp?.reachable && dp.autoban && !dp.autoban.enabled && (
        <motion.div variants={fadeUp} className="code-block" style={{ borderLeft: "3px solid var(--amber)" }}>
          <span style={{ color: "var(--amber)" }}>● AUTO-BAN IS OFF</span> on this node (SENTINEL_XDP_AUTOBAN). Repeat offenders are escalated but never dropped in the kernel.
        </motion.div>
      )}

      <motion.div variants={staggerContainer} initial="hidden" animate="visible" style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 12 }}>
        {(Object.keys(KIND_META) as Kind[]).map(k => (
          <motion.div key={k} className={`kpi ${filter === k ? "" : ""}`} variants={cardVariants} onClick={() => setFilter(f => f === k ? "" : k)}
            style={{ cursor: "pointer", outline: filter === k ? "1px solid var(--cyan)" : undefined }} title={KIND_META[k].tip}>
            <div className="kpi-lbl">{KIND_META[k].label}</div>
            <div className="kpi-val" style={{ color: KIND_META[k].fg }}>{data ? counts[k] : "…"}</div>
          </motion.div>
        ))}
      </motion.div>

      <motion.div className="panel" variants={fadeUp}>
        <div className="ph">
          <div className="ptitle">Block a source</div>
          <span className="td3" style={{ fontSize: 12.5 }}>Adds a manual block-tier indicator, enforced on every node within one sync</span>
        </div>
        <div className="pb" style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <input className="fin2" placeholder="IP or CIDR — 203.0.113.9 or 203.0.113.0/24" value={newVal} onChange={e => setNewVal(e.target.value)} style={{ width: 300, fontFamily: "var(--font-mono)" }} onKeyDown={e => { if (e.key === "Enter") addBlock(); }} />
          <input className="fin2" placeholder="reason (optional)" value={newWhy} onChange={e => setNewWhy(e.target.value)} style={{ width: 220 }} />
          <input className="fin2" type="number" min={0} placeholder="expires in hours (blank = never)" value={newHours} onChange={e => setNewHours(e.target.value)} style={{ width: 230 }} />
          <motion.button className="btn bgn btn-sm" disabled={adding || !newVal.trim()} onClick={addBlock} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>{adding ? "…" : "Block"}</motion.button>
        </div>
      </motion.div>

      <motion.div className="panel" variants={fadeUp}>
        <div className="ph">
          <div className="ptitle">Active blocks ({rows.length}{filter ? ` · ${KIND_META[filter].label}` : ""})</div>
          {iocTruncated > 0 && (
            <div className="td3" style={{ fontSize: 12, fontFamily: "var(--font-mono)" }}
              title="The API returns at most 500 indicators per type. The threat-intel tile counts the whole feed; this table lists the page.">
              listing {data!.indicators.length.toLocaleString()} of {(data!.indicators_total ?? 0).toLocaleString()} indicators
            </div>
          )}
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            {filter && <button className="btn bg-btn btn-xs" onClick={() => setFilter("")}>✕ clear filter</button>}
            <input className="fi2" placeholder="Search IP, CIDR, source…" value={search} onChange={e => setSearch(e.target.value)} style={{ width: 220 }} />
          </div>
        </div>
        <div className="tw">
          {!data ? (
            <div style={{ padding: 24, textAlign: "center", fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--text3)" }}>Loading…</div>
          ) : rows.length === 0 ? (
            <div style={{ padding: 24, textAlign: "center", fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--text3)" }}>
              {filter || search ? "nothing matches" : "nothing is blocked right now"}
            </div>
          ) : (
            <table>
              <thead><tr><th>Mechanism</th><th>Source</th><th>Detail</th><th>Last seen</th><th>Expires</th><th></th></tr></thead>
              <tbody>
                {rows.map(r => (
                  <tr key={r.key}>
                    <td><span className="bdg" title={KIND_META[r.kind].tip} style={{ textTransform: "none", background: KIND_META[r.kind].bg, color: KIND_META[r.kind].fg }}>{KIND_META[r.kind].label}</span></td>
                    <td style={{ fontFamily: "var(--font-mono)", fontSize: 13.5 }}>{r.value}</td>
                    <td className="td3" style={{ maxWidth: 380, whiteSpace: "normal", lineHeight: 1.4 }}>{r.detail}</td>
                    <td className="td3">{rel(r.since ?? null)}</td>
                    <td className="td3">{r.kind === "offender" ? `window ${dp?.offenders?.window_secs ?? 60}s` : until(r.expires)}</td>
                    <td>
                      {r.unblock ? (
                        <motion.button className="btn bg-btn btn-xs" disabled={busy === r.key} whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}
                          onClick={() => act(r.key, r.unblock!, `${r.value} unblocked`)}>{busy === r.key ? "…" : "Unblock"}</motion.button>
                      ) : <span className="td3" style={{ fontSize: 11.5 }} title={r.note}>{r.note ?? ""}</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </motion.div>

      <motion.div variants={fadeUp} className="td3" style={{ fontSize: 12.5, lineHeight: 1.5 }}>
        Rate limiting is not listed: it decides per request and holds no ban. Unblocking an auto-banned or repeat-offender address clears
        its history on the data plane this control plane talks to; an address that keeps attacking will be banned again.
      </motion.div>
    </motion.div>
  );
}
