"use client";
/**
 * WorldMap — interactive, fully-offline threat map of blocked requests.
 *
 * Basemap: public-domain world silhouette baked in at build time (lib/worldMap.ts)
 * — NO tiles/fonts/network at runtime (air-gap / on-prem safe).
 *
 * Interactions:
 *  • scroll / +- buttons to zoom (toward cursor), drag to pan, ⟲ to reset
 *  • click any country marker → context menu with a real "Block this country"
 *    action (POST /geoip/block → added to every site's geoip block list,
 *    hot-applied in ~5s). Enforcement requires a GeoLite2 mmdb — surfaced
 *    honestly in the menu when absent.
 *  • blocked countries show an amber lock-ring; threat origins glow red.
 */
import { useState, useRef, useEffect, useCallback } from "react";
import { showToast } from "@/components/ui/Toast";
import { api } from "@/lib/api";
import { WORLD_PATH, COUNTRY_POS, type CountryPos } from "@/lib/worldMap";

const VB_W = 950, VB_H = 620;
const POS_BY_CODE: Record<string, CountryPos> = Object.fromEntries(COUNTRY_POS.map(c => [c.code, c]));
const clamp = (v: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, v));

interface Menu { code: string; name: string; flag: string; n: number; ox: number; oy: number }

export default function WorldMap({
  data, loaded, dbPresent,
}: {
  data: Record<string, number>;
  /** There is country-attributed event data to draw. NOT "the database exists". */
  loaded: boolean;
  /** The country database is present on the data plane. Undefined = unknown. */
  dbPresent?: boolean;
}) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const [view, setView] = useState({ s: 1, tx: 0, ty: 0 });
  const [hover, setHover] = useState<string | null>(null);
  const [menu, setMenu] = useState<Menu | null>(null);
  const [blocked, setBlocked] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState<string | null>(null);
  const pan = useRef({ active: false, sx: 0, sy: 0, tx0: 0, ty0: 0, moved: false });

  const max = Math.max(1, ...Object.values(data));
  const totalCountries = Object.values(data).filter(v => v > 0).length;
  const ranked = Object.entries(data).filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const nameFor = (c: string) => POS_BY_CODE[c]?.name ?? c;
  const flagFor = (c: string) => POS_BY_CODE[c]?.flag ?? "\u{1F310}";
  const radius = (n: number) => 4 + 12 * Math.sqrt(n / max);

  // Load the current global block list.
  const loadBlocked = useCallback(() => {
    api.geoip.listBlocked().then(r => setBlocked(new Set(r.countries ?? []))).catch(() => {});
  }, []);
  useEffect(() => { loadBlocked(); }, [loadBlocked]);

  // px-per-viewBox-unit (uniform; aspect preserved).
  const kFactor = () => {
    const r = wrapRef.current?.getBoundingClientRect();
    return r ? r.width / VB_W : 1;
  };

  const zoomAt = useCallback((factor: number, clientX: number, clientY: number) => {
    const r = wrapRef.current?.getBoundingClientRect();
    if (!r) return;
    const k = r.width / VB_W;
    const vx = (clientX - r.left) / k, vy = (clientY - r.top) / k;
    setView(v => {
      const s2 = clamp(v.s * factor, 1, 7);
      const mx = (vx - v.tx) / v.s, my = (vy - v.ty) / v.s;
      const tx = clamp(vx - mx * s2, VB_W * (1 - s2), 0);
      const ty = clamp(vy - my * s2, VB_H * (1 - s2), 0);
      return { s: s2, tx, ty };
    });
    setMenu(null);
  }, []);

  // Non-passive wheel listener so we can block page scroll while zooming.
  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      zoomAt(e.deltaY < 0 ? 1.15 : 1 / 1.15, e.clientX, e.clientY);
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, [zoomAt]);

  function onPointerDown(e: React.PointerEvent) {
    pan.current = { active: true, sx: e.clientX, sy: e.clientY, tx0: view.tx, ty0: view.ty, moved: false };
    (e.target as Element).setPointerCapture?.(e.pointerId);
  }
  function onPointerMove(e: React.PointerEvent) {
    if (!pan.current.active) return;
    const k = kFactor();
    const dx = (e.clientX - pan.current.sx) / k, dy = (e.clientY - pan.current.sy) / k;
    if (Math.abs(e.clientX - pan.current.sx) + Math.abs(e.clientY - pan.current.sy) > 4) pan.current.moved = true;
    setView(v => ({
      s: v.s,
      tx: clamp(pan.current.tx0 + dx, VB_W * (1 - v.s), 0),
      ty: clamp(pan.current.ty0 + dy, VB_H * (1 - v.s), 0),
    }));
    if (pan.current.moved) setMenu(null);
  }
  function onPointerUp() { pan.current.active = false; }

  function openMenu(p: CountryPos, e: React.MouseEvent) {
    e.stopPropagation();
    if (pan.current.moved) return; // was a drag, not a click
    const r = wrapRef.current?.getBoundingClientRect();
    if (!r) return;
    const k = r.width / VB_W;
    setMenu({
      code: p.code, name: p.name, flag: p.flag, n: data[p.code] ?? 0,
      ox: (view.tx + p.x * view.s) * k,
      oy: (view.ty + p.y * view.s) * k,
    });
  }

  async function toggleBlock(code: string, name: string) {
    const isBlocked = blocked.has(code);
    setBusy(code);
    try {
      const r = isBlocked ? await api.geoip.unblock(code) : await api.geoip.block(code);
      setBlocked(new Set(r.countries ?? []));
      showToast(
        `${name} ${isBlocked ? "unblocked" : "blocked"}${loaded ? " · applies in ~5s" : " · stored (enforces once the country database is downloaded)"}`,
        "s", isBlocked ? "\u{1F513}" : "\u{1F6AB}",
      );
      setMenu(null);
    } catch (err) { showToast(err instanceof Error ? err.message : "Failed", "e", "⚠️"); }
    finally { setBusy(null); }
  }

  const reset = () => { setView({ s: 1, tx: 0, ty: 0 }); setMenu(null); };
  const points = Object.entries(data).filter(([c, n]) => n > 0 && POS_BY_CODE[c])
    .map(([c, n]) => ({ ...POS_BY_CODE[c], n })).sort((a, b) => a.n - b.n);

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1.7fr 1fr", gap: 16, alignItems: "stretch" }}>
      {/* ── map ── */}
      <div ref={wrapRef} onPointerDown={() => setMenu(null)} style={{
        position: "relative", borderRadius: 10, overflow: "hidden", touchAction: "none",
        background: "linear-gradient(180deg, rgba(6,12,24,.6), rgba(4,8,16,.85))",
        border: "1px solid var(--bg4)", cursor: pan.current.active ? "grabbing" : "grab", userSelect: "none",
      }}>
        <svg viewBox={`0 0 ${VB_W} ${VB_H}`} width="100%" style={{ display: "block" }}
          preserveAspectRatio="xMidYMid meet"
          onPointerDown={onPointerDown} onPointerMove={onPointerMove}
          onPointerUp={onPointerUp} onPointerLeave={onPointerUp}>
          <g transform={`translate(${view.tx} ${view.ty}) scale(${view.s})`}>
            {/* graticule */}
            <g stroke="rgba(255,255,255,.04)" strokeWidth={0.6 / view.s}>
              {[155, 310, 465].map(y => <line key={y} x1={0} y1={y} x2={VB_W} y2={y} />)}
              {[238, 475, 712].map(x => <line key={x} x1={x} y1={0} x2={x} y2={VB_H} />)}
            </g>
            {/* land */}
            <path d={WORLD_PATH} fill="rgba(255,255,255,.07)"
              stroke="rgba(0,229,255,.18)" strokeWidth={0.5 / view.s} />

            {/* threat heat */}
            {loaded && points.map(p => {
              const r = radius(p.n), top = p.n === max;
              return (
                <g key={"t" + p.code} style={{ pointerEvents: "none" }}>
                  <circle cx={p.x} cy={p.y} r={r * 1.9} fill="rgba(255,69,96,.16)">
                    {top && <animate attributeName="r" values={`${r*1.6};${r*2.4};${r*1.6}`} dur="2.2s" repeatCount="indefinite" />}
                  </circle>
                  <circle cx={p.x} cy={p.y} r={r} fill="rgba(255,69,96,.85)" stroke="#ff8095" strokeWidth={0.8 / view.s} />
                </g>
              );
            })}

            {/* clickable country markers (all known positions) */}
            {COUNTRY_POS.map(p => {
              const isBlocked = blocked.has(p.code);
              const isHover = hover === p.code;
              return (
                <g key={p.code} style={{ cursor: "pointer" }}
                  onMouseEnter={() => setHover(p.code)} onMouseLeave={() => setHover(null)}
                  onClick={(e) => openMenu(p, e)}>
                  {isBlocked && (
                    <circle cx={p.x} cy={p.y} r={9} fill="none" stroke="var(--amber,#ffb020)"
                      strokeWidth={1.6 / view.s} strokeDasharray={`${3/view.s} ${2/view.s}`} />
                  )}
                  {isHover && <circle cx={p.x} cy={p.y} r={7} fill="none" stroke="var(--cyan)" strokeWidth={1.2 / view.s} />}
                  {/* generous transparent hit target */}
                  <circle cx={p.x} cy={p.y} r={10} fill="transparent" />
                </g>
              );
            })}
          </g>
        </svg>

        {/* zoom controls */}
        <div style={{ position: "absolute", top: 8, left: 8, display: "flex", flexDirection: "column", gap: 4 }}>
          {[["+", () => zoomAt(1.4, (wrapRef.current!.getBoundingClientRect().left + wrapRef.current!.getBoundingClientRect().right) / 2, (wrapRef.current!.getBoundingClientRect().top + wrapRef.current!.getBoundingClientRect().bottom) / 2)],
            ["−", () => zoomAt(1 / 1.4, (wrapRef.current!.getBoundingClientRect().left + wrapRef.current!.getBoundingClientRect().right) / 2, (wrapRef.current!.getBoundingClientRect().top + wrapRef.current!.getBoundingClientRect().bottom) / 2)],
            ["⟲", reset]].map(([label, fn], i) => (
            <button key={i} onClick={fn as () => void} style={{
              width: 26, height: 26, borderRadius: 6, border: "1px solid var(--bg4)",
              background: "var(--bg2)", color: "var(--text2)", cursor: "pointer", fontSize: 15, lineHeight: 1,
              fontFamily: "var(--font-mono)",
            }}>{label as string}</button>
          ))}
        </div>

        {/* hover readout */}
        <div style={{
          position: "absolute", top: 8, right: 8, padding: "5px 10px", borderRadius: 8,
          background: "var(--bg2)", border: "1px solid var(--bg4)", fontSize: 14,
          color: "var(--text2)", fontFamily: "var(--font-mono)",
          opacity: hover ? 1 : 0.45, transition: "opacity .15s", pointerEvents: "none", maxWidth: 200,
        }}>
          {hover ? `${flagFor(hover)} ${nameFor(hover)} · ${(data[hover] ?? 0).toLocaleString()}${blocked.has(hover) ? " · BLOCKED" : ""}` : "Click a country to act"}
        </div>

        {/* context menu */}
        {menu && (
          <div onClick={(e) => e.stopPropagation()} style={{
            position: "absolute", left: clamp(menu.ox, 90, (wrapRef.current?.clientWidth ?? 400) - 90),
            top: Math.max(8, menu.oy - 12), transform: "translate(-50%, -100%)",
            background: "var(--bg2)", border: "1px solid var(--bg4)", borderRadius: 10,
            boxShadow: "0 10px 30px rgba(0,0,0,.5)", padding: 10, width: 210, zIndex: 20,
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
              <span style={{ fontSize: 18 }}>{menu.flag}</span>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 15, color: "var(--text)", fontWeight: 600 }}>{menu.name}</div>
                <div style={{ fontSize: 13, color: "var(--text3)", fontFamily: "var(--font-mono)" }}>
                  {menu.n > 0 ? `${menu.n.toLocaleString()} blocked requests` : "no blocked traffic"}
                </div>
              </div>
            </div>
            <button disabled={busy === menu.code} onClick={() => toggleBlock(menu.code, menu.name)}
              style={{
                width: "100%", padding: "7px 10px", borderRadius: 7, cursor: "pointer", fontSize: 14, fontWeight: 600,
                border: "1px solid " + (blocked.has(menu.code) ? "rgba(0,230,118,.4)" : "rgba(255,69,96,.45)"),
                background: blocked.has(menu.code) ? "rgba(0,230,118,.12)" : "rgba(255,69,96,.14)",
                color: blocked.has(menu.code) ? "var(--green)" : "#ff8095",
              }}>
              {busy === menu.code ? "…" : blocked.has(menu.code) ? "\u{1F513} Unblock this country" : "\u{1F6AB} Block this country"}
            </button>
            {!loaded && (
              <div style={{ fontSize: 12, color: "var(--text3)", marginTop: 6, lineHeight: 1.4, fontFamily: "var(--font-mono)" }}>
                {dbPresent === false ? "Stored now — enforces once the country database is downloaded (System Jobs → geoip.refresh)." : "Stored — applies within about 5 seconds."}
              </div>
            )}
          </div>
        )}

        {loaded && (
          <div style={{ position: "absolute", right: 10, bottom: 6, fontSize: 10, color: "var(--text3)", fontFamily: "var(--font-mono)", pointerEvents: "auto" }}>
            IP Geolocation by <a href="https://db-ip.com" target="_blank" rel="noreferrer" style={{ color: "var(--text3)" }}>DB-IP</a>
          </div>
        )}
        {/* not-loaded note */}
        {!loaded && !menu && (
          <div style={{
            position: "absolute", left: 0, right: 0, bottom: 0, padding: "9px 12px",
            display: "flex", alignItems: "center", gap: 10, justifyContent: "center",
            background: "linear-gradient(0deg, rgba(4,8,16,.92), transparent)", textAlign: "center", pointerEvents: "none",
          }}>
            <span style={{ fontSize: 18 }}>{"\u{1F30D}"}</span>
            <span style={{ fontSize: 14, color: "var(--text3)", lineHeight: 1.5, fontFamily: "var(--font-mono)" }}>
              {/* `loaded` means "there are country-attributed events to draw", which
                  is NOT the same as "the database is missing". Saying the latter
                  when the database is sitting there loaded sends an operator to
                  re-run a job that already worked — and the usual real reason for
                  an empty map is that the traffic came from private addresses,
                  which have no country in any database. */}
              {dbPresent === false ? (
                <>Country database not loaded yet — the <span style={{ color: "var(--cyan)" }}>geoip.refresh</span> job downloads it (System Jobs → Run now), or set <span style={{ color: "var(--cyan)" }}>SENTINEL_GEOIP_DB</span> to your own .mmdb.</>
              ) : (
                <>Country database loaded. No country-attributed traffic yet — requests from private or loopback addresses (10.x, 172.16–31.x, 192.168.x, 127.x) have no country in any database, so they cannot appear here.</>
              )}
            </span>
          </div>
        )}
      </div>

      {/* ── ranked list ── */}
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        <div style={{ fontSize: 14, color: "var(--text3)", fontFamily: "var(--font-mono)", letterSpacing: 1, textTransform: "uppercase" }}>
          Top origins {loaded && totalCountries > 0 ? `(${totalCountries})` : ""}
          {blocked.size > 0 && <span style={{ color: "var(--amber,#ffb020)" }}> · {blocked.size} blocked</span>}
        </div>
        {ranked.length === 0 ? (
          <div style={{ fontSize: 14, color: "var(--text3)", fontFamily: "var(--font-mono)", padding: "8px 0" }}>
            {loaded ? "No blocked traffic yet" : "Awaiting GeoIP data"}
          </div>
        ) : ranked.map(([code, n]) => (
          <div key={code} style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontSize: 16 }}>{flagFor(code)}</span>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 14, color: "var(--text2)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                {nameFor(code)}{blocked.has(code) && <span style={{ color: "var(--amber,#ffb020)", marginLeft: 5 }}>{"\u{1F6AB}"}</span>}
              </div>
              <div style={{ height: 5, background: "var(--bg3)", borderRadius: 3, marginTop: 3, overflow: "hidden" }}>
                <div style={{ height: "100%", width: `${(n / max) * 100}%`, background: "rgba(255,69,96,.8)", borderRadius: 3 }} />
              </div>
            </div>
            <span style={{ fontSize: 14, color: "var(--text)", fontFamily: "var(--font-mono)" }}>{n.toLocaleString()}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
