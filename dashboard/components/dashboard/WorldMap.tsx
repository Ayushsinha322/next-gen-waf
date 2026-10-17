"use client";
/**
 * WorldMap — interactive, fully-offline threat map of blocked requests.
 *
 * Two views of the same data, chosen with the Globe / Flat control (remembered
 * per browser): a 3D globe (components/dashboard/Globe.tsx) and the flat map.
 * Basemaps are public-domain data baked in at build time (lib/worldMap.ts,
 * lib/globeData.ts) — NO tiles/fonts/network at runtime (air-gap / on-prem safe).
 *
 * Flat-map interactions:
 *  • scroll / +- buttons to zoom (toward cursor), drag to pan, ⟲ to reset
 *  • click any country marker → context menu with a real "Block this country"
 *    action (POST /geoip/block → added to every site's geoip block list,
 *    hot-applied in ~5s). Enforcement requires a GeoLite2 mmdb — surfaced
 *    honestly in the menu when absent.
 *  • blocked countries show an amber lock-ring; threat origins glow red.
 */
import { useState, useRef, useEffect, useCallback } from "react";
import Globe, { type GlobeHandle, type GlobePick } from "@/components/dashboard/Globe";
import { countryFlag, countryName } from "@/lib/geo";
import { showToast } from "@/components/ui/Toast";
import { confirmAction } from "@/components/ui/confirm";
import { countryBlockConfirm } from "@/lib/siteConfirm";
import { api } from "@/lib/api";
import { WORLD_PATH, COUNTRY_POS, type CountryPos } from "@/lib/worldMap";

const VB_W = 950, VB_H = 620;
const POS_BY_CODE: Record<string, CountryPos> = Object.fromEntries(COUNTRY_POS.map(c => [c.code, c]));
const clamp = (v: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, v));

interface Menu { code: string; name: string; flag: string; n: number; ox: number; oy: number }
type Mode = "globe" | "flat";
const NO_DATA: Record<string, number> = {};   // stable, so the globe does not re-derive on every render
const MODE_KEY = "sk-geo-view";

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
  const globeRef = useRef<GlobeHandle>(null);
  const [mode, setModeState] = useState<Mode>("globe");
  // Remembered per browser only — a viewing preference, not shared state.
  useEffect(() => {
    try { const m = localStorage.getItem(MODE_KEY); if (m === "flat" || m === "globe") setModeState(m); } catch { /* storage blocked */ }
  }, []);
  const setMode = (m: Mode) => {
    setModeState(m); setMenu(null); setHover(null);
    try { localStorage.setItem(MODE_KEY, m); } catch { /* storage blocked */ }
  };

  const max = Math.max(1, ...Object.values(data));
  const totalCountries = Object.values(data).filter(v => v > 0).length;
  const ranked = Object.entries(data).filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1]).slice(0, 6);
  // The globe can point at any country, not just the flat map's hand-placed 27.
  const nameFor = (c: string) => POS_BY_CODE[c]?.name ?? countryName(c);
  const flagFor = (c: string) => POS_BY_CODE[c]?.flag ?? countryFlag(c);
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
    if (!el || mode !== "flat") return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      zoomAt(e.deltaY < 0 ? 1.15 : 1 / 1.15, e.clientX, e.clientY);
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, [zoomAt, mode]);

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
    if (!isBlocked && !(await confirmAction(countryBlockConfirm(name)))) return;
    setBusy(code);
    try {
      const r = isBlocked ? await api.geoip.unblock(code) : await api.geoip.block(code);
      setBlocked(new Set(r.countries ?? []));
      showToast(
        `${name} ${isBlocked ? "unblocked" : "blocked"}${loaded ? " · applies in ~5s" : " · stored (enforces once the country database is downloaded)"}`,
        "s");
      setMenu(null);
    } catch (err) { showToast(err instanceof Error ? err.message : "Failed", "e"); }
    finally { setBusy(null); }
  }

  const reset = () => {
    setMenu(null);
    if (mode === "globe") globeRef.current?.reset(); else setView({ s: 1, tx: 0, ty: 0 });
  };
  const zoomCentre = (f: number) => {
    if (mode === "globe") { globeRef.current?.zoomBy(f); setMenu(null); return; }
    const r = wrapRef.current?.getBoundingClientRect();
    if (r) zoomAt(f, (r.left + r.right) / 2, (r.top + r.bottom) / 2);
  };
  const onGlobePick = (p: GlobePick) => setMenu({
    code: p.code, name: nameFor(p.code), flag: flagFor(p.code), n: data[p.code] ?? 0, ox: p.x, oy: p.y,
  });
  const globeLabel = `Globe of blocked requests by origin. ${ranked.length
    ? "Top origins: " + ranked.slice(0, 3).map(([c, n]) => `${nameFor(c)} ${n.toLocaleString()}`).join(", ") + "."
    : "No country-attributed traffic yet."} Arrow keys turn it, plus and minus zoom, Enter acts on the country in the centre.`;
  // Menus open above the point, or below it when the point is near the top edge.
  const menuBelow = (menu?.oy ?? 0) < 150;
  const points = Object.entries(data).filter(([c, n]) => n > 0 && POS_BY_CODE[c])
    .map(([c, n]) => ({ ...POS_BY_CODE[c], n })).sort((a, b) => a.n - b.n);

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1.7fr 1fr", gap: 16, alignItems: "stretch" }}>
      {/* ── map ── */}
      <div ref={wrapRef} onPointerDown={() => setMenu(null)}
        onKeyDown={(e) => { if (e.key === "Escape") setMenu(null); }}
        className={mode === "globe" ? "geo-well" : undefined}
        style={{
          position: "relative", borderRadius: 10, overflow: "hidden",
          // The globe turns on horizontal drags only, so a phone can still scroll the page.
          touchAction: mode === "globe" ? "pan-y" : "none",
          background: mode === "flat" ? "var(--inset-bg)" : undefined,
          border: "1px solid var(--card-bd)", userSelect: "none",
          cursor: mode === "flat" ? (pan.current.active ? "grabbing" : "grab") : undefined,
        }}>
        {mode === "globe" ? (
          <div className="geo-globe">
            <Globe ref={globeRef} data={loaded ? data : NO_DATA} blocked={blocked} hover={hover} paused={!!menu}
              onHover={setHover} onPick={onGlobePick} onInteract={() => setMenu(null)} label={globeLabel} />
          </div>
        ) : (
        <svg viewBox={`0 0 ${VB_W} ${VB_H}`} width="100%" style={{ display: "block" }}
          preserveAspectRatio="xMidYMid meet"
          onPointerDown={onPointerDown} onPointerMove={onPointerMove}
          onPointerUp={onPointerUp} onPointerLeave={onPointerUp}>
          <g transform={`translate(${view.tx} ${view.ty}) scale(${view.s})`}>
            {/* graticule */}
            <g style={{ stroke: "var(--sep-row)" }} strokeWidth={0.6 / view.s}>
              {[155, 310, 465].map(y => <line key={y} x1={0} y1={y} x2={VB_W} y2={y} />)}
              {[238, 475, 712].map(x => <line key={x} x1={x} y1={0} x2={x} y2={VB_H} />)}
            </g>
            {/* land */}
            <path d={WORLD_PATH} style={{ fill: "var(--fill-h)", stroke: "var(--sep)" }}
              strokeWidth={0.5 / view.s} />

            {/* threat heat */}
            {loaded && points.map(p => {
              const r = radius(p.n), top = p.n === max;
              return (
                <g key={"t" + p.code} style={{ pointerEvents: "none" }}>
                  <circle cx={p.x} cy={p.y} r={top ? r * 2.2 : r * 1.9} style={{ fill: "var(--red-t)" }} />
                  <circle cx={p.x} cy={p.y} r={r} style={{ fill: "var(--red)" }} />
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
                    <circle cx={p.x} cy={p.y} r={9} fill="none" style={{ stroke: "var(--amber)" }}
                      strokeWidth={1.6 / view.s} strokeDasharray={`${3/view.s} ${2/view.s}`} />
                  )}
                  {isHover && <circle cx={p.x} cy={p.y} r={7} fill="none" style={{ stroke: "var(--cyan)" }} strokeWidth={1.2 / view.s} />}
                  {/* generous transparent hit target */}
                  <circle cx={p.x} cy={p.y} r={10} fill="transparent" />
                </g>
              );
            })}
          </g>
        </svg>
        )}

        {/* view switch + zoom */}
        <div style={{ position: "absolute", top: 8, left: 8, display: "flex", flexDirection: "column", alignItems: "flex-start", gap: 6, zIndex: 2 }}
          onPointerDown={(e) => e.stopPropagation()}>
          <div className="geo-ctl" role="group" aria-label="Map view">
            {(["globe", "flat"] as const).map(m => (
              <button key={m} type="button" aria-pressed={mode === m} onClick={() => setMode(m)}>
                {m === "globe" ? "Globe" : "Flat"}
              </button>
            ))}
          </div>
          <div className="geo-ctl col" role="group" aria-label="Zoom">
            <button type="button" aria-label="Zoom in" title="Zoom in" onClick={() => zoomCentre(1.4)}>+</button>
            <button type="button" aria-label="Zoom out" title="Zoom out" onClick={() => zoomCentre(1 / 1.4)}>−</button>
            <button type="button" aria-label="Reset view" title="Reset view" onClick={reset}>
              <svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M2.5 8a5.5 5.5 0 1 0 1.7-4" /><path d="M2.5 2.5v3h3" />
              </svg>
            </button>
          </div>
        </div>

        {/* hover readout */}
        <div className="geo-callout" aria-live="polite" style={{
          position: "absolute", top: 8, right: 8, zIndex: 2,
          opacity: hover ? 1 : 0.7, transition: "opacity var(--t) var(--ease)", pointerEvents: "none",
          maxWidth: "min(240px, calc(100% - 136px))",   // never over the view switch on a phone
        }}>
          {hover ? (
            <>
              <span>{flagFor(hover)} </span><span style={{ color: "var(--text)" }}>{nameFor(hover)}</span>
              <span style={{ fontVariantNumeric: "tabular-nums" }}> · {(data[hover] ?? 0).toLocaleString()}</span>
              {blocked.has(hover) && <span style={{ color: "var(--amber)" }}> · Blocked</span>}
            </>
          ) : mode === "globe" ? "Drag to turn · click a country" : "Click a country to act"}
        </div>

        {/* context menu */}
        {menu && (
          // The map closes its menu on any pointer-down. Without this the menu's own
          // button press closed the menu before its click landed, so "Block this
          // country" had never worked from the map (since 183da31, 2026-06-25).
          <div onPointerDown={(e) => e.stopPropagation()} onClick={(e) => e.stopPropagation()} style={{
            position: "absolute", left: clamp(menu.ox, 112, (wrapRef.current?.clientWidth ?? 400) - 112),
            top: menuBelow ? menu.oy + 14 : menu.oy - 12, transform: menuBelow ? "translate(-50%, 0)" : "translate(-50%, -100%)",
            background: "var(--elev)", border: "1px solid var(--card-bd)", borderRadius: 10,
            boxShadow: "var(--shadow-pop)", padding: 10, width: 210, zIndex: 20,
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
              <span style={{ fontSize: 18 }}>{menu.flag}</span>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 15, color: "var(--text)", fontWeight: 600 }}>{menu.name}</div>
                <div style={{ fontSize: 13, color: "var(--text3)", fontFamily: "var(--font-sans)" }}>
                  {menu.n > 0 ? `${menu.n.toLocaleString()} blocked requests` : "no blocked traffic"}
                </div>
              </div>
            </div>
            <button disabled={busy === menu.code} onClick={() => toggleBlock(menu.code, menu.name)}
              style={{
                width: "100%", padding: "7px 10px", borderRadius: 7, cursor: "pointer", fontSize: 14, fontWeight: 600,
                border: "1px solid transparent",
                background: blocked.has(menu.code) ? "var(--green-t)" : "var(--red-t)",
                color: blocked.has(menu.code) ? "var(--green)" : "var(--red-b)",
              }}>
              {busy === menu.code ? "…" : blocked.has(menu.code) ? "Unblock this country" : "Block this country"}
            </button>
            {!loaded && (
              <div style={{ fontSize: 12, color: "var(--text3)", marginTop: 6, lineHeight: 1.4, fontFamily: "var(--font-sans)" }}>
                {dbPresent === false ? "Stored now — enforces once the country database is downloaded (System Jobs → geoip.refresh)." : "Stored — applies within about 5 seconds."}
              </div>
            )}
          </div>
        )}

        {loaded && (
          <div style={{ position: "absolute", right: 10, bottom: 6, fontSize: 10, color: "var(--text3)", fontFamily: "var(--font-sans)", pointerEvents: "auto" }}>
            IP Geolocation by <a href="https://db-ip.com" target="_blank" rel="noreferrer" style={{ color: "var(--text3)" }}>DB-IP</a>
          </div>
        )}
        {/* not-loaded note */}
        {!loaded && !menu && (
          <div style={{
            position: "absolute", left: 0, right: 0, bottom: 0, padding: "9px 12px",
            display: "flex", alignItems: "center", gap: 10, justifyContent: "center",
            background: "linear-gradient(0deg, var(--card) 35%, transparent)", textAlign: "center", pointerEvents: "none",
          }}>
            <span style={{ fontSize: 13, color: "var(--text3)", lineHeight: 1.5, fontFamily: "var(--font-sans)" }}>
              {/* `loaded` means "there are country-attributed events to draw", which
                  is NOT the same as "the database is missing". Saying the latter
                  when the database is sitting there loaded sends an operator to
                  re-run a job that already worked — and the usual real reason for
                  an empty map is that the traffic came from private addresses,
                  which have no country in any database. */}
              {dbPresent === false ? (
                <>Country database not loaded yet — the <span style={{ color: "var(--cyan)" }}>geoip.refresh</span> job downloads it (System Jobs → Run now), or set <span style={{ color: "var(--cyan)" }}>SENTINEL_GEOIP_DB</span> to your own .mmdb.</>
              ) : dbPresent === true ? (
                <>Country database loaded. No country-attributed traffic yet — requests from private or loopback addresses (10.x, 172.16–31.x, 192.168.x, 127.x) have no country in any database, so they cannot appear here.</>
              ) : (
                // Unknown is a third state, not a synonym for "loaded". The first
                // version collapsed undefined into the loaded branch — right on .71
                // by accident, and a lie anywhere the data plane was unreachable.
                <>No country-attributed traffic yet. Database state unknown — the data plane did not report it.</>
              )}
            </span>
          </div>
        )}
      </div>

      {/* ── ranked list ── */}
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        <div style={{ fontSize: 14, color: "var(--text3)", fontFamily: "var(--font-sans)" }}>
          Top origins {loaded && totalCountries > 0 ? `(${totalCountries})` : ""}
          {blocked.size > 0 && <span style={{ color: "var(--amber)" }}> · {blocked.size} blocked</span>}
        </div>
        {ranked.length === 0 ? (
          <div style={{ fontSize: 14, color: "var(--text3)", fontFamily: "var(--font-sans)", padding: "8px 0" }}>
            {loaded ? "No blocked traffic yet" : "No country-attributed events yet"}
          </div>
        ) : ranked.map(([code, n]) => (
          // On the globe a row turns the globe to its country; hovering lights it up there.
          <div key={code} className={`geo-row${mode === "globe" ? " live" : ""}${hover === code ? " on" : ""}`}
            style={{ display: "flex", alignItems: "center", gap: 8 }}
            role={mode === "globe" ? "button" : undefined} tabIndex={mode === "globe" ? 0 : undefined}
            aria-label={mode === "globe" ? `Show ${nameFor(code)} on the globe` : undefined}
            onMouseEnter={() => setHover(code)} onMouseLeave={() => setHover(null)}
            onClick={() => { if (mode === "globe") { setMenu(null); globeRef.current?.focus(code); } }}
            onKeyDown={(e) => { if (mode === "globe" && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); globeRef.current?.focus(code); setHover(code); } }}>
            <span style={{ fontSize: 16 }}>{flagFor(code)}</span>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 14, color: "var(--text2)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                {nameFor(code)}{blocked.has(code) && <span style={{ color: "var(--amber)", marginLeft: 6, fontSize: 12, fontWeight: 600 }}>Blocked</span>}
              </div>
              <div style={{ height: 5, background: "var(--track)", borderRadius: 3, marginTop: 3, overflow: "hidden" }}>
                <div style={{ height: "100%", width: `${(n / max) * 100}%`, background: "var(--red)", borderRadius: 3 }} />
              </div>
            </div>
            <span style={{ fontSize: 14, color: "var(--text)", fontFamily: "var(--font-sans)", fontVariantNumeric: "tabular-nums" }}>{n.toLocaleString()}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
