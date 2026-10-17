"use client";
/**
 * Globe — the 3D view of "Blocked requests by origin".
 *
 * Canvas 2D with an orthographic projection: no WebGL, no new dependency and no
 * map data fetched at runtime. Land is ~5,300 baked dots (lib/globeData.ts,
 * Natural Earth, public domain, India point of view), so an air-gapped console
 * draws exactly what an internet-connected one does.
 *
 * What it shows, and only that:
 *  • land as an even dot grid. A country with blocked traffic tints its own dots
 *    red, stronger with more traffic (square root of its share of the top count);
 *  • a column at each such country's label point, its height on a log scale so
 *    a country with a handful of requests still shows up;
 *  • the three loudest origins pulse (never under reduced motion);
 *  • blocked countries turn amber with a dashed ring, whether or not they sent
 *    traffic in the window;
 *  • the hovered country (here or in the list beside it) lights up in the accent.
 *  There are deliberately no attack arcs. Arcs need a destination, and the console
 *  does not know where the protected site physically is. An arc to an invented
 *  "home" would draw a fact nothing measured.
 *
 * Interaction: drag to turn (with momentum), scroll or the buttons to zoom, click
 * a country to act on it. Keyboard: arrows turn and tilt, + and − zoom, 0 resets,
 * Enter acts on the country under the centre. It turns slowly on its own while
 * nobody is pointing at it, and never when the OS asks for reduced motion.
 */
import { forwardRef, useEffect, useImperativeHandle, useRef } from "react";
import { GLOBE_STEP, GLOBE_ROW_N, GLOBE_ROWS, GLOBE_CODES, GLOBE_LABELS } from "@/lib/globeData";

const RAD = Math.PI / 180;
const TAU = Math.PI * 2;
const clamp = (v: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, v));
/** Wrap a longitude into [-180, 180). */
const wrapLon = (l: number) => ((((l + 180) % 360) + 360) % 360) - 180;

/** Where the globe faces before any data arrives: South Asia, where the console is
 *  sold. It is only a camera position; nothing is drawn there because of it. */
const HOME = { lam: 78, phi: 18 };
const ZOOM_MIN = 0.8, ZOOM_MAX = 3;
const SPIN_DEG_PER_MS = 0.003;   // 3°/s, one turn in two minutes: alive, never busy
const SPIN_IDLE_MS = 2500;       // resume turning this long after the pointer leaves
const MOMENTUM_TAU_MS = 320;     // drag momentum decays with this time constant

// ── Decoded dataset ─────────────────────────────────────────────────────────
// Decoded once per page load: unit vectors for every land dot, plus a full
// band-by-band lookup (sea included) so a pointer position resolves to a country
// without searching polygons.
interface Dots {
  n: number;
  x: Float32Array; y: Float32Array; z: Float32Array;
  code: Int16Array;          // index into GLOBE_CODES
  rowStart: Int32Array;      // offset of band i in `grid`
  grid: Int16Array;          // every grid cell, land or sea: code index or -1
}
let DOTS: Dots | null = null;
function dots(): Dots {
  if (DOTS) return DOTS;
  const rows = GLOBE_ROWS.length;
  const rowStart = new Int32Array(rows);
  let cells = 0, land = 0;
  for (let i = 0; i < rows; i++) {
    rowStart[i] = cells; cells += GLOBE_ROW_N[i];
    const r = GLOBE_ROWS[i];
    for (let k = 1; k < r.length; k += 3) land += r[k];
  }
  const grid = new Int16Array(cells).fill(-1);
  const x = new Float32Array(land), y = new Float32Array(land), z = new Float32Array(land);
  const code = new Int16Array(land);
  let d = 0;
  for (let i = 0; i < rows; i++) {
    const lat = (-90 + (i + 0.5) * GLOBE_STEP) * RAD;
    const cl = Math.cos(lat), sl = Math.sin(lat), n = GLOBE_ROW_N[i];
    const r = GLOBE_ROWS[i];
    for (let k = 0; k < r.length; k += 3) {
      for (let j = r[k]; j < r[k] + r[k + 1]; j++) {
        const lon = (-180 + ((j + 0.5) * 360) / n) * RAD;
        x[d] = cl * Math.sin(lon); y[d] = sl; z[d] = cl * Math.cos(lon);
        code[d] = r[k + 2]; grid[rowStart[i] + j] = r[k + 2];
        d++;
      }
    }
  }
  DOTS = { n: land, x, y, z, code, rowStart, grid };
  return DOTS;
}
const CODE_INDEX = new Map(GLOBE_CODES.map((c, i) => [c, i] as const));

/** The country whose grid cell contains (lat, lon), or null over sea. */
export function countryAt(latDeg: number, lonDeg: number): string | null {
  const D = dots();
  const i = clamp(Math.floor((latDeg + 90) / GLOBE_STEP), 0, GLOBE_ROW_N.length - 1);
  const n = GLOBE_ROW_N[i];
  const j = clamp(Math.floor(((wrapLon(lonDeg) + 180) / 360) * n), 0, n - 1);
  const c = D.grid[D.rowStart[i] + j];
  return c >= 0 && GLOBE_CODES[c] ? GLOBE_CODES[c] : null;
}

// ── Colour helpers (a canvas cannot resolve CSS variables itself) ──────────
type RGBA = [number, number, number, number];
function parseColor(c: string): RGBA {
  const s = c.trim();
  if (s.startsWith("#")) {
    const h = s.slice(1);
    const f = h.length === 3 ? h.split("").map(ch => ch + ch).join("") : h.slice(0, 6);
    const a = h.length === 8 ? parseInt(h.slice(6, 8), 16) / 255 : 1;
    return [parseInt(f.slice(0, 2), 16), parseInt(f.slice(2, 4), 16), parseInt(f.slice(4, 6), 16), a];
  }
  const m = s.match(/rgba?\(([^)]+)\)/);
  if (m) {
    const p = m[1].split(/[\s,/]+/).filter(Boolean).map(Number);
    return [p[0] || 0, p[1] || 0, p[2] || 0, p.length > 3 ? p[3] : 1];
  }
  return [128, 128, 128, 1];
}
/** Same colour, new alpha. Gradient stops fade to this rather than to transparent
 *  black, which would drag a grey fringe through every fade. */
const withAlpha = (c: RGBA, a: number) => `rgba(${c[0]},${c[1]},${c[2]},${clamp(a, 0, 1)})`;

interface Palette {
  hi: string; mid: string; lo: string; rim: string;
  dot: string; red: RGBA; amber: string; accent: string;
  glow: RGBA; shadow: RGBA; well: string; dark: boolean;
}
function readPalette(): Palette {
  const cs = getComputedStyle(document.documentElement);
  const v = (name: string, fb: string) => cs.getPropertyValue(name).trim() || fb;
  return {
    hi: v("--globe-hi", "#3a3a3e"), mid: v("--globe-mid", "#1d1d20"), lo: v("--globe-lo", "#08080a"),
    rim: v("--globe-rim", "rgba(255,255,255,0.12)"), dot: v("--globe-dot", "#ebebf5"),
    red: parseColor(v("--red", "#ff453a")), amber: v("--amber", "#ff9f0a"), accent: v("--cyan", "#409cff"),
    glow: parseColor(v("--globe-glow", "rgba(64,156,255,0.16)")),
    shadow: parseColor(v("--globe-shadow", "rgba(0,0,0,0)")),
    well: v("--globe-well-lo", "#0d0d0f"),
    dark: document.documentElement.getAttribute("data-theme") !== "light",
  };
}

// ── Public surface ─────────────────────────────────────────────────────────
export interface GlobePick { code: string; x: number; y: number }
export interface GlobeHandle {
  /** Turn the globe until this country faces the viewer. */
  focus(code: string): void;
  zoomBy(factor: number): void;
  reset(): void;
}
interface Props {
  data: Record<string, number>;
  blocked: Set<string>;
  hover: string | null;
  /** The menu is open: hold still so it stays next to the country it is about. */
  paused: boolean;
  onHover(code: string | null): void;
  onPick(p: GlobePick): void;
  /** Any drag, zoom or key press — the parent closes its menu. */
  onInteract(): void;
  label: string;
}

interface Marker { code: string; bx: number; by: number; tx: number; ty: number; z: number }

const Globe = forwardRef<GlobeHandle, Props>(function Globe(props, ref) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  // Everything the animation loop reads lives in one mutable record so the loop,
  // the DOM listeners and React renders never disagree about the current view.
  const s = useRef({
    lam: HOME.lam, phi: HOME.phi, zoom: 1,
    vLam: 0, vPhi: 0,
    drag: null as null | { id: number; x0: number; y0: number; lam0: number; phi0: number; moved: boolean; lx: number; ly: number; lt: number },
    fly: null as null | { t0: number; dur: number; lam0: number; phi0: number; z0: number; dLam: number; dPhi: number; dZ: number },
    over: false, lastInteract: -Infinity, centredOnData: false,
    w: 0, h: 0, dpr: 1, visible: true, reduced: false,
    pal: null as Palette | null,
    // mirrored props
    paused: false, hoverIdx: -2, hoverCode: null as string | null,
    heat: new Float32Array(GLOBE_CODES.length), blockedIdx: new Uint8Array(GLOBE_CODES.length),
    blockedCodes: [] as string[],
    origins: [] as { code: string; t: number; lat: number; lon: number }[],
    loud: [] as string[],
    markers: [] as Marker[],
    raf: 0, lastT: 0,
    // scratch buffers, reused every frame
    sx: new Float32Array(0), sy: new Float32Array(0), key: new Uint8Array(0), order: new Uint16Array(0),
  });
  const cb = useRef(props);
  cb.current = props;

  // ── geometry ──
  const radius = () => Math.min(s.current.w, s.current.h) * 0.4 * s.current.zoom;
  /** Rotate a unit vector into view space: x right, y up, z toward the viewer. */
  function rot(x: number, y: number, z: number, out: Float64Array) {
    const st = s.current;
    const cl = Math.cos(st.lam * RAD), sl = Math.sin(st.lam * RAD);
    const cp = Math.cos(st.phi * RAD), sp = Math.sin(st.phi * RAD);
    const x1 = x * cl - z * sl, z1 = x * sl + z * cl;
    out[0] = x1; out[1] = y * cp - z1 * sp; out[2] = y * sp + z1 * cp;
  }
  function unit(latDeg: number, lonDeg: number): [number, number, number] {
    const la = latDeg * RAD, lo = lonDeg * RAD;
    return [Math.cos(la) * Math.sin(lo), Math.sin(la), Math.cos(la) * Math.cos(lo)];
  }
  /** Screen point (CSS px) → [lat, lon], or null off the sphere. */
  function unproject(px: number, py: number): [number, number] | null {
    const st = s.current, R = radius();
    const x1 = (px - st.w / 2) / R, y2 = -(py - st.h / 2) / R;
    const q = x1 * x1 + y2 * y2;
    if (q > 1) return null;
    const z2 = Math.sqrt(1 - q);
    const cl = Math.cos(st.lam * RAD), sl = Math.sin(st.lam * RAD);
    const cp = Math.cos(st.phi * RAD), sp = Math.sin(st.phi * RAD);
    const y = y2 * cp + z2 * sp, z1 = -y2 * sp + z2 * cp;
    const x = x1 * cl + z1 * sl, z = -x1 * sl + z1 * cl;
    return [Math.asin(clamp(y, -1, 1)) / RAD, Math.atan2(x, z) / RAD];
  }
  /** The country under a screen point: a column or ring first (small countries
   *  have no dots of their own), then the land cell. */
  function pick(px: number, py: number): string | null {
    const st = s.current;
    let best: string | null = null, bestD = 14 * 14;
    for (const m of st.markers) {
      const d1 = (m.tx - px) ** 2 + (m.ty - py) ** 2;
      const d2 = (m.bx - px) ** 2 + (m.by - py) ** 2;
      const d = Math.min(d1, d2);
      if (d < bestD) { bestD = d; best = m.code; }
    }
    if (best) return best;
    const ll = unproject(px, py);
    return ll ? countryAt(ll[0], ll[1]) : null;
  }

  // ── drawing ──
  function draw(t: number) {
    const cv = canvasRef.current, st = s.current;
    if (!cv || !st.w || !st.h) return;
    const ctx = cv.getContext("2d");
    if (!ctx) return;
    if (!st.pal) st.pal = readPalette();
    const P = st.pal;
    const D = dots();
    const { w, h, dpr } = st;
    const R = radius(), cx = w / 2, cy = h / 2;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);

    // Atmosphere: a narrow halo just outside the limb.
    if (P.glow[3] > 0) {
      const g = ctx.createRadialGradient(cx, cy, R * 0.985, cx, cy, R * 1.2);
      g.addColorStop(0, withAlpha(P.glow, P.glow[3]));
      g.addColorStop(1, withAlpha(P.glow, 0));
      ctx.fillStyle = g;
      ctx.beginPath(); ctx.arc(cx, cy, R * 1.2, 0, TAU); ctx.fill();
    }
    // Contact shadow (light theme): the sphere sits on the page.
    if (P.shadow[3] > 0) {
      ctx.save();
      ctx.shadowColor = withAlpha(P.shadow, P.shadow[3]);
      ctx.shadowBlur = R * 0.22 * dpr;      // shadow metrics ignore the transform
      ctx.shadowOffsetY = R * 0.06 * dpr;
      ctx.fillStyle = P.mid;
      ctx.beginPath(); ctx.arc(cx, cy, R, 0, TAU); ctx.fill();
      ctx.restore();
    }
    // The sphere, lit from the upper left.
    const sg = ctx.createRadialGradient(cx - R * 0.36, cy - R * 0.42, R * 0.04, cx - R * 0.12, cy - R * 0.14, R * 1.22);
    sg.addColorStop(0, P.hi); sg.addColorStop(0.5, P.mid); sg.addColorStop(1, P.lo);
    ctx.fillStyle = sg;
    ctx.beginPath(); ctx.arc(cx, cy, R, 0, TAU); ctx.fill();

    // ── land dots ──
    if (st.sx.length !== D.n) {
      st.sx = new Float32Array(D.n); st.sy = new Float32Array(D.n);
      st.key = new Uint8Array(D.n); st.order = new Uint16Array(D.n);
    }
    const cl = Math.cos(st.lam * RAD), sl = Math.sin(st.lam * RAD);
    const cp = Math.cos(st.phi * RAD), sp = Math.sin(st.phi * RAD);
    // key = class * 8 + depth level. Class 0 land, 1–4 heat, 5 blocked, 6 hover,
    // 7 the far side (seen faintly through the sphere). Depth 0–7 = limb → centre.
    const counts = new Int32Array(64);
    for (let i = 0; i < D.n; i++) {
      const x = D.x[i], y = D.y[i], z = D.z[i];
      const x1 = x * cl - z * sl, z1 = x * sl + z * cl;
      const y2 = y * cp - z1 * sp, z2 = y * sp + z1 * cp;
      st.sx[i] = cx + R * x1; st.sy[i] = cy - R * y2;
      let k: number;
      if (z2 <= 0) k = 7 * 8;
      else {
        const lvl = Math.min(7, (z2 * 8) | 0);
        const c = D.code[i];
        const cls = c === st.hoverIdx ? 6 : st.blockedIdx[c] ? 5 : st.heat[c] > 0 ? 1 + Math.min(3, (st.heat[c] * 4) | 0) : 0;
        k = cls * 8 + lvl;
      }
      st.key[i] = k; counts[k]++;
    }
    const offs = new Int32Array(65);
    for (let k = 0; k < 64; k++) offs[k + 1] = offs[k] + counts[k];
    const fill = offs.slice(0, 64);
    for (let i = 0; i < D.n; i++) st.order[fill[st.key[i]]++] = i;

    const dotR = Math.max(0.55, R * GLOBE_STEP * RAD * 0.28);
    const drawKey = (k: number) => {
      const a = offs[k], b = offs[k + 1];
      if (a === b) return;
      const cls = k >> 3, lvl = k & 7;
      const depth = (lvl + 0.5) / 8;                 // ≈ z of this bucket
      const r = cls === 7 ? dotR * 0.8 : dotR * (0.62 + 0.38 * depth);
      let alpha: number;
      if (cls === 7) { ctx.fillStyle = P.dot; alpha = P.dark ? 0.07 : 0.06; }
      else if (cls === 0) { ctx.fillStyle = P.dot; alpha = (P.dark ? 0.14 : 0.12) + (P.dark ? 0.5 : 0.44) * depth; }
      else if (cls <= 4) { ctx.fillStyle = withAlpha(P.red, 1); alpha = (0.35 + 0.65 * depth) * [0, 0.3, 0.52, 0.76, 1][cls]; }
      else if (cls === 5) { ctx.fillStyle = P.amber; alpha = 0.35 + 0.65 * depth; }
      else { ctx.fillStyle = P.accent; alpha = 0.45 + 0.55 * depth; }
      ctx.globalAlpha = alpha;
      ctx.beginPath();
      for (let o = a; o < b; o++) {
        const i = st.order[o];
        ctx.moveTo(st.sx[i] + r, st.sy[i]);
        ctx.arc(st.sx[i], st.sy[i], r, 0, TAU);
      }
      ctx.fill();
    };
    drawKey(7 * 8);                                   // far side first
    for (let cls = 0; cls < 7; cls++) for (let lvl = 0; lvl < 8; lvl++) drawKey(cls * 8 + lvl);
    ctx.globalAlpha = 1;

    // Rim: a hairline keeps the limb crisp against the well.
    ctx.strokeStyle = P.rim; ctx.lineWidth = 1;
    ctx.beginPath(); ctx.arc(cx, cy, R - 0.5, 0, TAU); ctx.stroke();

    // ── rings on the surface (blocked, hover, pulse) ──
    const v = new Float64Array(3);
    const ring = (lat: number, lon: number, rhoDeg: number) => {
      const [x, y, z] = unit(lat, lon);
      const la = lat * RAD, lo = lon * RAD;
      const ex = Math.cos(lo), ez = -Math.sin(lo);                                 // east
      const nx = -Math.sin(la) * Math.sin(lo), ny = Math.cos(la), nz = -Math.sin(la) * Math.cos(lo); // north
      const cr = Math.cos(rhoDeg * RAD), sr = Math.sin(rhoDeg * RAD);
      ctx.beginPath();
      let pen = false;
      for (let k = 0; k <= 48; k++) {
        const th = (k / 48) * TAU, c = Math.cos(th), si = Math.sin(th);
        rot(x * cr + (ex * c + nx * si) * sr, y * cr + ny * si * sr, z * cr + (ez * c + nz * si) * sr, v);
        if (v[2] <= 0) { pen = false; continue; }
        const px = cx + R * v[0], py = cy - R * v[1];
        if (pen) ctx.lineTo(px, py); else { ctx.moveTo(px, py); pen = true; }
      }
      ctx.stroke();
    };
    ctx.lineCap = "round";
    if (st.blockedCodes.length) {
      ctx.strokeStyle = P.amber; ctx.lineWidth = 1.4; ctx.setLineDash([3, 2.5]);
      for (const c of st.blockedCodes) { const l = GLOBE_LABELS[c]; if (l) ring(l[0], l[1], 2.6); }
      ctx.setLineDash([]);
    }
    const animate = !st.reduced;
    if (animate && st.loud.length) {
      ctx.strokeStyle = withAlpha(P.red, 1); ctx.lineWidth = 1.5;
      st.loud.forEach((c, n) => {
        const l = GLOBE_LABELS[c];
        if (!l) return;
        const ph = ((t / 2600) + n / 3) % 1;
        const e = 1 - (1 - ph) ** 3;
        ctx.globalAlpha = 0.55 * (1 - ph);
        ring(l[0], l[1], 0.8 + 6 * e);
      });
      ctx.globalAlpha = 1;
    }

    // ── columns ──
    const ms: Marker[] = [];
    for (const o of st.origins) {
      const [x, y, z] = unit(o.lat, o.lon);
      rot(x, y, z, v);
      if (v[2] <= 0.02) continue;
      const hgt = 0.045 + 0.2 * o.t;
      ms.push({ code: o.code, bx: cx + R * v[0], by: cy - R * v[1], tx: cx + R * (1 + hgt) * v[0], ty: cy - R * (1 + hgt) * v[1], z: v[2] });
    }
    ms.sort((a, b) => a.z - b.z);                    // far columns first
    const lw = Math.max(1.6, R * 0.011), capR = Math.max(2, R * 0.016);
    for (const m of ms) {
      const fade = clamp((m.z - 0.03) * 4, 0, 1);         // columns ease out at the limb
      const hot = m.code === st.hoverCode;
      const g = ctx.createLinearGradient(m.bx, m.by, m.tx, m.ty);
      g.addColorStop(0, withAlpha(P.red, 0.12 * fade));
      g.addColorStop(1, withAlpha(P.red, 0.95 * fade));
      ctx.strokeStyle = g; ctx.lineWidth = hot ? lw * 1.4 : lw;
      ctx.beginPath(); ctx.moveTo(m.bx, m.by); ctx.lineTo(m.tx, m.ty); ctx.stroke();
      ctx.globalAlpha = fade;
      ctx.fillStyle = withAlpha(P.red, 1);
      ctx.beginPath(); ctx.arc(m.tx, m.ty, hot ? capR * 1.45 : capR, 0, TAU); ctx.fill();
      ctx.strokeStyle = hot ? P.accent : P.well; ctx.lineWidth = hot ? 1.5 : 1;
      ctx.stroke();
      ctx.globalAlpha = 1;
    }
    st.markers = ms;

    // Hovered country with no dots of its own (Singapore, Bahrain…): ring it.
    if (st.hoverCode) {
      const l = GLOBE_LABELS[st.hoverCode];
      if (l) { ctx.strokeStyle = P.accent; ctx.lineWidth = 1.6; ring(l[0], l[1], 3.2); }
    }
  }

  // ── animation loop ──
  function wantsFrames() {
    const st = s.current;
    if (!st.visible) return false;
    if (st.drag || st.fly || Math.abs(st.vLam) + Math.abs(st.vPhi) > 0) return true;
    if (st.reduced) return false;
    return !st.paused && !st.over ? true : st.loud.length > 0;
  }
  function frame(t: number) {
    const st = s.current;
    st.raf = 0;
    const dt = st.lastT ? Math.min(50, t - st.lastT) : 16;
    st.lastT = t;
    if (st.fly) {
      const f = st.fly, p = clamp((t - f.t0) / f.dur, 0, 1);
      const e = p < 0.5 ? 4 * p * p * p : 1 - (-2 * p + 2) ** 3 / 2;       // ease in-out
      st.lam = wrapLon(f.lam0 + f.dLam * e); st.phi = f.phi0 + f.dPhi * e; st.zoom = f.z0 + f.dZ * e;
      if (p >= 1) st.fly = null;
    } else if (!st.drag) {
      if (st.vLam || st.vPhi) {
        st.lam = wrapLon(st.lam + st.vLam * dt);
        st.phi = clamp(st.phi + st.vPhi * dt, -70, 70);
        const k = Math.exp(-dt / MOMENTUM_TAU_MS);
        st.vLam *= k; st.vPhi *= k;
        if (Math.abs(st.vLam) < 0.0004) st.vLam = 0;
        if (Math.abs(st.vPhi) < 0.0004) st.vPhi = 0;
      } else if (!st.reduced && !st.paused && !st.over && performance.now() - st.lastInteract > SPIN_IDLE_MS) {
        st.lam = wrapLon(st.lam - SPIN_DEG_PER_MS * dt);                // west → east, as the Earth turns
      }
    }
    draw(t);
    if (wantsFrames()) st.raf = requestAnimationFrame(frame);
    else st.lastT = 0;
  }
  function kick() {
    const st = s.current;
    if (!st.raf && st.visible) st.raf = requestAnimationFrame(frame);
  }
  function flyTo(lam: number, phi: number, zoom: number, dur = 900) {
    const st = s.current;
    st.vLam = st.vPhi = 0;
    const dLam = wrapLon(lam - st.lam);
    if (st.reduced) { st.lam = wrapLon(lam); st.phi = phi; st.zoom = zoom; st.fly = null; kick(); return; }
    st.fly = { t0: performance.now(), dur, lam0: st.lam, phi0: st.phi, z0: st.zoom, dLam, dPhi: phi - st.phi, dZ: zoom - st.zoom };
    kick();
  }

  useImperativeHandle(ref, () => ({
    focus(code: string) {
      const l = GLOBE_LABELS[code];
      if (!l) return;
      s.current.lastInteract = performance.now();
      flyTo(l[1], clamp(l[0], -50, 50), s.current.zoom);
    },
    zoomBy(f: number) {
      const st = s.current;
      st.lastInteract = performance.now();
      flyTo(st.lam, st.phi, clamp(st.zoom * f, ZOOM_MIN, ZOOM_MAX), 280);
    },
    reset() {
      const st = s.current;
      st.lastInteract = -Infinity;
      const top = st.origins.length ? st.origins.reduce((a, b) => (b.t > a.t ? b : a)) : null;
      flyTo(top ? top.lon : HOME.lam, top ? clamp(top.lat, -40, 40) : HOME.phi, 1);
    },
  }));

  // ── mirror props into the loop's record ──
  useEffect(() => {
    const st = s.current;
    const entries = Object.entries(props.data).filter(([, n]) => n > 0);
    const max = Math.max(1, ...entries.map(([, n]) => n));
    st.heat.fill(0);
    st.origins = [];
    for (const [code, n] of entries) {
      // Two scales on purpose. Dot tint uses the square root of the share, so the
      // top few origins stay distinguishable from each other; column height uses
      // a log scale, so a country with 30 requests still gets a visible column.
      const t = Math.log1p(n) / Math.log1p(max);
      const i = CODE_INDEX.get(code);
      if (i !== undefined) st.heat[i] = Math.max(0.06, Math.sqrt(n / max));
      const l = GLOBE_LABELS[code];
      if (l) st.origins.push({ code, t, lat: l[0], lon: l[1] });
    }
    st.loud = entries.sort((a, b) => b[1] - a[1]).slice(0, 3).map(([c]) => c).filter(c => GLOBE_LABELS[c]);
    // Face the loudest origin the first time there is data, unless the operator
    // has already turned the globe themselves.
    if (!st.centredOnData && st.loud.length && st.lastInteract === -Infinity) {
      st.centredOnData = true;
      const l = GLOBE_LABELS[st.loud[0]];
      flyTo(l[1], clamp(l[0], -40, 40), st.zoom, 1200);
    }
    kick();
  }, [props.data]);

  useEffect(() => {
    const st = s.current;
    st.blockedIdx.fill(0);
    st.blockedCodes = [...props.blocked];
    for (const c of props.blocked) { const i = CODE_INDEX.get(c); if (i !== undefined) st.blockedIdx[i] = 1; }
    kick();
  }, [props.blocked]);

  useEffect(() => {
    const st = s.current;
    st.hoverCode = props.hover;
    st.hoverIdx = props.hover ? CODE_INDEX.get(props.hover) ?? -2 : -2;
    kick();
  }, [props.hover]);

  useEffect(() => { s.current.paused = props.paused; kick(); }, [props.paused]);

  // ── DOM wiring: size, theme, motion preference, visibility, input ──
  useEffect(() => {
    const cv = canvasRef.current;
    if (!cv) return;
    const st = s.current;
    const box = cv.parentElement!;

    const resize = () => {
      const r = box.getBoundingClientRect();
      st.dpr = Math.min(2, window.devicePixelRatio || 1);
      st.w = r.width; st.h = r.height;
      cv.width = Math.round(r.width * st.dpr); cv.height = Math.round(r.height * st.dpr);
      draw(performance.now()); kick();
    };
    const ro = new ResizeObserver(resize);
    ro.observe(box); resize();

    const mo = new MutationObserver(() => { st.pal = readPalette(); draw(performance.now()); });
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme", "class"] });

    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    const onMq = () => { st.reduced = mq.matches; if (st.reduced) { st.vLam = st.vPhi = 0; } kick(); };
    onMq(); mq.addEventListener("change", onMq);
    const cq = window.matchMedia("(prefers-contrast: more)");
    const onCq = () => { st.pal = readPalette(); draw(performance.now()); };
    cq.addEventListener("change", onCq);

    // Stop drawing when nobody can see it: scrolled away or the tab is hidden.
    let inView = true;
    const sync = () => { st.visible = inView && !document.hidden; if (st.visible) kick(); };
    const io = new IntersectionObserver(es => { inView = es.some(e => e.isIntersecting); sync(); });
    io.observe(cv);
    document.addEventListener("visibilitychange", sync);

    const local = (e: { clientX: number; clientY: number }) => {
      const r = cv.getBoundingClientRect();
      return [e.clientX - r.left, e.clientY - r.top] as const;
    };
    const setCursor = (c: string) => { if (cv.style.cursor !== c) cv.style.cursor = c; };
    let lastHover: string | null = null;
    const hoverTo = (c: string | null) => { if (c !== lastHover) { lastHover = c; cb.current.onHover(c); } };

    const down = (e: PointerEvent) => {
      if (e.button !== 0) return;
      const [x, y] = local(e);
      st.drag = { id: e.pointerId, x0: x, y0: y, lam0: st.lam, phi0: st.phi, moved: false, lx: x, ly: y, lt: performance.now() };
      st.fly = null; st.vLam = st.vPhi = 0;
      st.lastInteract = performance.now();
      cv.setPointerCapture(e.pointerId);
      cb.current.onInteract();
      kick();
    };
    const move = (e: PointerEvent) => {
      const [x, y] = local(e);
      const d = st.drag;
      if (d && d.id === e.pointerId) {
        if (!d.moved && Math.abs(x - d.x0) + Math.abs(y - d.y0) > 4) { d.moved = true; hoverTo(null); }
        if (!d.moved) return;
        setCursor("grabbing");
        const R = radius();
        const lam = wrapLon(d.lam0 - ((x - d.x0) / R) / RAD);
        const phi = clamp(d.phi0 + ((y - d.y0) / R) / RAD, -70, 70);
        const now = performance.now(), dt = Math.max(1, now - d.lt);
        // Velocity in degrees per ms, smoothed so one jittery sample does not fling it.
        st.vLam = 0.7 * st.vLam + 0.3 * (wrapLon(lam - st.lam) / dt);
        st.vPhi = 0.7 * st.vPhi + 0.3 * ((phi - st.phi) / dt);
        st.lam = lam; st.phi = phi;
        d.lx = x; d.ly = y; d.lt = now;
        st.lastInteract = now;
        return;
      }
      const c = pick(x, y);
      hoverTo(c);
      setCursor(c ? "pointer" : "grab");
    };
    const up = (e: PointerEvent) => {
      const d = st.drag;
      if (!d || d.id !== e.pointerId) return;
      st.drag = null;
      st.lastInteract = performance.now();
      if (!d.moved) {
        st.vLam = st.vPhi = 0;
        const [x, y] = local(e);
        const c = pick(x, y);
        if (c) cb.current.onPick({ code: c, x, y });
      } else if (st.reduced || performance.now() - d.lt > 80) {
        st.vLam = st.vPhi = 0;                     // let go after holding still: no fling
      }
      setCursor("grab");
      kick();
    };
    const cancel = (e: PointerEvent) => {
      if (st.drag && st.drag.id === e.pointerId) { st.drag = null; st.vLam = st.vPhi = 0; kick(); }
    };
    const enter = () => { st.over = true; };
    const leave = () => { st.over = false; st.lastInteract = performance.now(); hoverTo(null); kick(); };
    const wheel = (e: WheelEvent) => {
      e.preventDefault();
      st.fly = null;
      st.zoom = clamp(st.zoom * (e.deltaY < 0 ? 1.1 : 1 / 1.1), ZOOM_MIN, ZOOM_MAX);
      st.lastInteract = performance.now();
      cb.current.onInteract();
      kick();
    };
    const key = (e: KeyboardEvent) => {
      const step = e.shiftKey ? 30 : 12;
      let handled = true;
      st.lastInteract = performance.now();
      switch (e.key) {
        case "ArrowLeft": flyTo(st.lam - step, st.phi, st.zoom, 320); break;
        case "ArrowRight": flyTo(st.lam + step, st.phi, st.zoom, 320); break;
        case "ArrowUp": flyTo(st.lam, clamp(st.phi + 8, -70, 70), st.zoom, 320); break;
        case "ArrowDown": flyTo(st.lam, clamp(st.phi - 8, -70, 70), st.zoom, 320); break;
        case "+": case "=": flyTo(st.lam, st.phi, clamp(st.zoom * 1.25, ZOOM_MIN, ZOOM_MAX), 240); break;
        case "-": case "_": flyTo(st.lam, st.phi, clamp(st.zoom / 1.25, ZOOM_MIN, ZOOM_MAX), 240); break;
        case "0": case "Home": flyTo(HOME.lam, HOME.phi, 1); break;
        case "Enter": case " ": {
          const c = pick(st.w / 2, st.h / 2);
          if (c) { cb.current.onHover(c); cb.current.onPick({ code: c, x: st.w / 2, y: st.h / 2 }); }
          break;
        }
        case "Escape": handled = false; break;
        default: handled = false;
      }
      if (handled) { e.preventDefault(); if (e.key !== "Enter" && e.key !== " ") cb.current.onInteract(); }
    };
    cv.addEventListener("pointerdown", down);
    cv.addEventListener("pointermove", move);
    cv.addEventListener("pointerup", up);
    cv.addEventListener("pointercancel", cancel);
    cv.addEventListener("pointerenter", enter);
    cv.addEventListener("pointerleave", leave);
    cv.addEventListener("wheel", wheel, { passive: false });
    cv.addEventListener("keydown", key);
    kick();
    return () => {
      ro.disconnect(); mo.disconnect(); io.disconnect();
      mq.removeEventListener("change", onMq); cq.removeEventListener("change", onCq);
      document.removeEventListener("visibilitychange", sync);
      cv.removeEventListener("pointerdown", down);
      cv.removeEventListener("pointermove", move);
      cv.removeEventListener("pointerup", up);
      cv.removeEventListener("pointercancel", cancel);
      cv.removeEventListener("pointerenter", enter);
      cv.removeEventListener("pointerleave", leave);
      cv.removeEventListener("wheel", wheel);
      cv.removeEventListener("keydown", key);
      if (st.raf) cancelAnimationFrame(st.raf);
      st.raf = 0;
    };
    // The loop reads everything through `s`; wiring once on mount is intended.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <canvas
      ref={canvasRef}
      role="img"
      tabIndex={0}
      aria-label={props.label}
      style={{ position: "absolute", inset: 0, width: "100%", height: "100%", display: "block", cursor: "grab", touchAction: "pan-y", borderRadius: "inherit" }}
    />
  );
});

export default Globe;
