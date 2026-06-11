"use client";
import { useEffect, useRef } from "react";

interface BgCanvasProps {
  style?: React.CSSProperties;
  opacity?: number;
}

export default function BgCanvas({ style, opacity = 1 }: BgCanvasProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d", { alpha: true });
    if (!ctx) return;

    let W = 0, H = 0;
    let rafId = 0;
    let themeMode: "dark" | "light" = "dark";
    let frameCount = 0;
    let hexGridDrawn = false;

    const themeObserver = new MutationObserver(() => {
      const next = document.documentElement.dataset.theme === "light" ? "light" : "dark";
      if (next !== themeMode) {
        themeMode = next;
        hexGridDrawn = false; // re-draw hex grid on theme switch
      }
    });
    themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    themeMode = document.documentElement.dataset.theme === "light" ? "light" : "dark";

    // ─── Dark mode state ─────────────────────────────────────────────────────
    type DNode = { x: number; y: number; vx: number; vy: number; r: number; col: string; pulse: number; ps: number };
    type DStream = { x: number; len: number; y: number; spd: number; alpha: number; col: string };
    type DWave = { x: number; y: number; r: number; maxR: number; spd: number; c: string };

    const nodes: DNode[] = [];
    const streams: DStream[] = [];
    const waves: DWave[] = [];
    const SCHARS = "01ABCDEF<>|!@#%⟨⟩{}[]⊕⊗∑∆Ω";
    let ra1 = 0, ra2 = Math.PI;
    const blips = Array.from({ length: 6 }, () => ({ a: Math.random() * Math.PI * 2, r: 28 + Math.random() * 76 }));
    let waveTimer: ReturnType<typeof setInterval>;

    const NODE_COLS = ["0,212,255", "255,45,85", "139,92,246", "0,230,118"];

    // ─── Light mode state ────────────────────────────────────────────────────
    type LPoint = { x: number; y: number; vx: number; vy: number; r: number; a: number; col: string };
    const lightPoints: LPoint[] = [];

    function initNodes() {
      nodes.length = 0;
      for (let i = 0; i < 52; i++) {
        nodes.push({
          x: Math.random() * W,
          y: Math.random() * H,
          vx: (Math.random() - 0.5) * 0.4,
          vy: (Math.random() - 0.5) * 0.4,
          r: Math.random() * 2 + 0.5,
          col: NODE_COLS[Math.floor(Math.random() * NODE_COLS.length)],
          pulse: Math.random() * Math.PI * 2,
          ps: 0.018 + Math.random() * 0.016,
        });
      }
    }

    function initStreams() {
      streams.length = 0;
      const cnt = Math.max(Math.ceil(W / 44), 4);
      for (let i = 0; i < cnt; i++) {
        streams.push({
          x: i * 44 + Math.random() * 20,
          len: 5 + Math.floor(Math.random() * 11),
          y: Math.random() * H,
          spd: 0.6 + Math.random() * 1.3,
          alpha: 0.028 + Math.random() * 0.082,
          col: Math.random() < 0.22 ? "255,45,85" : "0,212,255",
        });
      }
    }

    function initLightPoints() {
      lightPoints.length = 0;
      const lcols = ["13,148,136", "99,102,241", "2,132,199", "5,150,105"];
      for (let i = 0; i < 80; i++) {
        lightPoints.push({
          x: Math.random() * W,
          y: Math.random() * H,
          vx: (Math.random() - 0.5) * 0.3,
          vy: (Math.random() - 0.5) * 0.3,
          r: Math.random() * 1.4 + 0.35,
          a: Math.random() * 0.18 + 0.05,
          col: lcols[Math.floor(Math.random() * lcols.length)],
        });
      }
    }

    function resize() {
      W = canvas.width = window.innerWidth;
      H = canvas.height = window.innerHeight;
      hexGridDrawn = false;
      initNodes();
      initStreams();
      initLightPoints();
    }

    // ─── Draw hex grid directly (throttled — only once per resize/theme-change) ──
    function drawHexGrid() {
      const S = 28, W2 = S * 1.5, H2 = S * Math.sqrt(3);
      ctx.strokeStyle = themeMode === "dark"
        ? "rgba(0,212,255,0.028)"
        : "rgba(13,148,136,0.06)";
      ctx.lineWidth = 0.5;
      const cols = Math.ceil(W / W2) + 2, rows = Math.ceil(H / H2) + 2;
      for (let c = -1; c < cols; c++) {
        for (let r = -1; r < rows; r++) {
          const x = c * W2, y = r * H2 + (c % 2 ? H2 / 2 : 0);
          ctx.beginPath();
          for (let i = 0; i < 6; i++) {
            const a = (Math.PI / 3) * i;
            const xi = x + (S - 1) * Math.cos(a), yi = y + (S - 1) * Math.sin(a);
            i === 0 ? ctx.moveTo(xi, yi) : ctx.lineTo(xi, yi);
          }
          ctx.closePath();
          ctx.stroke();
        }
      }
    }

    // ─── Dark mode draw ──────────────────────────────────────────────────────
    function drawDark() {
      // Hex grid — drawn once, then naturally faded by trail each frame
      if (!hexGridDrawn) {
        drawHexGrid();
        hexGridDrawn = true;
      }

      // Motion-blur trail
      ctx.fillStyle = "rgba(5,5,8,0.12)";
      ctx.fillRect(0, 0, W, H);

      // Expanding waves
      for (let i = waves.length - 1; i >= 0; i--) {
        const w = waves[i];
        w.r += w.spd;
        const a = (1 - w.r / w.maxR) * 0.2;
        if (a <= 0) { waves.splice(i, 1); continue; }
        ctx.beginPath();
        ctx.arc(w.x, w.y, w.r, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(${w.c},${a})`;
        ctx.lineWidth = 1;
        ctx.stroke();
      }

      // Network connections
      for (let i = 0; i < nodes.length; i++) {
        const a = nodes[i];
        for (let j = i + 1; j < nodes.length; j++) {
          const b = nodes[j];
          const dx = a.x - b.x, dy = a.y - b.y;
          const d2 = dx * dx + dy * dy;
          if (d2 < 130 * 130) {
            const al = (1 - Math.sqrt(d2) / 130) * 0.06;
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.strokeStyle = `rgba(0,212,255,${al})`;
            ctx.lineWidth = 0.5;
            ctx.stroke();
          }
        }
      }

      // Node particles
      for (const n of nodes) {
        n.x += n.vx; n.y += n.vy;
        n.pulse += n.ps;
        if (n.x < -60) n.x = W + 60; else if (n.x > W + 60) n.x = -60;
        if (n.y < -60) n.y = H + 60; else if (n.y > H + 60) n.y = -60;
        const pr = n.r + Math.sin(n.pulse) * 0.55;
        // 3 concentric circles (cheaper than radialGradient)
        ctx.beginPath(); ctx.arc(n.x, n.y, pr * 5, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${n.col},0.04)`; ctx.fill();
        ctx.beginPath(); ctx.arc(n.x, n.y, pr * 2.5, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${n.col},0.09)`; ctx.fill();
        ctx.beginPath(); ctx.arc(n.x, n.y, pr, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${n.col},0.82)`; ctx.fill();
      }

      // Matrix character streams
      ctx.font = "10px 'Share Tech Mono',monospace";
      for (const s of streams) {
        s.y += s.spd;
        if (s.y > H + s.len * 15) { s.y = -(s.len * 15); s.x = Math.random() * W; }
        for (let i = 0; i < s.len; i++) {
          const cy = s.y - i * 14;
          if (cy < 0 || cy > H) continue;
          const ff = (1 - i / s.len) * s.alpha;
          ctx.fillStyle = i === 0
            ? `rgba(${s.col},${ff * 3})`
            : `rgba(${s.col},${ff})`;
          ctx.fillText(SCHARS[Math.floor(Math.random() * SCHARS.length)], s.x, cy);
        }
      }

      // Radar (top-right corner)
      const rcx = W - 118, rcy = 118, rr = 88;
      ctx.save();
      ctx.globalAlpha = 0.5;

      ctx.strokeStyle = "rgba(0,212,255,0.1)";
      ctx.lineWidth = 0.8;
      for (const f of [1, 0.65, 0.33]) {
        ctx.beginPath(); ctx.arc(rcx, rcy, rr * f, 0, Math.PI * 2); ctx.stroke();
      }
      ctx.beginPath();
      ctx.moveTo(rcx - rr, rcy); ctx.lineTo(rcx + rr, rcy);
      ctx.moveTo(rcx, rcy - rr); ctx.lineTo(rcx, rcy + rr);
      ctx.stroke();

      const drawSweep = (angle: number, colStr: string) => {
        const steps = 18, arc = Math.PI * 0.38;
        ctx.save();
        ctx.beginPath(); ctx.arc(rcx, rcy, rr, 0, Math.PI * 2); ctx.clip();
        for (let i = 0; i < steps; i++) {
          const a1 = angle - arc + arc * i / steps;
          const a2 = angle - arc + arc * (i + 1) / steps;
          ctx.beginPath(); ctx.moveTo(rcx, rcy);
          ctx.arc(rcx, rcy, rr, a1, a2); ctx.closePath();
          ctx.fillStyle = `rgba(${colStr},${(i / steps) * 0.16})`; ctx.fill();
        }
        ctx.beginPath(); ctx.moveTo(rcx, rcy);
        ctx.lineTo(rcx + Math.cos(angle) * rr, rcy + Math.sin(angle) * rr);
        ctx.strokeStyle = `rgba(${colStr},0.75)`;
        ctx.lineWidth = 1.5; ctx.stroke();
        ctx.restore();
      };

      ra1 += 0.01; ra2 += 0.007;
      drawSweep(ra1, "0,212,255");
      drawSweep(ra2, "255,45,85");

      for (const b of blips) {
        const bx = rcx + b.r * Math.cos(b.a), by = rcy + b.r * Math.sin(b.a);
        const d = ((b.a - ra1) % (Math.PI * 2) + Math.PI * 2) % (Math.PI * 2);
        const age = 1 - Math.min(d / (Math.PI * 0.5), 1);
        if (age > 0) {
          ctx.beginPath(); ctx.arc(bx, by, 2, 0, Math.PI * 2);
          ctx.fillStyle = `rgba(0,212,255,${age * 0.75})`; ctx.fill();
        }
      }
      ctx.restore();
    }

    // ─── Light mode draw ─────────────────────────────────────────────────────
    function drawLight() {
      // Hex grid — drawn once, then naturally faded by trail each frame
      if (!hexGridDrawn) {
        drawHexGrid();
        hexGridDrawn = true;
      }

      // Motion-blur trail — soft slate overlay
      ctx.fillStyle = "rgba(248,250,252,0.18)";
      ctx.fillRect(0, 0, W, H);

      // Subtle dot grid (throttled — only once per frame cycle, then faded)
      if (frameCount % 8 === 0) {
        const gs = 40;
        ctx.fillStyle = "rgba(13,148,136,0.045)";
        for (let x = 0; x <= W; x += gs) {
          for (let y = 0; y <= H; y += gs) {
            ctx.beginPath(); ctx.arc(x, y, 0.7, 0, Math.PI * 2); ctx.fill();
          }
        }
      }

      // Particle network
      for (let i = 0; i < lightPoints.length; i++) {
        const a = lightPoints[i];
        for (let j = i + 1; j < lightPoints.length; j++) {
          const b = lightPoints[j];
          const dx = a.x - b.x, dy = a.y - b.y;
          const d2 = dx * dx + dy * dy;
          if (d2 < 120 * 120) {
            const al = (1 - Math.sqrt(d2) / 120) * 0.06;
            ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y);
            ctx.strokeStyle = `rgba(13,148,136,${al})`;
            ctx.lineWidth = 0.35; ctx.stroke();
          }
        }
      }

      // Light particles
      for (const p of lightPoints) {
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0) p.x = W; else if (p.x > W) p.x = 0;
        if (p.y < 0) p.y = H; else if (p.y > H) p.y = 0;
        ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${p.col},${p.a})`; ctx.fill();
      }
    }

    // ─── Main RAF loop (error-guarded) ───────────────────────────────────────
    function animate() {
      frameCount++;
      try {
        if (themeMode === "light") {
          drawLight();
        } else {
          drawDark();
        }
      } catch (_) {
        // Swallow — keep animation alive
      }
      rafId = requestAnimationFrame(animate);
    }

    resize();
    window.addEventListener("resize", resize, { passive: true });
    waveTimer = setInterval(() => {
      if (themeMode === "dark") {
        waves.push({
          x: Math.random() * W,
          y: Math.random() * H,
          r: 0,
          maxR: 100 + Math.random() * 140,
          spd: 0.9 + Math.random() * 0.5,
          c: Math.random() > 0.5 ? "0,212,255" : "255,45,85",
        });
      }
    }, 2400);
    animate();

    return () => {
      cancelAnimationFrame(rafId);
      clearInterval(waveTimer);
      window.removeEventListener("resize", resize);
      themeObserver.disconnect();
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 0,
        pointerEvents: "none",
        opacity,
        ...style,
      }}
    />
  );
}