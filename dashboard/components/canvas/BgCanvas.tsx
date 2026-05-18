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
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let W = 0, H = 0;
    let rafId: number;
    const nodes: { x: number; y: number; vx: number; vy: number; r: number; isRed: boolean; pulse: number; ps: number }[] = [];
    const parts: { x: number; y: number; r: number; vx: number; vy: number; c: string; a: number }[] = [];
    let streams: { x: number; len: number; y: number; spd: number; alpha: number; isRed: boolean }[] = [];
    const waves: { x: number; y: number; r: number; maxR: number; spd: number; c: string }[] = [];
    const SCHARS = "01ABCDEF<>|!@#%⟨⟩{}[]⊕⊗∑∆ΩΨ";
    const blips = Array.from({ length: 7 }, () => ({ a: Math.random() * Math.PI * 2, r: 30 + Math.random() * 88 }));
    let ra1 = 0, ra2 = Math.PI;
    let waveTimer: ReturnType<typeof setInterval>;

    function initNodes() {
      nodes.length = 0;
      for (let i = 0; i < 55; i++) {
        nodes.push({ x: Math.random() * W * 1.1 - W * 0.05, y: Math.random() * H * 1.1 - H * 0.05, vx: (Math.random() - 0.5) * 0.22, vy: (Math.random() - 0.5) * 0.22, r: Math.random() * 2.2 + 0.7, isRed: Math.random() < 0.3, pulse: Math.random() * Math.PI * 2, ps: 0.025 + Math.random() * 0.02 });
      }
    }
    function initParts() {
      parts.length = 0;
      for (let i = 0; i < 100; i++) {
        parts.push({ x: Math.random() * W, y: Math.random() * H, r: Math.random() * 1.4 + 0.3, vx: (Math.random() - 0.5) * 0.18, vy: (Math.random() - 0.5) * 0.18, c: Math.random() < 0.3 ? "200,0,30" : (Math.random() < 0.5 ? "0,200,240" : "255,255,255"), a: Math.random() * 0.4 + 0.08 });
      }
    }
    function initStreams() {
      streams = [];
      const cnt = Math.ceil(W / 38);
      for (let i = 0; i < cnt; i++) {
        const len = 7 + Math.floor(Math.random() * 14);
        streams.push({ x: i * 38 + Math.random() * 20, len, y: Math.random() * H, spd: 0.6 + Math.random() * 1.4, alpha: 0.04 + Math.random() * 0.11, isRed: Math.random() < 0.28 });
      }
    }

    function resize() {
      W = canvas.width = window.innerWidth;
      H = canvas.height = window.innerHeight;
      initNodes(); initParts(); initStreams();
    }

    function animate() {
      ctx.fillStyle = "rgba(6,9,18,.18)";
      ctx.fillRect(0, 0, W, H);
      // hex grid
      const S = 26, W2 = S * 1.5, H2 = S * Math.sqrt(3);
      ctx.strokeStyle = "rgba(0,212,255,.028)"; ctx.lineWidth = 0.5;
      const cols = Math.ceil(W / W2) + 2, rows = Math.ceil(H / H2) + 2;
      for (let c = -1; c < cols; c++) for (let r = -1; r < rows; r++) {
        const x = c * W2, y = r * H2 + (c % 2 ? H2 / 2 : 0);
        ctx.beginPath();
        for (let i = 0; i < 6; i++) { const a = (Math.PI / 3) * i; const xi = x + (S - 1) * Math.cos(a), yi = y + (S - 1) * Math.sin(a); i === 0 ? ctx.moveTo(xi, yi) : ctx.lineTo(xi, yi); }
        ctx.closePath(); ctx.stroke();
      }
      // waves
      for (let i = waves.length - 1; i >= 0; i--) {
        const w = waves[i]; w.r += w.spd;
        const a = (1 - w.r / w.maxR) * 0.26;
        if (a <= 0) { waves.splice(i, 1); continue; }
        ctx.beginPath(); ctx.arc(w.x, w.y, w.r, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(${w.c},${a})`; ctx.lineWidth = 1; ctx.stroke();
      }
      // network
      const md = 140;
      for (let i = 0; i < nodes.length; i++) {
        const a = nodes[i];
        for (let j = i + 1; j < nodes.length; j++) {
          const b = nodes[j], d = Math.hypot(a.x - b.x, a.y - b.y);
          if (d < md) { const al = (1 - d / md) * (a.isRed || b.isRed ? 0.18 : 0.08); ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.strokeStyle = (a.isRed || b.isRed) ? `rgba(255,45,85,${al})` : `rgba(0,212,255,${al})`; ctx.lineWidth = 0.6; ctx.stroke(); }
        }
      }
      nodes.forEach(n => {
        n.x += n.vx; n.y += n.vy; n.pulse += n.ps;
        if (n.x < -60) n.x = W + 60; if (n.x > W + 60) n.x = -60;
        if (n.y < -60) n.y = H + 60; if (n.y > H + 60) n.y = -60;
        const pr = n.r + Math.sin(n.pulse) * 0.7, c = n.isRed ? "255,45,85" : "0,212,255";
        const grd = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, pr * 4.5);
        grd.addColorStop(0, `rgba(${c},.35)`); grd.addColorStop(1, `rgba(${c},0)`);
        ctx.beginPath(); ctx.arc(n.x, n.y, pr * 4.5, 0, Math.PI * 2); ctx.fillStyle = grd; ctx.fill();
        ctx.beginPath(); ctx.arc(n.x, n.y, pr, 0, Math.PI * 2); ctx.fillStyle = `rgba(${c},.85)`; ctx.fill();
      });
      // streams
      ctx.font = "11px 'Share Tech Mono',monospace";
      streams.forEach(s => {
        s.y += s.spd;
        if (s.y > H + s.len * 16) { s.y = -(s.len * 16); s.x = Math.random() * W; }
        for (let i = 0; i < s.len; i++) {
          const cy = s.y - i * 15; if (cy < 0 || cy > H) continue;
          const ff = (1 - i / s.len) * s.alpha, isH = i === 0, ch = SCHARS[Math.floor(Math.random() * SCHARS.length)];
          ctx.fillStyle = isH ? (s.isRed ? `rgba(255,77,109,${ff * 3.5})` : `rgba(0,212,255,${ff * 3.5})`) : (s.isRed ? `rgba(180,20,40,${ff})` : `rgba(0,140,200,${ff})`);
          ctx.fillText(ch, s.x, cy);
        }
      });
      // particles
      parts.forEach(p => {
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0) p.x = W; if (p.x > W) p.x = 0;
        if (p.y < 0) p.y = H; if (p.y > H) p.y = 0;
        ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${p.c},${p.a})`; ctx.fill();
      });
      // radar (top-right)
      const cx = W - 130, cy2 = 130, rr = 96;
      ctx.save(); ctx.globalAlpha = 0.6;
      ctx.strokeStyle = "rgba(0,212,255,.12)"; ctx.lineWidth = 1;
      [1, 0.66, 0.33].forEach(f => { ctx.beginPath(); ctx.arc(cx, cy2, rr * f, 0, Math.PI * 2); ctx.stroke(); });
      ctx.beginPath(); ctx.moveTo(cx - rr, cy2); ctx.lineTo(cx + rr, cy2); ctx.moveTo(cx, cy2 - rr); ctx.lineTo(cx, cy2 + rr); ctx.stroke();
      function sweep(angle: number, col: string) {
        const steps = 24, arc = Math.PI * 0.42;
        ctx.save(); ctx.beginPath(); ctx.arc(cx, cy2, rr, 0, Math.PI * 2); ctx.clip();
        for (let i = 0; i < steps; i++) { const a1 = angle - arc + arc * i / steps, a2 = angle - arc + arc * (i + 1) / steps; ctx.beginPath(); ctx.moveTo(cx, cy2); ctx.arc(cx, cy2, rr, a1, a2); ctx.closePath(); ctx.fillStyle = `rgba(${col},${(i / steps) * 0.22})`; ctx.fill(); }
        ctx.beginPath(); ctx.moveTo(cx, cy2); ctx.lineTo(cx + Math.cos(angle) * rr, cy2 + Math.sin(angle) * rr);
        ctx.strokeStyle = `rgba(${col},.85)`; ctx.lineWidth = 1.5; ctx.stroke(); ctx.restore();
      }
      ra1 += 0.012; ra2 += 0.008; sweep(ra1, "0,212,255"); sweep(ra2, "255,45,85");
      blips.forEach(b => {
        const bx = cx + b.r * Math.cos(b.a), by = cy2 + b.r * Math.sin(b.a);
        const d = ((b.a - ra1) % (Math.PI * 2) + Math.PI * 2) % (Math.PI * 2), age = 1 - Math.min(d / (Math.PI * 0.5), 1);
        if (age > 0) { ctx.beginPath(); ctx.arc(bx, by, 2.5, 0, Math.PI * 2); ctx.fillStyle = `rgba(0,212,255,${age * 0.85})`; ctx.fill(); }
      });
      ctx.restore();
      rafId = requestAnimationFrame(animate);
    }

    resize();
    window.addEventListener("resize", resize);
    waveTimer = setInterval(() => {
      waves.push({ x: Math.random() * W, y: Math.random() * H, r: 0, maxR: 130 + Math.random() * 160, spd: 1.1 + Math.random() * 0.7, c: Math.random() > 0.5 ? "0,212,255" : "255,45,85" });
    }, 1900);
    animate();

    return () => {
      cancelAnimationFrame(rafId);
      clearInterval(waveTimer);
      window.removeEventListener("resize", resize);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      style={{ position: "fixed", inset: 0, zIndex: 0, pointerEvents: "none", opacity, ...style }}
    />
  );
}
