"use client";
import { useEffect, useRef } from "react";

export default function ScannerCanvas() {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const sc = ref.current;
    if (!sc) return;
    const c2 = sc.getContext("2d");
    if (!c2) return;
    const cx = 80, cy = 55, R = 50;
    let sa = 0, rafId: number;
    function draw() {
      c2.clearRect(0, 0, 160, 110);
      c2.strokeStyle = "rgba(200,0,30,.25)"; c2.lineWidth = 1;
      [1, 0.66, 0.33].forEach(f => { c2.beginPath(); c2.arc(cx, cy, R * f, 0, Math.PI * 2); c2.stroke(); });
      c2.beginPath(); c2.moveTo(cx - R, cy); c2.lineTo(cx + R, cy); c2.moveTo(cx, cy - R); c2.lineTo(cx, cy + R); c2.stroke();
      const steps = 20, arc = Math.PI * 0.44;
      c2.save(); c2.beginPath(); c2.arc(cx, cy, R, 0, Math.PI * 2); c2.clip();
      for (let i = 0; i < steps; i++) {
        const a1 = sa - arc + arc * i / steps, a2 = sa - arc + arc * (i + 1) / steps;
        c2.beginPath(); c2.moveTo(cx, cy); c2.arc(cx, cy, R, a1, a2); c2.closePath();
        c2.fillStyle = `rgba(200,0,30,${(i / steps) * 0.3})`; c2.fill();
      }
      c2.beginPath(); c2.moveTo(cx, cy); c2.lineTo(cx + Math.cos(sa) * R, cy + Math.sin(sa) * R);
      c2.strokeStyle = "rgba(255,30,68,.9)"; c2.lineWidth = 2; c2.stroke(); c2.restore();
      c2.beginPath(); c2.arc(cx, cy, 4, 0, Math.PI * 2); c2.fillStyle = "rgba(200,0,30,.9)"; c2.fill();
      [{ a: 0.8, r: 30 }, { a: 2.1, r: 42 }, { a: 4.5, r: 22 }].forEach(b => {
        const bx = cx + b.r * Math.cos(b.a), by = cy + b.r * Math.sin(b.a);
        const d = ((b.a - sa) % (Math.PI * 2) + Math.PI * 2) % (Math.PI * 2), age = 1 - Math.min(d / (Math.PI * 0.5), 1);
        if (age > 0.05) { c2.beginPath(); c2.arc(bx, by, 2.5, 0, Math.PI * 2); c2.fillStyle = `rgba(255,30,68,${age * 0.9})`; c2.fill(); }
      });
      sa += 0.016;
      rafId = requestAnimationFrame(draw);
    }
    draw();
    return () => cancelAnimationFrame(rafId);
  }, []);
  return <canvas ref={ref} width={160} height={110} style={{ display: "block" }} />;
}
