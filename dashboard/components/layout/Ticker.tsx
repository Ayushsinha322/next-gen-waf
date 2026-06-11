"use client";
import { motion } from "framer-motion";
import { TICKER_ITEMS } from "@/lib/tickerData";

export default function Ticker({ className = "ticker-bar" }: { className?: string }) {
  const items = [...TICKER_ITEMS, ...TICKER_ITEMS];
  return (
    <div className={className}>
      <motion.div
        className="tick-lbl"
        animate={{ textShadow: ["0 0 6px var(--cyan-glow)", "0 0 16px var(--cyan-glow)", "0 0 6px var(--cyan-glow)"] }}
        transition={{ duration: 2, repeat: Infinity }}
      >
        ⚡ LIVE THREATS
      </motion.div>
      <div className="tick-scroll">
        <div className="tick-inner">
          {items.map((t, i) => (
            <span key={i} className="ti">
              <span className={`tsev ${t.sev}`}>{t.sl}</span>
              {t.msg}
              <span className="tsep">◆</span>
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}