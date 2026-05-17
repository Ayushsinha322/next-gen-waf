"use client";
import { TICKER_ITEMS } from "@/lib/tickerData";
export default function Ticker({ className = "ticker-bar" }: { className?: string }) {
  const items = [...TICKER_ITEMS, ...TICKER_ITEMS];
  return (
    <div className={className}>
      <div className="tick-lbl">⚡ LIVE THREATS</div>
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
