"use client";
import { useState, useRef, useEffect } from "react";
import { AI_RESPONSES, GREET, getAIResponse } from "@/lib/aiResponses";
import type { ChatMessage } from "@/lib/types";

function formatMsg(text: string) {
  return text
    .replace(/\n/g, "<br>")
    .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
    .replace(/`(.*?)`/g, '<code style="background:rgba(255,255,255,.08);padding:1px 5px;border-radius:3px;font-size:10px">$1</code>')
    .replace(/```([\s\S]*?)```/g, '<pre style="background:rgba(0,0,0,.3);padding:8px;border-radius:6px;font-size:10px;margin:5px 0;overflow-x:auto;white-space:pre-wrap">$1</pre>');
}

const QUICK_LABELS: Record<string, string> = {
  explain: "Explain the latest alert",
  rule: "Write a custom WAF rule",
  report: "Generate threat report",
  fp: "Debug a false positive",
  patch: "Generate CVE virtual patch",
};

export default function CopilotFab({ variant = "login" }: { variant?: "login" | "dashboard" }) {
  const [open, setOpen] = useState(false);
  const [msgs, setMsgs] = useState<ChatMessage[]>([]);
  const [typing, setTyping] = useState(false);
  const [input, setInput] = useState("");
  const msgsRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const t = setTimeout(() => {
      const now = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      setMsgs([{ who: "ai", text: GREET, time: now }]);
    }, 2600);
    return () => clearTimeout(t);
  }, []);

  useEffect(() => {
    if (msgsRef.current) msgsRef.current.scrollTop = msgsRef.current.scrollHeight;
  }, [msgs, typing]);

  function sendAI(text: string) {
    const now = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    setMsgs(p => [...p, { who: "usr", text, time: now }]);
    setTyping(true);
    setTimeout(() => {
      const now2 = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      setTyping(false);
      setMsgs(p => [...p, { who: "ai", text: getAIResponse(text), time: now2 }]);
    }, 900 + Math.random() * 600);
  }

  function sendInput() {
    if (!input.trim()) return;
    sendAI(input.trim());
    setInput("");
  }

  const panelClass = variant === "dashboard" ? "cop-mini" : "cop-panel";
  const fabClass = variant === "dashboard" ? "cfab" : "copilot-fab";

  return (
    <>
      <button className={fabClass} onClick={() => setOpen(o => !o)} style={{ position: "fixed" }}>
        <span className={variant === "dashboard" ? "cfab-ring" : "fab-ring"} />
        <span style={{ fontSize: 22 }}>🤖</span>
        {variant === "login" && <span className="fab-badge">AI</span>}
        {variant === "login" && <span style={{ position: "absolute", right: 62, top: "50%", transform: "translateY(-50%)", background: "rgba(20,12,38,.96)", backdropFilter: "blur(8px)", border: "1px solid rgba(124,47,191,.4)", borderRadius: 20, padding: "5px 12px", fontSize: 10, fontFamily: "'Share Tech Mono',monospace", color: "#fff", whiteSpace: "nowrap", opacity: 0, pointerEvents: "none" }} className="fab-tip">Sentinel AI Copilot</span>}
      </button>

      <div className={`${panelClass} ${open ? "open" : ""}`}>
        <div style={{ padding: "14px 18px", borderBottom: "1px solid rgba(124,47,191,.2)", display: "flex", alignItems: "center", gap: 11, background: "linear-gradient(135deg,rgba(124,47,191,.15) 0%,transparent 100%)", flexShrink: 0 }}>
          <div style={{ width: 34, height: 34, borderRadius: "50%", background: "linear-gradient(135deg,var(--purple),#4A0FA0)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 17, boxShadow: "0 0 14px var(--pur-glow)" }}>🤖</div>
          <div>
            <div style={{ fontFamily: "'Orbitron',sans-serif", fontSize: 11, fontWeight: 700, color: "var(--text)" }}>Sentinel AI Copilot</div>
            <div style={{ fontFamily: "'Share Tech Mono',monospace", fontSize: 9, color: "#9B60E0", display: "flex", alignItems: "center", gap: 4, marginTop: 1 }}>
              <span style={{ width: 5, height: 5, borderRadius: "50%", background: "var(--green)", boxShadow: "0 0 5px var(--green)", display: "inline-block" }} />
              Online · DeepSeek R1
            </div>
          </div>
          <button style={{ cursor: "pointer", color: "var(--text3)", fontSize: 17, background: "none", border: "none", marginLeft: "auto", lineHeight: 1, transition: "color .2s" }} onClick={() => setOpen(false)}>✕</button>
        </div>

        <div ref={msgsRef} style={{ flex: 1, overflowY: "auto", padding: 14, display: "flex", flexDirection: "column", gap: 11 }}>
          {msgs.map((m, i) => (
            <div key={i} className={`msg ${m.who}`}>
              <div className={`mav ${m.who}`}>{m.who === "ai" ? "🤖" : "👤"}</div>
              <div>
                <div className="mbbl" dangerouslySetInnerHTML={{ __html: formatMsg(m.text) }} />
                <div style={{ fontSize: 8, color: "var(--text3)", marginTop: 3, textAlign: m.who === "usr" ? "right" : "left" }}>{m.time}</div>
              </div>
            </div>
          ))}
          {typing && (
            <div className="msg ai">
              <div className="mav ai">🤖</div>
              <div style={{ display: "flex", gap: 4, alignItems: "center", padding: "10px 13px", background: "rgba(124,47,191,.14)", border: "1px solid rgba(124,47,191,.24)", borderRadius: "3px 12px 12px 12px" }}>
                <div className="tyd" /><div className="tyd" /><div className="tyd" />
              </div>
            </div>
          )}
        </div>

        <div style={{ padding: "7px 14px", borderTop: "1px solid rgba(124,47,191,.14)", display: "flex", gap: 5, flexWrap: "wrap", flexShrink: 0 }}>
          {Object.entries(QUICK_LABELS).map(([k, label]) => (
            <button key={k} className="qbtn" onClick={() => sendAI(label)}>{label}</button>
          ))}
        </div>
        <div style={{ padding: "11px 14px", borderTop: "1px solid rgba(124,47,191,.18)", display: "flex", gap: 8, alignItems: "center", background: "rgba(124,47,191,.05)", flexShrink: 0 }}>
          <input className="cop-inp" value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => e.key === "Enter" && sendInput()} placeholder="Ask Sentinel AI anything..." />
          <button style={{ width: 32, height: 32, borderRadius: "50%", background: "linear-gradient(135deg,var(--purple),#4A0FA0)", border: "none", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 13, transition: "all .2s", flexShrink: 0 }} onClick={sendInput}>➤</button>
        </div>
      </div>
    </>
  );
}
