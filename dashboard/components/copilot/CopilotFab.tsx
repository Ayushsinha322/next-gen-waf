"use client";
import { useState, useRef, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { GREET, askCopilot } from "@/lib/copilot";
import type { ChatMessage } from "@/lib/types";
import { spring } from "@/lib/animations";
import { renderCopilotMarkdown } from "@/lib/safeMarkdown";
import Icon from "@/components/ui/Icon";

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

  async function sendAI(text: string) {
    const now = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    const history = msgs.map(m => ({ role: (m.who === "ai" ? "assistant" : "user") as "assistant" | "user", content: m.text }));
    setMsgs(p => [...p, { who: "usr", text, time: now }]);
    setTyping(true);
    try {
      const reply = await askCopilot(history, text);
      const now2 = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      setTyping(false);
      setMsgs(p => [...p, { who: "ai", text: reply, time: now2 }]);
    } catch (err: unknown) {
      const now2 = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      setTyping(false);
      const msg = err instanceof Error ? err.message : String(err);
      setMsgs(p => [...p, { who: "ai", text: `⚠ ${msg}`, time: now2 }]);
    }
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
      <motion.button
        className={fabClass}
        onClick={() => setOpen(o => !o)}
        style={{ position: "fixed" }}
        whileHover={{ scale: 1.1, rotate: 5 }}
        whileTap={{ scale: 0.92 }}
      >
        <span className={variant === "dashboard" ? "cfab-ring" : "fab-ring"} />
        <Icon name="sparkles" size={22} />
        {variant === "login" && <span className="fab-badge">AI</span>}
        {variant === "login" && <span style={{ position: "absolute", right: 62, top: "50%", transform: "translateY(-50%)", background: "rgba(20,12,38,.96)", backdropFilter: "blur(8px)", border: "1px solid rgba(124,47,191,.4)", borderRadius: 20, padding: "5px 12px", fontSize: 14, fontFamily: "var(--font-mono)", color: "#fff", whiteSpace: "nowrap", opacity: 0, pointerEvents: "none" }} className="fab-tip">Sentinel AI Copilot</span>}
      </motion.button>

      <AnimatePresence>
        {open && (
          <motion.div
            className={`${panelClass} open`}
            initial={false}
            animate={{ scale: 1, y: 0, opacity: 1 }}
            exit={{ scale: 0.88, y: 20, opacity: 0 }}
            transition={spring}
          >
            <div style={{ padding: "14px 18px", borderBottom: "1px solid rgba(124,47,191,.2)", display: "flex", alignItems: "center", gap: 11, background: "linear-gradient(135deg,rgba(124,47,191,.15) 0%,transparent 100%)", flexShrink: 0 }}>
              <motion.div animate={{ boxShadow: ["0 0 14px var(--pur-glow)", "0 0 24px rgba(124,58,237,.6)", "0 0 14px var(--pur-glow)"] }} transition={{ duration: 3, repeat: Infinity }} style={{ width: 34, height: 34, borderRadius: "50%", background: "linear-gradient(135deg,var(--purple),#4A0FA0)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 19 }}><Icon name="sparkles" size={18} /></motion.div>
              <div>
                <div style={{ fontFamily: "var(--font-display)", fontSize: 13, fontWeight: 700, color: "var(--text)" }}>Sentinel AI Copilot</div>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "#9B60E0", display: "flex", alignItems: "center", gap: 4, marginTop: 1 }}>
                  <span style={{ width: 5, height: 5, borderRadius: "50%", background: "var(--green)", boxShadow: "0 0 5px var(--green)", display: "inline-block" }} />
                  Online · DeepSeek R1
                </div>
              </div>
              <motion.button style={{ cursor: "pointer", color: "var(--text3)", fontSize: 19, background: "none", border: "none", marginLeft: "auto", lineHeight: 1, transition: "color .2s" }} onClick={() => setOpen(false)} whileHover={{ scale: 1.15, color: "var(--red-b)" }}>✕</motion.button>
            </div>

            <div ref={msgsRef} style={{ flex: 1, overflowY: "auto", padding: 14, display: "flex", flexDirection: "column", gap: 11 }}>
              {msgs.map((m, i) => (
                <motion.div key={i} className={`msg ${m.who}`} initial={{ opacity: 0, y: 6, scale: 0.98 }} animate={{ opacity: 1, y: 0, scale: 1 }} transition={{ duration: 0.22 }}>
                  <div className={`mav ${m.who}`}><Icon name={m.who === "ai" ? "sparkles" : "user"} size={14} /></div>
                  <div>
                    <div className="mbbl" dangerouslySetInnerHTML={{ __html: renderCopilotMarkdown(m.text) }} />
                    <div style={{ fontSize: 10, color: "var(--text3)", marginTop: 3, textAlign: m.who === "usr" ? "right" : "left" }}>{m.time}</div>
                  </div>
                </motion.div>
              ))}
              {typing && (
                <motion.div className="msg ai" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                  <div className="mav ai"><Icon name="sparkles" size={14} /></div>
                  <div style={{ display: "flex", gap: 4, alignItems: "center", padding: "10px 13px", background: "rgba(124,47,191,.14)", border: "1px solid rgba(124,47,191,.24)", borderRadius: "3px 12px 12px 12px" }}>
                    <div className="tyd" /><div className="tyd" /><div className="tyd" />
                  </div>
                </motion.div>
              )}
            </div>

            <div style={{ padding: "7px 14px", borderTop: "1px solid rgba(124,47,191,.14)", display: "flex", gap: 5, flexWrap: "wrap", flexShrink: 0 }}>
              {Object.entries(QUICK_LABELS).map(([k, label]) => (
                <motion.button key={k} className="qbtn" onClick={() => sendAI(label)} whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.96 }}>{label}</motion.button>
              ))}
            </div>
            <div style={{ padding: "11px 14px", borderTop: "1px solid rgba(124,47,191,.18)", display: "flex", gap: 8, alignItems: "center", background: "rgba(124,47,191,.05)", flexShrink: 0 }}>
              <input className="cop-inp" value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => e.key === "Enter" && sendInput()} placeholder="Ask Sentinel AI anything..." />
              <motion.button style={{ width: 32, height: 32, borderRadius: "50%", background: "linear-gradient(135deg,var(--purple),#4A0FA0)", border: "none", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 15, transition: "all .2s", flexShrink: 0 }} onClick={sendInput} whileHover={{ scale: 1.1 }} whileTap={{ scale: 0.93 }}><Icon name="send" size={15} title="Send" /></motion.button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}