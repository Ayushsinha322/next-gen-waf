"use client";
import { useState, useRef, useEffect } from "react";
import { motion } from "framer-motion";
import { GREET, askCopilot } from "@/lib/copilot";
import { takeCopilotHandoff, listRecentHandoffs, rememberRecent, clearRecentHandoffs, buildCopilotMessage, virtualPatchPrompt, type CopilotHandoff } from "@/lib/copilotContext";
import { spring } from "@/lib/animations";
import { renderCopilotMarkdown } from "@/lib/safeMarkdown";
import Icon from "@/components/ui/Icon";
import { PRODUCT_NAME } from "@/lib/version";

// The left column used to list six invented conversations ("SQLi on /api/login",
// "CVE-2024-1234 patch"…) that opened nothing. It now lists the operator's real
// hand-offs from the Alerts, Threat Search and Rules pages; empty until one is made.
const QUICK_ACTIONS: Array<[string, string, string]> = [
  ["explain", "Explain an alert", "Open the Alerts page and press on a row — the alert is loaded here with the question asked."],
  ["rule",    "Write a rule",     `Write a ${PRODUCT_NAME} custom rule in ModSecurity SecRule syntax that `],
  ["fp",      "Fix a false positive", "Open Threat Search, pick the event, and press Draft exclusion — the event is loaded here."],
  ["patch",   "Virtual patch a CVE", "CVE-"],
  ["tune",    "Tune a threshold",  "Our anomaly threshold is 5 at paranoia level 1 with ML sensitivity 0.9. Given these false-positive candidates from learning mode, what should change first? "],
];

export default function CopilotPage() {
  const [msgs, setMsgs] = useState<{who:"ai"|"usr";text:string;time:string}[]>([]);
  const [typing, setTyping] = useState(false);
  const [input, setInput] = useState("");
  const [recent, setRecent] = useState<CopilotHandoff[]>([]);
  const [loaded, setLoaded] = useState<CopilotHandoff | null>(null);
  const msgsRef = useRef<HTMLDivElement>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setRecent(listRecentHandoffs());
    const h = takeCopilotHandoff();
    const t = setTimeout(() => {
      const now = new Date().toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"});
      setMsgs([{ who:"ai", text:GREET, time:now }]);
      // A hand-off from another page: show what was loaded and ask its question
      // straight away — the operator came here for that answer, not for a chat box.
      if (h) startFrom(h, false);
    }, 300);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function startFrom(h: CopilotHandoff, remember: boolean) {
    setLoaded(h);
    if (remember) { rememberRecent(h); setRecent(listRecentHandoffs()); }
    void sendMsg(buildCopilotMessage(h), `${h.title}\n\n_(record from ${h.source} attached)_`);
  }

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [msgs, typing]);

  /** `shown` is what the transcript displays when the sent text carries a long JSON record. */
  async function sendMsg(text: string, shown?: string) {
    const now = new Date().toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"});
    setMsgs(p => [...p, { who:"usr", text: shown ?? text, time:now }]);
    setTyping(true);
    try {
      const history = msgs.map(m => ({ role: (m.who === "ai" ? "assistant" : "user") as "assistant" | "user", content: m.text }));
      const reply = await askCopilot(history, text);
      const now2 = new Date().toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"});
      setTyping(false);
      setMsgs(p => [...p, { who:"ai", text:reply, time:now2 }]);
    } catch (err: unknown) {
      const now2 = new Date().toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"});
      setTyping(false);
      const msg = err instanceof Error ? err.message : String(err);
      setMsgs(p => [...p, { who:"ai", text:`⚠ ${msg}`, time:now2 }]);
    }
  }

  function send() { if(!input.trim()) return; sendMsg(input.trim()); setInput(""); }

  return (
    <div className="sec">
      <motion.div initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={spring} style={{display:"flex",alignItems:"flex-start",justifyContent:"space-between",gap:14}}>
        <div><div className="sec-title" style={{color:"#BF7FFF"}}>AI Security Copilot</div><div className="sec-sub">Powered by DeepSeek R1 · Rule generation · CVE patching · Alert explanation</div></div>
        <div style={{display:"flex",gap:8,alignItems:"center"}}>
          <span style={{fontSize: 11,fontFamily:"var(--font-mono)",color:"#A070E0",background:"rgba(124,47,191,.15)",border:"1px solid rgba(124,47,191,.3)",borderRadius:20,padding:"4px 12px"}}>deepseek-r1:8b</span>
          <motion.button className="btn bg-btn btn-sm" whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }} onClick={() => { setMsgs([]); setTimeout(() => { const now=new Date().toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"}); setMsgs([{who:"ai",text:GREET,time:now}]); },100); }}>Clear Chat</motion.button>
        </div>
      </motion.div>

      <motion.div className="cop-page" initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ ...spring, delay: 0.1 }}>
        <div className="cop-hist">
          <div style={{padding:"13px 16px",borderBottom:"1px solid rgba(124,47,191,.15)",display:"flex",alignItems:"center",justifyContent:"space-between"}}>
            <div style={{fontFamily:"var(--font-display)",fontSize: 14,fontWeight:700,letterSpacing:1}}>Conversations</div>
            <motion.button className="btn bg-btn btn-xs" title="New conversation" onClick={() => { setMsgs([]); setLoaded(null); }} whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.96 }}>＋</motion.button>
          </div>
          <div style={{flex:1,overflowY:"auto",padding:8}}>
            {recent.length === 0 ? (
              <div style={{padding:"14px 10px",fontSize:12,color:"var(--text3)",fontFamily:"var(--font-mono)",lineHeight:1.5}}>
                No conversations yet. Press on an alert or a Threat Search event and it appears here with its record.
              </div>
            ) : recent.map((c,i) => (
              <div key={i} className={`hi ${loaded?.title===c.title?"active":""}`} title={`${c.source} · ${new Date(c.at).toLocaleString()}`} onClick={() => { setMsgs([]); startFrom(c, false); }}>
                {c.title}
              </div>
            ))}
            {recent.length > 0 && <div style={{padding:"6px 10px"}}><button className="btn bg-btn btn-xs" onClick={() => { clearRecentHandoffs(); setRecent([]); }}>Clear list</button></div>}
          </div>
        </div>

        <div className="cop-main">
          <div style={{padding:"14px 18px",borderBottom:"1px solid rgba(124,47,191,.15)",display:"flex",alignItems:"center",gap:12,background:"linear-gradient(135deg,rgba(124,47,191,.12),transparent)",flexShrink:0}}>
            <motion.div animate={{ boxShadow: ["0 0 18px var(--pur-glow)", "0 0 32px rgba(124,58,237,.6)", "0 0 18px var(--pur-glow)"] }} transition={{ duration: 3, repeat: Infinity }} style={{width:40,height:40,borderRadius:"50%",background:"linear-gradient(135deg,var(--purple),#4A0FA0)",display:"flex",alignItems:"center",justifyContent:"center",fontSize: 25}}><Icon name="sparkles" size={18} /></motion.div>
            <div>
              <div style={{fontFamily:"var(--font-display)",fontSize: 15,fontWeight:700}}>{PRODUCT_NAME} AI Copilot</div>
              <div style={{fontFamily:"var(--font-mono)",fontSize: 11,color:"#9B60E0",display:"flex",alignItems:"center",gap:5,marginTop:2}}>
                <span style={{width:5,height:5,borderRadius:"50%",background:"var(--green)",boxShadow:"0 0 5px var(--green)",display:"inline-block"}} />Online · Ready to assist
              </div>
            </div>
            {loaded && (
              <div title={`Loaded from ${loaded.source}`} style={{marginLeft:"auto",fontSize: 11,fontFamily:"var(--font-mono)",color:"var(--cyan)",background:"rgba(0,212,255,.08)",border:"1px solid rgba(0,212,255,.25)",borderRadius:20,padding:"3px 10px",maxWidth:340,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>
                {loaded.title}
              </div>
            )}
            <div style={{marginLeft:loaded?0:"auto",fontSize: 11,fontFamily:"var(--font-mono)",color:"#A070E0",background:"rgba(124,47,191,.15)",border:"1px solid rgba(124,47,191,.3)",borderRadius:20,padding:"3px 10px"}}>deepseek-r1:8b</div>
          </div>

          <div ref={msgsRef} className="flex-1 overflow-y-auto" style={{padding:"16px 18px",display:"flex",flexDirection:"column",gap:12}}>
            {msgs.map((m,i) => (
              <motion.div key={i} className={`msg2 ${m.who}`} initial={{ opacity: 0, y: 8, scale: 0.98 }} animate={{ opacity: 1, y: 0, scale: 1 }} transition={{ duration: 0.25 }}>
                <div className={`mav2 ${m.who}`}><Icon name={m.who==="ai"?"sparkles":"user"} size={14} /></div>
                <div>
                  <div className="mbbl2" dangerouslySetInnerHTML={{__html:renderCopilotMarkdown(m.text)}} />
                  <div className="mt3">{m.time}</div>
                </div>
              </motion.div>
            ))}
            {typing && (
              <motion.div className="msg2 ai" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                <div className="mav2 ai"><Icon name="sparkles" size={14} /></div>
                <div style={{display:"flex",gap:4,alignItems:"center",padding:"10px 13px",background:"rgba(124,47,191,.14)",border:"1px solid rgba(124,47,191,.24)",borderRadius:"3px 12px 12px 12px"}}>
                  <div className="tyd"/><div className="tyd"/><div className="tyd"/>
                </div>
              </motion.div>
            )}
            <div ref={messagesEndRef} />
          </div>

          <div style={{padding:"8px 18px",borderTop:"1px solid rgba(124,47,191,.15)",display:"flex",gap:6,flexWrap:"wrap",flexShrink:0}}>
            {QUICK_ACTIONS.map(([k,l,tmpl]) => (
              <motion.button key={k} className="qbtn2" title={k === "explain" || k === "fp" ? tmpl : "Fills the box with a prompt to complete"} whileHover={{ scale: 1.04 }} whileTap={{ scale: 0.97 }}
                onClick={() => {
                  // "Explain" and "false positive" need a record: point at where it comes from.
                  if (k === "explain" || k === "fp") { void sendMsg(tmpl, l); return; }
                  if (k === "patch") { setInput(virtualPatchPrompt("CVE-YYYY-NNNNN").prompt); return; }
                  setInput(tmpl);
                }}>{l}</motion.button>
            ))}
          </div>
          <div style={{padding:"12px 18px",borderTop:"1px solid rgba(124,47,191,.18)",display:"flex",gap:10,alignItems:"flex-end",background:"rgba(124,47,191,.04)",flexShrink:0}}>
            <textarea className="cop-inp2" value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => { if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();send();} }} placeholder="Ask about alerts, rules, CVEs, false positives, threat analysis..." />
            <motion.button style={{width:38,height:38,borderRadius:9,background:"linear-gradient(135deg,var(--purple),#4A0FA0)",border:"none",cursor:"pointer",display:"flex",alignItems:"center",justifyContent:"center",fontSize: 18,transition:"all .2s",flexShrink:0}} onClick={send} whileHover={{ scale: 1.08 }} whileTap={{ scale: 0.94 }}><Icon name="send" size={15} title="Send" /></motion.button>
          </div>
        </div>
      </motion.div>
    </div>
  );
}