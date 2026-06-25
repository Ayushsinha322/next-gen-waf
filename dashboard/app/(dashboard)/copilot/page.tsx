"use client";
import { useState, useRef, useEffect } from "react";
import { motion } from "framer-motion";
import { GREET } from "@/lib/aiResponses";
import { spring } from "@/lib/animations";

function fmt(text: string) {
  return text.replace(/\n/g,"<br>").replace(/\*\*(.*?)\*\*/g,"<strong>$1</strong>").replace(/`(.*?)`/g,'<code style="background:rgba(255,255,255,.08);padding:1px 5px;border-radius:3px;font-size:12px">$1</code>').replace(/```([\s\S]*?)```/g,'<pre style="background:rgba(0,0,0,.3);padding:8px;border-radius:6px;font-size:12px;margin:5px 0;overflow-x:auto;white-space:pre-wrap">$1</pre>');
}

const CONVOS = ["SQLi on /api/login","Log4Shell probe analysis","False positive CRS-920420","Rate limit tuning","CVE-2024-1234 patch","Bot detector JA4 tune"];
const QUICK_ACTIONS = [["explain","🔍 Explain Alert"],["rule","📝 Write Rule"],["report","📊 Threat Summary"],["fp","🐛 Fix False Positive"],["patch","⚡ Patch CVE"],["tune","⚙️ Tune ML Threshold"]];

export default function CopilotPage() {
  const [msgs, setMsgs] = useState<{who:"ai"|"usr";text:string;time:string}[]>([]);
  const [typing, setTyping] = useState(false);
  const [input, setInput] = useState("");
  const [activeConvo, setActiveConvo] = useState(0);
  const msgsRef = useRef<HTMLDivElement>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const t = setTimeout(() => {
      const now = new Date().toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"});
      setMsgs([{ who:"ai", text:GREET, time:now }]);
    }, 300);
    return () => clearTimeout(t);
  }, []);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [msgs, typing]);

  async function sendMsg(text: string) {
    const now = new Date().toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"});
    setMsgs(p => [...p, { who:"usr", text, time:now }]);
    setTyping(true);
    try {
      const history = msgs.map(m => ({ role: m.who === "ai" ? "assistant" : "user", content: m.text }));
      const res = await fetch("https://ai.enlight.dev/api/chat/completions", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${process.env.NEXT_PUBLIC_ENLIGHT_API_KEY}` },
        body: JSON.stringify({
          model: "deepseek-r1:8b",
          messages: [
            { role: "system", content: "You are Sentinel AI Copilot, an elite cybersecurity assistant integrated into an enterprise Web Application Firewall (WAF). Your job is to analyze SQLi, XSS, and DDoS threats, explain logs, and help write WAF rules. Keep answers concise, technical, and accurate. Do not hallucinate." },
            ...history,
            { role: "user", content: text },
          ],
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(`API ${res.status}: ${data.error?.message ?? JSON.stringify(data)}`);
      const reply = data.choices?.[0]?.message?.content
        ?? data.response ?? data.content ?? data.message
        ?? `⚠️ Unexpected format: ${JSON.stringify(data).slice(0, 300)}`;
      const now2 = new Date().toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"});
      setTyping(false);
      setMsgs(p => [...p, { who:"ai", text:reply, time:now2 }]);
    } catch (err: unknown) {
      const now2 = new Date().toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"});
      setTyping(false);
      const msg = err instanceof Error ? err.message : String(err);
      setMsgs(p => [...p, { who:"ai", text:`⚠️ ${msg}`, time:now2 }]);
    }
  }

  function send() { if(!input.trim()) return; sendMsg(input.trim()); setInput(""); }

  return (
    <div className="sec">
      <motion.div initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={spring} style={{display:"flex",alignItems:"flex-start",justifyContent:"space-between",gap:14}}>
        <div><div className="sec-title" style={{color:"#BF7FFF"}}>🤖 AI Security Copilot</div><div className="sec-sub">Powered by DeepSeek R1 · Rule generation · CVE patching · Alert explanation</div></div>
        <div style={{display:"flex",gap:8,alignItems:"center"}}>
          <span style={{fontSize:9,fontFamily:"'Share Tech Mono',monospace",color:"#A070E0",background:"rgba(124,47,191,.15)",border:"1px solid rgba(124,47,191,.3)",borderRadius:20,padding:"4px 12px"}}>deepseek-r1:8b</span>
          <motion.button className="btn bg-btn btn-sm" whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }} onClick={() => { setMsgs([]); setTimeout(() => { const now=new Date().toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"}); setMsgs([{who:"ai",text:GREET,time:now}]); },100); }}>🗑️ Clear Chat</motion.button>
        </div>
      </motion.div>

      <motion.div className="cop-page" initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ ...spring, delay: 0.1 }}>
        <div className="cop-hist">
          <div style={{padding:"13px 16px",borderBottom:"1px solid rgba(124,47,191,.15)",display:"flex",alignItems:"center",justifyContent:"space-between"}}>
            <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:12,fontWeight:700,letterSpacing:1}}>💬 Conversations</div>
            <motion.button className="btn bg-btn btn-xs" onClick={() => { setMsgs([]); }} whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.96 }}>＋</motion.button>
          </div>
          <div style={{flex:1,overflowY:"auto",padding:8}}>
            {CONVOS.map((c,i) => <div key={i} className={`hi ${activeConvo===i?"active":""}`} onClick={() => setActiveConvo(i)}>{c}</div>)}
          </div>
        </div>

        <div className="cop-main">
          <div style={{padding:"14px 18px",borderBottom:"1px solid rgba(124,47,191,.15)",display:"flex",alignItems:"center",gap:12,background:"linear-gradient(135deg,rgba(124,47,191,.12),transparent)",flexShrink:0}}>
            <motion.div animate={{ boxShadow: ["0 0 18px var(--pur-glow)", "0 0 32px rgba(124,58,237,.6)", "0 0 18px var(--pur-glow)"] }} transition={{ duration: 3, repeat: Infinity }} style={{width:40,height:40,borderRadius:"50%",background:"linear-gradient(135deg,var(--purple),#4A0FA0)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:22}}>🤖</motion.div>
            <div>
              <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:13,fontWeight:700}}>Sentinel AI Copilot</div>
              <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:9,color:"#9B60E0",display:"flex",alignItems:"center",gap:5,marginTop:2}}>
                <span style={{width:5,height:5,borderRadius:"50%",background:"var(--green)",boxShadow:"0 0 5px var(--green)",display:"inline-block"}} />Online · Ready to assist
              </div>
            </div>
            <div style={{marginLeft:"auto",fontSize:9,fontFamily:"'Share Tech Mono',monospace",color:"#A070E0",background:"rgba(124,47,191,.15)",border:"1px solid rgba(124,47,191,.3)",borderRadius:20,padding:"3px 10px"}}>⚡ deepseek-r1:8b</div>
          </div>

          <div ref={msgsRef} className="flex-1 overflow-y-auto" style={{padding:"16px 18px",display:"flex",flexDirection:"column",gap:12}}>
            {msgs.map((m,i) => (
              <motion.div key={i} className={`msg2 ${m.who}`} initial={{ opacity: 0, y: 8, scale: 0.98 }} animate={{ opacity: 1, y: 0, scale: 1 }} transition={{ duration: 0.25 }}>
                <div className={`mav2 ${m.who}`}>{m.who==="ai"?"🤖":"👤"}</div>
                <div>
                  <div className="mbbl2" dangerouslySetInnerHTML={{__html:fmt(m.text)}} />
                  <div className="mt3">{m.time}</div>
                </div>
              </motion.div>
            ))}
            {typing && (
              <motion.div className="msg2 ai" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                <div className="mav2 ai">🤖</div>
                <div style={{display:"flex",gap:4,alignItems:"center",padding:"10px 13px",background:"rgba(124,47,191,.14)",border:"1px solid rgba(124,47,191,.24)",borderRadius:"3px 12px 12px 12px"}}>
                  <div className="tyd"/><div className="tyd"/><div className="tyd"/>
                </div>
              </motion.div>
            )}
            <div ref={messagesEndRef} />
          </div>

          <div style={{padding:"8px 18px",borderTop:"1px solid rgba(124,47,191,.15)",display:"flex",gap:6,flexWrap:"wrap",flexShrink:0}}>
            {QUICK_ACTIONS.map(([k,l]) => <motion.button key={k} className="qbtn2" onClick={() => sendMsg(l)} whileHover={{ scale: 1.04 }} whileTap={{ scale: 0.97 }}>{l}</motion.button>)}
          </div>
          <div style={{padding:"12px 18px",borderTop:"1px solid rgba(124,47,191,.18)",display:"flex",gap:10,alignItems:"flex-end",background:"rgba(124,47,191,.04)",flexShrink:0}}>
            <textarea className="cop-inp2" value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => { if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();send();} }} placeholder="Ask about alerts, rules, CVEs, false positives, threat analysis..." />
            <motion.button style={{width:38,height:38,borderRadius:9,background:"linear-gradient(135deg,var(--purple),#4A0FA0)",border:"none",cursor:"pointer",display:"flex",alignItems:"center",justifyContent:"center",fontSize:16,transition:"all .2s",flexShrink:0}} onClick={send} whileHover={{ scale: 1.08 }} whileTap={{ scale: 0.94 }}>➤</motion.button>
          </div>
        </div>
      </motion.div>
    </div>
  );
}