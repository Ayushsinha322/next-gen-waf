"use client";
import { motion } from "framer-motion";
import { showToast } from "@/components/ui/Toast";
import { staggerContainer, cardVariants, fadeUp, spring } from "@/lib/animations";

const PLUGINS = [
  { name:"JWT Validator", author:"sentinel-security · v1.2.3", ico:"🔐", desc:"Validates JWT Bearer tokens on protected routes. Supports RS256, HS256, ES256. JWKS endpoint caching.", meta:"Rust · 48KB · ⭐ 4.9", status:"installed" },
  { name:"GeoIP Blocker", author:"sentinel-security · v2.0.1", ico:"🌍", desc:"Country-level blocking with MaxMind GeoLite2. Allow/deny lists per site. Bypass for whitelisted IPs.", meta:"Rust · 82KB · ⭐ 4.8", status:"installed" },
  { name:"Custom Headers", author:"sentinel-security · v1.0.4", ico:"📨", desc:"Inject, remove, or rewrite request/response headers. CSP policy injection. HSTS enforcement.", meta:"Go · 28KB · ⭐ 4.7", status:"installed" },
  { name:"GraphQL Shield", author:"community · v0.9.0", ico:"📊", desc:"GraphQL query complexity analysis, depth limiting, introspection blocking, field-level authorization.", meta:"AssemblyScript · 61KB · ⭐ 4.6", status:"update" },
  { name:"Slack Alerter", author:"community · v1.1.0", ico:"💬", desc:"Real-time Slack notifications for critical alerts. Configurable severity thresholds, site filtering, and channel routing.", meta:"Go · 19KB · ⭐ 4.5", status:"available" },
  { name:"Bot CAPTCHA", author:"sentinel-security · v2.0.0", ico:"🤖", desc:"Invisible CAPTCHA challenge for suspicious user agents. hCaptcha / Cloudflare Turnstile integration.", meta:"Rust · 95KB · ⭐ 4.8", status:"available" },
];

export default function PluginsPage() {
  return (
    <motion.div className="sec" variants={staggerContainer} initial="hidden" animate="visible">
      <motion.div variants={fadeUp} style={{display:"flex",alignItems:"flex-start",justifyContent:"space-between",gap:14}}>
        <div><div className="sec-title">WASM Plugin Marketplace</div><div className="sec-sub">WebAssembly plugin runtime — Rust / Go / AssemblyScript SDKs — OCI registry</div></div>
        <div style={{display:"flex",gap:8}}>
          <motion.button className="btn bc btn-sm" onClick={() => showToast("Upload dialog opened","i","📦")} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>📦 Upload Plugin</motion.button>
          <motion.button className="btn bp btn-sm" onClick={() => showToast("Browsing OCI registry...","i","🔍")} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>🔍 Browse Registry</motion.button>
        </div>
      </motion.div>

      <motion.div variants={staggerContainer} initial="hidden" animate="visible" style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:12}}>
        {[{cls:"kg",lbl:"Installed",val:"3",valCls:"g"},{cls:"kc",lbl:"Available",val:"14",valCls:"c"},{cls:"ka",lbl:"Updates",val:"2",valCls:"a"},{cls:"",lbl:"WASM Runtime",val:"wasmtime 14.0",valCls:""}].map((k,i)=>(
          <motion.div key={i} className={`kpi ${k.cls}`} variants={cardVariants}>
            <div className="kpi-lbl">{k.lbl}</div>
            <div className="kpi-val" style={k.valCls?{}:{color:"var(--green)",fontSize: 16,paddingTop:4}}>{k.val}</div>
          </motion.div>
        ))}
      </motion.div>

      <motion.div variants={staggerContainer} initial="hidden" animate="visible" style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:14}}>
        {PLUGINS.map((p, idx) => (
          <motion.div key={p.name} className="pc" variants={cardVariants} custom={idx}>
            <div style={{display:"flex",alignItems:"flex-start",gap:12}}>
              <motion.div className="pci" whileHover={{ scale: 1.12, rotate: 5 }} transition={spring}>{p.ico}</motion.div>
              <div><div className="pcn">{p.name}</div><div className="pca">{p.author}</div></div>
            </div>
            <div className="pcd">{p.desc}</div>
            <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",gap:8}}>
              <div style={{fontSize: 11,fontFamily:"'Share Tech Mono',monospace",color:"var(--text3)"}}>{p.meta}</div>
              <div style={{display:"flex",gap:5}}>
                {p.status==="installed" && <><span className="bdg bgg">INSTALLED</span><motion.button className="btn bg-btn btn-xs" onClick={() => showToast(`${p.name} configured`,"i","⚙️")} whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.96 }}>⚙️ Config</motion.button></>}
                {p.status==="update" && <><span className="bdg ba blink">UPDATE</span><motion.button className="btn bp btn-xs" onClick={() => showToast(`${p.name} updating...`,"i","🔌")} whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.96 }}>Update</motion.button></>}
                {p.status==="available" && <><span className="bdg bgr">AVAILABLE</span><motion.button className="btn bp btn-xs" onClick={() => showToast(`${p.name} installing...`,"i","🔌")} whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.96 }}>Install</motion.button></>}
              </div>
            </div>
          </motion.div>
        ))}
      </motion.div>
    </motion.div>
  );
}