"use client";
/**
 * SiteWizard — a friendly, full-screen, multi-step wizard for adding and
 * editing protected sites. Designed to be dramatically easier than BunkerWeb:
 *   • Easy mode: 3 steps + one-click security templates (most users never
 *     touch anything else).
 *   • Advanced mode: full control over upstream LB, WAF, rate limiting,
 *     anti-DDoS, bot/geo/IP filtering, request limits, and ML — all from the UI.
 * Everything maps to the rich per-site config the data plane already supports.
 */
import { useMemo, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { showToast } from "@/components/ui/Toast";
import { api } from "@/lib/api";
import {
  SiteForm, emptyForm, applyPreset, formToPayload, PRESETS, CRS_CATEGORIES,
  ALL_CRS_KEYS, COUNTRIES, PresetKey, UpstreamServer, normalizeDomain,
} from "@/lib/siteConfig";

type Mode = "create" | "edit";

interface Props {
  mode:     Mode;
  siteId?:  string;
  initial?: SiteForm;
  onClose:  () => void;
  onSaved:  (deployedDomain?: string) => void;
}

/* ── small controlled primitives ─────────────────────────────── */
function Sw({ on, set }: { on: boolean; set: (v: boolean) => void }) {
  return <div className={`tog ${on ? "on" : ""}`} onClick={() => set(!on)} style={{ cursor: "pointer" }} />;
}

function ChipInput({
  values, onChange, placeholder, mono = true, validate, transform,
}: {
  values: string[]; onChange: (v: string[]) => void; placeholder: string;
  mono?: boolean; validate?: (s: string) => boolean; transform?: (s: string) => string;
}) {
  const [draft, setDraft] = useState("");
  function add() {
    const v = transform ? transform(draft) : draft.trim();
    if (!v) return;
    if (validate && !validate(v)) { showToast("Invalid value", "e", "⚠️"); return; }
    if (!values.includes(v)) onChange([...values, v]);
    setDraft("");
  }
  return (
    <div>
      <div style={{ display: "flex", gap: 8 }}>
        <input
          className="fin2" placeholder={placeholder} value={draft}
          style={mono ? { fontFamily: "'Share Tech Mono',monospace" } : undefined}
          onChange={e => setDraft(e.target.value)}
          onKeyDown={e => { if (e.key === "Enter") { e.preventDefault(); add(); } }}
        />
        <button className="btn bg-btn btn-sm" onClick={add} type="button">＋ Add</button>
      </div>
      {values.length > 0 && (
        <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 8 }}>
          {values.map(v => (
            <span key={v} style={{
              display: "inline-flex", alignItems: "center", gap: 6, padding: "3px 8px",
              background: "rgba(0,212,255,.1)", border: "1px solid rgba(0,212,255,.28)",
              borderRadius: 12, fontSize: 10, fontFamily: "'Share Tech Mono',monospace", color: "var(--cyan)",
            }}>
              {v}
              <span style={{ cursor: "pointer", color: "var(--text3)" }}
                onClick={() => onChange(values.filter(x => x !== v))}>✕</span>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="fg2">
      <label className="flbl2">{label}</label>
      {children}
      {hint && <div style={{ fontSize: 9, color: "var(--text3)", fontFamily: "'Share Tech Mono',monospace" }}>{hint}</div>}
    </div>
  );
}

function Row({ children }: { children: React.ReactNode }) {
  return <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>{children}</div>;
}

function SectionToggle({ label, desc, on, set }: { label: string; desc: string; on: boolean; set: (v: boolean) => void }) {
  return (
    <div style={{
      display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12,
      padding: "10px 14px", background: "rgba(255,255,255,.03)",
      border: "1px solid rgba(255,255,255,.07)", borderRadius: "var(--r2)",
    }}>
      <div>
        <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text)" }}>{label}</div>
        <div style={{ fontSize: 10, color: "var(--text3)", marginTop: 2 }}>{desc}</div>
      </div>
      <Sw on={on} set={set} />
    </div>
  );
}

/* ── steps ───────────────────────────────────────────────────── */
const EASY_STEPS     = ["Basics", "Reverse Proxy", "Protection", "Review"];
const ADVANCED_STEPS = ["Basics", "Reverse Proxy", "WAF Rules", "Rate & DDoS", "Bots / Geo / IP", "Advanced", "Review"];

export default function SiteWizard({ mode, siteId, initial, onClose, onSaved }: Props) {
  const [adv, setAdv]   = useState(mode === "edit");
  const [step, setStep] = useState(0);
  const [form, setForm] = useState<SiteForm>(initial ?? emptyForm());
  const [saving, setSaving] = useState(false);

  const steps = adv ? ADVANCED_STEPS : EASY_STEPS;
  const upd = (patch: Partial<SiteForm>) => setForm(f => ({ ...f, ...patch }));

  // Map a wizard step index to a logical screen id (easy mode skips some).
  const screen = useMemo(() => {
    if (!adv) return ["basics", "proxy", "protect", "review"][step];
    return ["basics", "proxy", "rules", "rate", "bots", "advanced", "review"][step];
  }, [adv, step]);

  function setServer(i: number, patch: Partial<UpstreamServer>) {
    upd({ servers: form.servers.map((s, idx) => idx === i ? { ...s, ...patch } : s) });
  }
  function addServer() { upd({ servers: [...form.servers, { host: "127.0.0.1", port: 8080, weight: 1, tls: false }] }); }
  function rmServer(i: number) { upd({ servers: form.servers.filter((_, idx) => idx !== i) }); }

  function choosePreset(p: PresetKey) { setForm(f => applyPreset(f, p)); }

  // Full validation used only at deploy/save time — navigation between steps
  // is always free so the user can jump to any section in any order.
  function validateAll(): string | null {
    if (!form.name.trim()) return "Site name is required (Basics)";
    if (form.domains.length === 0) return "Add at least one domain (Basics)";
    if (form.servers.length === 0) return "Add at least one upstream server (Reverse Proxy)";
    if (form.servers.some(s => !s.host || !s.port)) return "Every upstream server needs a host and port (Reverse Proxy)";
    return null;
  }

  function next() { setStep(s => Math.min(s + 1, steps.length - 1)); }
  function back() { setStep(s => Math.max(s - 1, 0)); }

  async function save() {
    const err = validateAll();
    if (err) { showToast(err, "e", "⚠️"); return; }
    setSaving(true);
    try {
      const payload = formToPayload(form);
      if (mode === "edit" && siteId) {
        await api.sites.update(siteId, payload);
        showToast("Site updated", "s", "✅");
      } else {
        await api.sites.create(payload);
        showToast("Site deployed", "s", "🚀");
      }
      onSaved(form.domains[0]);
    } catch (e) {
      showToast(e instanceof Error ? e.message : "Save failed", "e", "⚠️");
    } finally {
      setSaving(false);
    }
  }

  const toggleCat = (k: string) =>
    upd({ rule_categories: form.rule_categories.includes(k)
      ? form.rule_categories.filter(x => x !== k)
      : [...form.rule_categories, k] });

  return (
    <motion.div
      style={{
        position: "fixed", inset: 0, zIndex: 1000, background: "rgba(2,6,14,.82)",
        backdropFilter: "blur(6px)", display: "flex", alignItems: "center", justifyContent: "center", padding: 24,
      }}
      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      onClick={e => { if (e.target === e.currentTarget) onClose(); }}
    >
      <motion.div
        initial={{ opacity: 0, scale: 0.96, y: 16 }} animate={{ opacity: 1, scale: 1, y: 0 }}
        transition={{ type: "spring", stiffness: 260, damping: 24 }}
        style={{
          width: "min(1040px, 96vw)", height: "min(720px, 92vh)", display: "flex",
          background: "var(--bg2, #0a1018)", border: "1px solid rgba(0,212,255,.18)",
          borderRadius: 16, overflow: "hidden", boxShadow: "0 30px 90px rgba(0,0,0,.6)",
        }}
      >
        {/* ── Sidebar / stepper ── */}
        <div style={{
          width: 248, flexShrink: 0, padding: "22px 18px", display: "flex", flexDirection: "column",
          background: "linear-gradient(180deg, rgba(0,212,255,.06), rgba(0,0,0,.15))",
          borderRight: "1px solid rgba(255,255,255,.06)",
        }}>
          <div style={{ fontFamily: "'Orbitron',sans-serif", fontWeight: 700, fontSize: 15, color: "var(--text)", letterSpacing: 1 }}>
            {mode === "edit" ? "✏️ Edit Site" : "🌐 New Protected Site"}
          </div>
          <div style={{ fontSize: 10, color: "var(--text3)", marginTop: 4, fontFamily: "'Share Tech Mono',monospace" }}>
            {mode === "edit" ? form.name : "Reverse proxy + WAF in minutes"}
          </div>

          {/* Easy / Advanced switch */}
          <div style={{ display: "flex", gap: 4, margin: "16px 0 18px", padding: 3, background: "rgba(0,0,0,.3)", borderRadius: 10 }}>
            {(["Easy", "Advanced"] as const).map((m, i) => {
              const active = (i === 1) === adv;
              return (
                <button key={m} type="button"
                  onClick={() => { setAdv(i === 1); setStep(0); }}
                  style={{
                    flex: 1, padding: "6px 0", borderRadius: 8, border: "none", cursor: "pointer",
                    fontSize: 11, fontWeight: 700, fontFamily: "'Inter',sans-serif",
                    background: active ? "linear-gradient(135deg,rgba(0,212,255,.9),rgba(0,150,210,.9))" : "transparent",
                    color: active ? "#021018" : "var(--text3)",
                  }}>{m}</button>
              );
            })}
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            {steps.map((s, i) => {
              const done = i < step, cur = i === step;
              return (
                <div key={s} onClick={() => setStep(i)}
                  style={{
                    display: "flex", alignItems: "center", gap: 10, padding: "8px 10px", borderRadius: 8,
                    cursor: "pointer",
                    background: cur ? "rgba(0,212,255,.12)" : "transparent",
                    border: cur ? "1px solid rgba(0,212,255,.3)" : "1px solid transparent",
                    transition: "background .15s",
                  }}
                  onMouseEnter={e => { if (!cur) e.currentTarget.style.background = "rgba(255,255,255,.04)"; }}
                  onMouseLeave={e => { if (!cur) e.currentTarget.style.background = "transparent"; }}>
                  <div style={{
                    width: 22, height: 22, borderRadius: "50%", flexShrink: 0, display: "flex",
                    alignItems: "center", justifyContent: "center", fontSize: 10, fontWeight: 700,
                    background: done ? "var(--green)" : cur ? "var(--cyan)" : "rgba(255,255,255,.08)",
                    color: done || cur ? "#021018" : "var(--text3)",
                  }}>{done ? "✓" : i + 1}</div>
                  <span style={{ fontSize: 12, color: cur ? "var(--text)" : "var(--text2)", fontWeight: cur ? 600 : 400 }}>{s}</span>
                </div>
              );
            })}
          </div>

          <div style={{ marginTop: "auto", fontSize: 9, color: "var(--text3)", fontFamily: "'Share Tech Mono',monospace", lineHeight: 1.6 }}>
            💡 Traffic flows through the WAF proxy on port <span style={{ color: "var(--cyan)" }}>9080</span>.
          </div>
        </div>

        {/* ── Content ── */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "16px 22px", borderBottom: "1px solid rgba(255,255,255,.06)" }}>
            <div style={{ fontFamily: "'Orbitron',sans-serif", fontSize: 14, fontWeight: 700, color: "var(--text)" }}>{steps[step]}</div>
            <button onClick={onClose} style={{ background: "none", border: "none", color: "var(--text3)", fontSize: 18, cursor: "pointer" }}>✕</button>
          </div>

          <div style={{ flex: 1, overflowY: "auto", padding: "20px 22px" }}>
            <AnimatePresence mode="wait">
              <motion.div key={screen}
                initial={{ opacity: 0, x: 12 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -12 }}
                transition={{ duration: 0.18 }}
                style={{ display: "flex", flexDirection: "column", gap: 16 }}>

                {/* ───────── BASICS ───────── */}
                {screen === "basics" && (<>
                  <Row>
                    <Field label="Site Name" hint="Internal identifier (e.g. shop-prod)">
                      <input className="fin2" placeholder="my-app" value={form.name}
                        onChange={e => upd({ name: e.target.value })} />
                    </Field>
                    <Field label="Server / WAF Mode" hint="Learning logs only; Blocking enforces">
                      <select className="fin2 fsel2" value={form.mode} onChange={e => upd({ mode: e.target.value as SiteForm["mode"] })}>
                        <option value="blocking">Blocking</option>
                        <option value="learning">Learning</option>
                        <option value="off">Off</option>
                      </select>
                    </Field>
                  </Row>
                  <Field label="Domains / Server Names" hint="Bare hostnames only (no http:// or port). Press Enter to add.">
                    <ChipInput values={form.domains} onChange={v => upd({ domains: v })} placeholder="app.example.com" transform={normalizeDomain} />
                  </Field>

                  <div style={{ fontSize: 10, color: "var(--text3)", fontFamily: "'Share Tech Mono',monospace", letterSpacing: 1, textTransform: "uppercase", marginTop: 6 }}>Security Template</div>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 10 }}>
                    {(Object.keys(PRESETS) as Array<keyof typeof PRESETS>).map(k => {
                      const p = PRESETS[k]; const active = form.preset === k;
                      return (
                        <div key={k} onClick={() => choosePreset(k)} style={{
                          cursor: "pointer", padding: 14, borderRadius: 12,
                          background: active ? "rgba(0,212,255,.1)" : "rgba(255,255,255,.03)",
                          border: active ? "1px solid rgba(0,212,255,.45)" : "1px solid rgba(255,255,255,.08)",
                        }}>
                          <div style={{ fontSize: 20 }}>{p.icon}</div>
                          <div style={{ fontWeight: 700, fontSize: 13, color: "var(--text)", marginTop: 6 }}>{p.label}</div>
                          <div style={{ fontSize: 10, color: "var(--text3)", marginTop: 4, lineHeight: 1.5 }}>{p.desc}</div>
                          <div style={{ fontSize: 9, color: "var(--cyan)", marginTop: 8, fontFamily: "'Share Tech Mono',monospace" }}>
                            PL{p.paranoia_level} · thr {p.anomaly_threshold}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </>)}

                {/* ───────── REVERSE PROXY ───────── */}
                {screen === "proxy" && (<>
                  <Field label="Load Balancing" hint="Strategy across upstream servers">
                    <select className="fin2 fsel2" value={form.lb} onChange={e => upd({ lb: e.target.value as SiteForm["lb"] })}>
                      <option value="round_robin">Round Robin</option>
                      <option value="least_conn">Least Connections</option>
                      <option value="ip_hash">IP Hash (sticky)</option>
                      <option value="random">Random</option>
                      <option value="adaptive">Adaptive (latency-aware)</option>
                    </select>
                  </Field>

                  <div style={{ fontSize: 10, color: "var(--text3)", fontFamily: "'Share Tech Mono',monospace", letterSpacing: 1, textTransform: "uppercase" }}>Upstream Servers</div>
                  {form.servers.map((s, i) => (
                    <div key={i} style={{ display: "grid", gridTemplateColumns: "2fr 1fr 0.8fr auto auto", gap: 8, alignItems: "end" }}>
                      <Field label={`Host #${i + 1}`}><input className="fin2" value={s.host} placeholder="127.0.0.1" onChange={e => setServer(i, { host: e.target.value })} /></Field>
                      <Field label="Port"><input className="fin2" type="number" value={s.port} onChange={e => setServer(i, { port: Number(e.target.value) })} /></Field>
                      <Field label="Weight"><input className="fin2" type="number" value={s.weight} onChange={e => setServer(i, { weight: Number(e.target.value) })} /></Field>
                      <div style={{ display: "flex", flexDirection: "column", gap: 4, alignItems: "center" }}>
                        <label className="flbl2">TLS</label><Sw on={s.tls} set={v => setServer(i, { tls: v })} />
                      </div>
                      <button className="btn bg-btn btn-sm" type="button" disabled={form.servers.length === 1}
                        onClick={() => rmServer(i)} style={{ opacity: form.servers.length === 1 ? 0.4 : 1 }}>🗑</button>
                    </div>
                  ))}
                  <button className="btn bg-btn btn-sm" type="button" onClick={addServer} style={{ alignSelf: "flex-start" }}>＋ Add Server</button>

                  <SectionToggle label="Active Health Checks" desc="Probe upstreams and route around failures"
                    on={form.health.enabled} set={v => upd({ health: { ...form.health, enabled: v } })} />
                  {form.health.enabled && (
                    <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr", gap: 12 }}>
                      <Field label="Path"><input className="fin2" value={form.health.path} onChange={e => upd({ health: { ...form.health, path: e.target.value } })} /></Field>
                      <Field label="Interval"><input className="fin2" value={form.health.interval} onChange={e => upd({ health: { ...form.health, interval: e.target.value } })} /></Field>
                      <Field label="Timeout"><input className="fin2" value={form.health.timeout} onChange={e => upd({ health: { ...form.health, timeout: e.target.value } })} /></Field>
                    </div>
                  )}
                </>)}

                {/* ───────── PROTECTION (easy) ───────── */}
                {screen === "protect" && (<>
                  <Row>
                    <Field label="Paranoia Level" hint="1 = fewer false positives · 4 = strictest">
                      <input className="fin2" type="number" min={1} max={4} value={form.paranoia_level} onChange={e => upd({ paranoia_level: Number(e.target.value), preset: "custom" })} />
                    </Field>
                    <Field label="Anomaly Threshold" hint="Score needed to block a request">
                      <input className="fin2" type="number" value={form.anomaly_threshold} onChange={e => upd({ anomaly_threshold: Number(e.target.value), preset: "custom" })} />
                    </Field>
                  </Row>
                  <SectionToggle label="Per-IP Rate Limiting" desc={`${form.rl_per_ip.rps} req/s · burst ${form.rl_per_ip.burst}`}
                    on={form.rate_limit_enabled} set={v => upd({ rate_limit_enabled: v })} />
                  <SectionToggle label="Bot Detection (JA4 fingerprinting)" desc="Identify automated clients by TLS fingerprint"
                    on={form.bot_ja4} set={v => upd({ bot_ja4: v })} />
                  <div style={{ padding: "10px 14px", background: "rgba(0,212,255,.06)", border: "1px solid rgba(0,212,255,.15)", borderRadius: "var(--r2)", fontSize: 10, color: "var(--text3)", lineHeight: 1.7, fontFamily: "'Share Tech Mono',monospace" }}>
                    🛡️ All OWASP CRS categories are enabled by this template. Switch to <strong style={{ color: "var(--cyan)" }}>Advanced</strong> to fine-tune rules, GeoIP, anti-DDoS and ML.
                  </div>
                </>)}

                {/* ───────── WAF RULES (advanced) ───────── */}
                {screen === "rules" && (<>
                  <Row>
                    <Field label="Paranoia Level" hint="1–4 · higher = stricter">
                      <input className="fin2" type="number" min={1} max={4} value={form.paranoia_level} onChange={e => upd({ paranoia_level: Number(e.target.value) })} />
                    </Field>
                    <Field label="Anomaly Threshold">
                      <input className="fin2" type="number" value={form.anomaly_threshold} onChange={e => upd({ anomaly_threshold: Number(e.target.value) })} />
                    </Field>
                  </Row>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <div style={{ fontSize: 10, color: "var(--text3)", fontFamily: "'Share Tech Mono',monospace", letterSpacing: 1, textTransform: "uppercase" }}>OWASP CRS Categories ({form.rule_categories.length}/{CRS_CATEGORIES.length})</div>
                    <div style={{ display: "flex", gap: 6 }}>
                      <button className="btn bg-btn btn-xs" type="button" onClick={() => upd({ rule_categories: [...ALL_CRS_KEYS] })}>All</button>
                      <button className="btn bg-btn btn-xs" type="button" onClick={() => upd({ rule_categories: CRS_CATEGORIES.filter(c => c.core).map(c => c.key) })}>Core only</button>
                    </div>
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                    {CRS_CATEGORIES.map(c => {
                      const on = form.rule_categories.includes(c.key);
                      return (
                        <div key={c.key} onClick={() => toggleCat(c.key)} style={{
                          cursor: "pointer", padding: "8px 11px", borderRadius: 8, display: "flex", justifyContent: "space-between", gap: 8,
                          background: on ? "rgba(0,230,118,.07)" : "rgba(255,255,255,.02)",
                          border: on ? "1px solid rgba(0,230,118,.3)" : "1px solid rgba(255,255,255,.07)",
                        }}>
                          <div>
                            <div style={{ fontSize: 11, fontWeight: 600, color: "var(--text)" }}>{c.label}</div>
                            <div style={{ fontSize: 9, color: "var(--text3)", marginTop: 2 }}>{c.desc}</div>
                          </div>
                          <div style={{ fontSize: 13, color: on ? "var(--green)" : "var(--text3)" }}>{on ? "✓" : "○"}</div>
                        </div>
                      );
                    })}
                  </div>
                </>)}

                {/* ───────── RATE & DDOS (advanced) ───────── */}
                {screen === "rate" && (<>
                  <SectionToggle label="Rate Limiting" desc="Token-bucket limits per IP and globally"
                    on={form.rate_limit_enabled} set={v => upd({ rate_limit_enabled: v })} />
                  {form.rate_limit_enabled && (
                    <Row>
                      <div style={{ display: "flex", flexDirection: "column", gap: 10, padding: 12, borderRadius: 10, border: "1px solid rgba(255,255,255,.07)" }}>
                        <div style={{ fontSize: 11, fontWeight: 700, color: "var(--cyan)" }}>Per-IP</div>
                        <Field label="Requests / sec"><input className="fin2" type="number" value={form.rl_per_ip.rps} onChange={e => upd({ rl_per_ip: { ...form.rl_per_ip, rps: Number(e.target.value) } })} /></Field>
                        <Field label="Burst"><input className="fin2" type="number" value={form.rl_per_ip.burst} onChange={e => upd({ rl_per_ip: { ...form.rl_per_ip, burst: Number(e.target.value) } })} /></Field>
                      </div>
                      <div style={{ display: "flex", flexDirection: "column", gap: 10, padding: 12, borderRadius: 10, border: "1px solid rgba(255,255,255,.07)" }}>
                        <div style={{ fontSize: 11, fontWeight: 700, color: "var(--cyan)" }}>Global</div>
                        <Field label="Requests / sec"><input className="fin2" type="number" value={form.rl_global.rps} onChange={e => upd({ rl_global: { ...form.rl_global, rps: Number(e.target.value) } })} /></Field>
                        <Field label="Burst"><input className="fin2" type="number" value={form.rl_global.burst} onChange={e => upd({ rl_global: { ...form.rl_global, burst: Number(e.target.value) } })} /></Field>
                      </div>
                    </Row>
                  )}
                  <SectionToggle label="Connection-rate Anti-DDoS" desc="Block IPs opening too many connections per second"
                    on={form.antiddos_enabled} set={v => upd({ antiddos_enabled: v })} />
                  {form.antiddos_enabled && (
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
                      <Field label="Conn/s limit"><input className="fin2" type="number" value={form.antiddos_conn_rate} onChange={e => upd({ antiddos_conn_rate: Number(e.target.value) })} /></Field>
                      <Field label="Burst"><input className="fin2" type="number" value={form.antiddos_burst} onChange={e => upd({ antiddos_burst: Number(e.target.value) })} /></Field>
                      <Field label="Block (secs)"><input className="fin2" type="number" value={form.antiddos_block_secs} onChange={e => upd({ antiddos_block_secs: Number(e.target.value) })} /></Field>
                    </div>
                  )}
                </>)}

                {/* ───────── BOTS / GEO / IP (advanced) ───────── */}
                {screen === "bots" && (<>
                  <SectionToggle label="JA4 Bot Fingerprinting" desc="Detect automated clients by TLS fingerprint"
                    on={form.bot_ja4} set={v => upd({ bot_ja4: v })} />
                  <Field label="Bot Challenge" hint="Challenge suspicious clients before passing">
                    <select className="fin2 fsel2" value={form.bot_challenge} onChange={e => upd({ bot_challenge: e.target.value as SiteForm["bot_challenge"] })}>
                      <option value="off">Off</option>
                      <option value="native_pow">Native Proof-of-Work</option>
                      <option value="hcaptcha">hCaptcha</option>
                      <option value="turnstile">Cloudflare Turnstile</option>
                    </select>
                  </Field>
                  <Field label="GeoIP Filtering" hint="Allow-list takes precedence over block-list">
                    <select className="fin2 fsel2" value={form.geo_mode} onChange={e => upd({ geo_mode: e.target.value as SiteForm["geo_mode"] })}>
                      <option value="off">Disabled</option>
                      <option value="block">Block selected countries</option>
                      <option value="allow">Allow only selected countries</option>
                    </select>
                  </Field>
                  {form.geo_mode !== "off" && (
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                      {COUNTRIES.map(c => {
                        const on = form.geo_countries.includes(c.code);
                        return (
                          <span key={c.code} onClick={() => upd({ geo_countries: on ? form.geo_countries.filter(x => x !== c.code) : [...form.geo_countries, c.code] })}
                            style={{
                              cursor: "pointer", padding: "4px 9px", borderRadius: 12, fontSize: 10, fontFamily: "'Share Tech Mono',monospace",
                              background: on ? (form.geo_mode === "allow" ? "rgba(0,230,118,.12)" : "rgba(255,45,85,.12)") : "rgba(255,255,255,.03)",
                              border: on ? `1px solid ${form.geo_mode === "allow" ? "rgba(0,230,118,.4)" : "rgba(255,45,85,.4)"}` : "1px solid rgba(255,255,255,.08)",
                              color: on ? "var(--text)" : "var(--text3)",
                            }}>{c.code} {c.name}</span>
                        );
                      })}
                    </div>
                  )}
                  <Row>
                    <Field label="IP / CIDR Allow-list" hint="Always permitted (overrides blocks)">
                      <ChipInput values={form.ip_allow} onChange={v => upd({ ip_allow: v })} placeholder="10.0.0.0/8" />
                    </Field>
                    <Field label="IP / CIDR Block-list" hint="Always denied">
                      <ChipInput values={form.ip_block} onChange={v => upd({ ip_block: v })} placeholder="203.0.113.7" />
                    </Field>
                  </Row>
                </>)}

                {/* ───────── ADVANCED ───────── */}
                {screen === "advanced" && (<>
                  <div style={{ fontSize: 10, color: "var(--text3)", fontFamily: "'Share Tech Mono',monospace", letterSpacing: 1, textTransform: "uppercase" }}>Request Limits</div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
                    <Field label="Max Body (MB)"><input className="fin2" type="number" value={form.max_body_size_mb} onChange={e => upd({ max_body_size_mb: Number(e.target.value) })} /></Field>
                    <Field label="Max URI (bytes)"><input className="fin2" type="number" value={form.max_uri_length} onChange={e => upd({ max_uri_length: Number(e.target.value) })} /></Field>
                    <Field label="Max Headers"><input className="fin2" type="number" value={form.max_header_count} onChange={e => upd({ max_header_count: Number(e.target.value) })} /></Field>
                  </div>
                  <SectionToggle label="ML Anomaly Detection" desc="Score requests with the bundled ML models"
                    on={form.ml_enabled} set={v => upd({ ml_enabled: v })} />
                  {form.ml_enabled && (
                    <Field label={`ML Sensitivity (${form.ml_sensitivity})`} hint="0 = lenient · 1 = aggressive">
                      <input type="range" min={0} max={1} step={0.05} value={form.ml_sensitivity}
                        onChange={e => upd({ ml_sensitivity: Number(e.target.value) })} style={{ width: "100%" }} />
                    </Field>
                  )}
                  <SectionToggle label="API Discovery" desc="Learn and document API endpoints automatically"
                    on={form.api_discovery} set={v => upd({ api_discovery: v })} />
                </>)}

                {/* ───────── REVIEW ───────── */}
                {screen === "review" && (
                  <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                    <div style={{ padding: "12px 16px", background: "rgba(0,230,118,.07)", border: "1px solid rgba(0,230,118,.25)", borderRadius: 10, fontSize: 11, color: "var(--green)", fontFamily: "'Share Tech Mono',monospace" }}>
                      ✅ Review your configuration, then {mode === "edit" ? "save changes" : "deploy"}. Protection activates in ~5s.
                    </div>
                    {[
                      ["Name", form.name || "—"],
                      ["Domains", form.domains.join(", ") || "—"],
                      ["Mode", form.mode.toUpperCase()],
                      ["Upstreams", form.servers.map(s => `${s.host}:${s.port}${s.tls ? " (TLS)" : ""}`).join(", ")],
                      ["Load Balancer", form.lb],
                      ["Paranoia / Threshold", `PL${form.paranoia_level} · ${form.anomaly_threshold}`],
                      ["CRS Categories", `${form.rule_categories.length} enabled`],
                      ["Rate Limit", form.rate_limit_enabled ? `${form.rl_per_ip.rps}/s per IP` : "off"],
                      ["Anti-DDoS", form.antiddos_enabled ? `${form.antiddos_conn_rate} conn/s` : "off"],
                      ["Bot JA4", form.bot_ja4 ? "on" : "off"],
                      ["GeoIP", form.geo_mode === "off" ? "off" : `${form.geo_mode} ${form.geo_countries.join(",")}`],
                      ["IP Lists", `${form.ip_allow.length} allow · ${form.ip_block.length} block`],
                      ["ML", form.ml_enabled ? `on (${form.ml_sensitivity})` : "off"],
                    ].map(([k, v]) => (
                      <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "7px 12px", background: "rgba(255,255,255,.02)", borderRadius: 8, fontSize: 11 }}>
                        <span style={{ color: "var(--text3)" }}>{k}</span>
                        <span style={{ color: "var(--text)", fontFamily: "'Share Tech Mono',monospace", textAlign: "right", maxWidth: "60%" }}>{v}</span>
                      </div>
                    ))}
                  </div>
                )}
              </motion.div>
            </AnimatePresence>
          </div>

          {/* ── Footer ── */}
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "14px 22px", borderTop: "1px solid rgba(255,255,255,.06)" }}>
            <div style={{ fontSize: 10, color: "var(--text3)", fontFamily: "'Share Tech Mono',monospace" }}>Step {step + 1} / {steps.length}</div>
            <div style={{ display: "flex", gap: 8 }}>
              <button className="btn bg-btn" type="button" onClick={step === 0 ? onClose : back}>{step === 0 ? "Cancel" : "← Back"}</button>
              {step < steps.length - 1 && (
                <button className="btn bg-btn" type="button" onClick={next}>Next →</button>
              )}
              <button className="btn bp" type="button" disabled={saving} onClick={save}>
                {saving ? <span className="btn-spin" /> : (mode === "edit" ? "💾 Save Changes" : "🚀 Deploy Site")}
              </button>
            </div>
          </div>
        </div>
      </motion.div>
    </motion.div>
  );
}
