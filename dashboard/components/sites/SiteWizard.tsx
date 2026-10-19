"use client";
import Icon, { type IconName } from "@/components/ui/Icon";
/**
 * SiteWizard — full-screen, multi-step wizard for adding and editing protected
 * sites. Designed to be clearer AND more capable than BunkerWeb:
 *   • Easy mode (5 steps): name, front service (HTTPS + cert), upstream host:port,
 *     protection template, review — a client can be live in a minute.
 *   • Advanced mode (10 steps): the full "Front Service" surface (public exposure
 *     + complete TLS/ACME/custom-cert configuration), reverse proxy, WAF rules,
 *     rate/DDoS, antibot, geo/IP, HTTP headers and ML.
 *
 * Honesty tags on every section:
 *   ● Enforced — the data plane acts on it today
 *   ◐ Stored   — carried through / honoured where supported (e.g. DNS-01,
 *                ZeroSSL API tuning, custom-cert-by-path are roadmap)
 */
import { useEffect, useMemo, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { showToast } from "@/components/ui/Toast";
import { api, type Certificate, type Plugin, type SiteConfigProblem } from "@/lib/api";
import { isCountryCode, countryCodeProblem, countryName, isIpOrCidr } from "@/lib/netValidate";
import {
  SiteForm, emptyForm, applyPreset, formToPayload, PRESETS, CRS_CATEGORIES,
  CRS_REQUEST_CATEGORIES, CRS_RESPONSE_CATEGORIES, ALL_CRS_RESPONSE_KEYS, type CrsCategory,
  ALL_CRS_KEYS, COUNTRIES, PresetKey, UpstreamServer, normalizeDomain,
  HTTP_METHODS, ACME_PROVIDERS, CustomHeader, certCoversHost, servingCertFor,
  checkSiteLimits, type LimitCheck, INSPECTION_LIMIT_DEFAULTS,
  JWT_ALGORITHMS, FUSION_ENGINES, IpFeed, SERVER_POLICY_DEFAULTS, policyKeyUnset,
} from "@/lib/siteConfig";

/** A number input's value for a field where "" means unset. */
const optionalNumber = (v: string): number | "" => (v.trim() === "" ? "" : Number(v));

/** The limit checks that concern the given fields, shown next to those fields. */
function LimitNotes({ checks, fields }: { checks: LimitCheck[]; fields: LimitCheck["field"][] }) {
  const mine = checks.filter(c => fields.includes(c.field));
  if (mine.length === 0) return null;
  return (
    <div style={{ display: "grid", gap: 6, marginTop: 8 }}>
      {mine.map((c, i) => (
        <div key={i} role={c.level === "error" ? "alert" : undefined} style={{
          fontSize: 13, lineHeight: 1.5, padding: "8px 11px", borderRadius: 8,
          color: c.level === "error" ? "var(--red)" : "var(--amber)",
          background: c.level === "error" ? "color-mix(in srgb, var(--red) 10%, transparent)" : "var(--amber-t)",
          border: `1px solid ${c.level === "error" ? "color-mix(in srgb, var(--red) 35%, transparent)" : "color-mix(in srgb, var(--amber) 32%, transparent)"}`,
        }}>
          <strong>{c.level === "error" ? "Cannot deploy: " : "Check: "}</strong>{c.message}
        </div>
      ))}
    </div>
  );
}

/** All names a cert presents (primary domain + SANs), lowercased. */
function certNames(c: Certificate): string[] {
  return [c.domain, ...(c.san ?? [])].filter(Boolean).map(s => s.toLowerCase());
}

type Mode = "create" | "edit";

interface Props {
  mode:     Mode;
  siteId?:  string;
  initial?: SiteForm;
  onClose:  () => void;
  onSaved:  (deployedDomain?: string) => void;
}

/* ── primitives ─────────────────────────────────────────────── */
function Sw({ on, set }: { on: boolean; set: (v: boolean) => void }) {
  return <div className={`tog ${on ? "on" : ""}`} onClick={() => set(!on)} style={{ cursor: "pointer" }} />;
}

// Three states, and the difference between them matters to whoever is configuring
// a site:
//   enforced    the data plane reads this and acts on it
//   stored      persisted and readable back, but nothing enforces it yet
//   unavailable not wired up at all — the control is disabled so no one can set a
//               value that would look saved and silently do nothing
function Tag({ kind }: { kind: "enforced" | "stored" | "unavailable" }) {
  const palette = {
    enforced:    { fg: "var(--green)",            bg: "var(--green-t)",  bd: "var(--green-t)",  text: "● Enforced" },
    // Said plainly: "Stored" read as a neutral state, but these settings are saved
    // with the site and the data plane does not act on them in this release.
    stored:      { fg: "var(--amber)",   bg: "var(--amber-t)", bd: "var(--amber-t)", text: "◐ Not enforced yet" },
    unavailable: { fg: "var(--text3)",            bg: "var(--fill-soft)", bd: "var(--fill-h)", text: "○ Unavailable" },
  }[kind];
  const title = kind === "stored"
    ? "Saved with the site, but the data plane does not act on it in this release. Do not rely on it for protection."
    : undefined;
  return (
    <span title={title} style={{
      fontSize: 10.5, fontWeight: 700, padding: "2px 7px", borderRadius: 20,
      fontFamily: "var(--font-sans)",
      color: palette.fg, background: palette.bg, border: `1px solid ${palette.bd}`,
    }}>{palette.text}</span>
  );
}

function StepHead({ title, sub, tag }: { title: string; sub: string; tag?: "enforced" | "stored" }) {
  return (
    <div style={{ marginBottom: 4 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <span style={{ fontFamily: "var(--font-display)", fontSize: 17, fontWeight: 700, color: "var(--text)" }}>{title}</span>
        {tag && <Tag kind={tag} />}
      </div>
      <div style={{ fontSize: 13, color: "var(--text3)", marginTop: 3 }}>{sub}</div>
    </div>
  );
}

function ChipInput({
  values, onChange, placeholder, mono = true, validate, transform, invalidMessage, label,
}: {
  values: string[]; onChange: (v: string[]) => void; placeholder: string;
  mono?: boolean; validate?: (s: string) => boolean; transform?: (s: string) => string;
  /** What to tell the operator when `validate` refuses an entry. */
  invalidMessage?: (s: string) => string;
  /** Display text for a chip (the stored value is unchanged). */
  label?: (s: string) => string;
}) {
  const [draft, setDraft] = useState("");
  function add() {
    const v = transform ? transform(draft) : draft.trim();
    if (!v) return;
    if (validate && !validate(v)) { showToast(invalidMessage ? invalidMessage(v) : "Invalid value", "e"); return; }
    if (!values.includes(v)) onChange([...values, v]);
    setDraft("");
  }
  return (
    <div>
      <div style={{ display: "flex", gap: 8 }}>
        <input className="fin2" placeholder={placeholder} value={draft}
          style={mono ? { fontFamily: "var(--font-mono)" } : undefined}
          onChange={e => setDraft(e.target.value)}
          onKeyDown={e => { if (e.key === "Enter") { e.preventDefault(); add(); } }} />
        <button className="btn bg-btn btn-sm" onClick={add} type="button">＋ Add</button>
      </div>
      {values.length > 0 && (
        <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 8 }}>
          {values.map(v => {
            // A stored value that would be refused today (saved before validation
            // existed) is shown — in red, removable — never hidden: a hidden entry
            // is one the operator cannot find, let alone fix.
            const bad = validate ? !validate(v) : false;
            return (
              <span key={v} title={bad && invalidMessage ? invalidMessage(v) : undefined} style={{
                display: "inline-flex", alignItems: "center", gap: 6, padding: "3px 8px",
                background: bad ? "var(--red-t)" : "var(--accent-tint)",
                border: `1px solid ${bad ? "color-mix(in srgb, var(--red) 32%, transparent)" : "var(--accent-line)"}`,
                borderRadius: 12, fontSize: 14, fontFamily: "var(--font-sans)", color: bad ? "var(--red-b)" : "var(--cyan)",
              }}>
                {label ? label(v) : v}{bad ? " — invalid" : ""}<span style={{ cursor: "pointer", color: "var(--text3)" }} onClick={() => onChange(values.filter(x => x !== v))}>✕</span>
              </span>
            );
          })}
        </div>
      )}
    </div>
  );
}

// `unavailable` dims the field and appends the reason to the hint. It does NOT
// disable the child input by itself — pass `disabled` to that too, so a value
// cannot be typed into a control that nothing reads.
function Field({ label, hint, children, unavailable }: {
  label: string; hint?: string; children: React.ReactNode; unavailable?: string;
}) {
  return (
    <div className="fg2" style={unavailable ? { opacity: 0.55 } : undefined}>
      <label className="flbl2">
        {label}
        {unavailable && <> <Tag kind="unavailable" /></>}
      </label>
      {children}
      {hint && <div style={{ fontSize: 11, color: "var(--text3)", fontFamily: "var(--font-sans)" }}>{hint}</div>}
      {unavailable && (
        <div style={{ fontSize: 11, color: "var(--text3)", fontFamily: "var(--font-sans)" }}>{unavailable}</div>
      )}
    </div>
  );
}

function SecretInput({ value, set, placeholder }: { value: string; set: (v: string) => void; placeholder?: string }) {
  const [show, setShow] = useState(false);
  return (
    <div style={{ position: "relative" }}>
      <input className="fin2" type={show ? "text" : "password"} value={value} placeholder={placeholder}
        style={{ fontFamily: "var(--font-mono)", paddingRight: 34 }}
        onChange={e => set(e.target.value)} />
      <span onClick={() => setShow(s => !s)} title={show ? "Hide" : "Reveal"}
        style={{ position: "absolute", right: 10, top: "50%", transform: "translateY(-50%)", cursor: "pointer", color: "var(--text3)", fontSize: 15 }}>
        <Icon name={show ? "eye-off" : "eye"} size={16} />
      </span>
    </div>
  );
}

function Row({ children, cols = "1fr 1fr" }: { children: React.ReactNode; cols?: string }) {
  return <div style={{ display: "grid", gridTemplateColumns: cols, gap: 12 }}>{children}</div>;
}

// `unavailable` renders the toggle inert: dimmed, labelled, and `set` is dropped
// so flipping it cannot record an intent nothing acts on.
function SectionToggle({ label, desc, on, set, unavailable }: {
  label: string; desc: string; on: boolean; set: (v: boolean) => void; unavailable?: string;
}) {
  return (
    <div style={{
      display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12,
      padding: "10px 14px", background: "var(--fill-soft)",
      border: "1px solid var(--card-bd)", borderRadius: "var(--r2)",
      opacity: unavailable ? 0.55 : 1,
    }}>
      <div>
        <div style={{ fontSize: 14, fontWeight: 600, color: "var(--text)" }}>
          {label}
          {unavailable && <> <Tag kind="unavailable" /></>}
        </div>
        <div style={{ fontSize: 14, color: "var(--text3)", marginTop: 2 }}>
          {unavailable || desc}
        </div>
      </div>
      <Sw on={unavailable ? false : on} set={unavailable ? () => {} : set} />
    </div>
  );
}

function GroupLabel({ children }: { children: React.ReactNode }) {
  return <div style={{ fontSize: 14, color: "var(--text3)", fontFamily: "var(--font-sans)", marginTop: 4, display: "flex", alignItems: "center", gap: 8 }}>{children}</div>;
}

/* One selectable CRS category tile. Extracted so the request and response
 * groups render identically — they differ only in which list they map over. */
function CatTile({ c, on, onClick }: { c: CrsCategory; on: boolean; onClick: () => void }) {
  return (
    <div onClick={onClick} style={{ cursor: "pointer", padding: "8px 11px", borderRadius: 8, display: "flex", justifyContent: "space-between", gap: 8, background: on ? "var(--green-t)" : "var(--fill-soft)", border: on ? "1px solid color-mix(in srgb, var(--green) 32%, transparent)" : "1px solid var(--card-bd)" }}>
      <div>
        <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text)" }}>{c.label}</div>
        <div style={{ fontSize: 11, color: "var(--text3)", marginTop: 2 }}>{c.desc}</div>
      </div>
      <div style={{ fontSize: 15, color: on ? "var(--green)" : "var(--text3)" }}>{on ? "✓" : "○"}</div>
    </div>
  );
}

function InfoBox({ children, tone = "cyan" }: { children: React.ReactNode; tone?: "cyan" | "green" | "amber" }) {
  const c = tone === "green" ? ["var(--green-t)", "var(--green-t)"]
          : tone === "amber" ? ["var(--amber-t)", "var(--amber-t)"]
          : ["var(--accent-tint)", "var(--accent-tint-h)"];
  return (
    <div style={{ padding: "10px 14px", background: c[0], border: `1px solid ${c[1]}`, borderRadius: "var(--r2)", fontSize: 12.5, color: "var(--text3)", lineHeight: 1.7, fontFamily: "var(--font-mono)" }}>
      {children}
    </div>
  );
}

/* ── steps ───────────────────────────────────────────────────── */
const EASY_STEPS     = ["Basics", "Front Service", "Reverse Proxy", "Protection", "Review"];
const ADVANCED_STEPS = ["Basics", "Front Service", "Reverse Proxy", "WAF Rules", "API Security", "Rate & DDoS", "Antibot", "Geo & IP", "HTTP Headers", "Advanced", "Review"];

export default function SiteWizard({ mode, siteId, initial, onClose, onSaved }: Props) {
  const [adv, setAdv]   = useState(mode === "edit");
  const [step, setStep] = useState(0);
  const [form, setForm] = useState<SiteForm>(initial ?? emptyForm());
  const [saving, setSaving] = useState(false);
  const [repoCerts, setRepoCerts] = useState<Certificate[]>([]);

  // Load the certificate repository so the user can assign an existing cert
  // (e.g. an enterprise wildcard) without re-uploading per site.
  useEffect(() => { api.certs.list().then(r => setRepoCerts(r.certs ?? [])).catch(() => {}); }, []);
  // Installed plugins, for the per-site selection on the Advanced step. Plugins
  // are opt-in per site: installing and enabling one makes the module available
  // to the fleet, and a site runs it only when it is ticked there.
  const [installedPlugins, setInstalledPlugins] = useState<Plugin[]>([]);
  useEffect(() => { api.plugins.list().then(r => setInstalledPlugins(r.plugins ?? [])).catch(() => {}); }, []);
  // Escape closes, like the backdrop and Cancel already do, and like every other
  // dialog in the console (Modal, confirmAction, the event drawer). The wizard
  // draws its own overlay, so it never inherited that. A dialog opened on top
  // of it (a confirmation) takes the key instead, and nothing closes mid-save.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape" || saving) return;
      if (document.querySelector('.modal[role="dialog"]')) return;
      onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose, saving]);

  // Server-side dry run. The control plane exposes POST /sites/validate, which
  // runs the SAME conversion functions the config sync runs — so a green result
  // means the site will actually reach the proxy rather than silently vanish at
  // sync time. It was fully implemented and had never been called by anything.
  const [problems, setProblems] = useState<SiteConfigProblem[] | null>(null);
  const [checking, setChecking] = useState(false);
  const steps = adv ? ADVANCED_STEPS : EASY_STEPS;
  const upd = (patch: Partial<SiteForm>) => setForm(f => ({ ...f, ...patch }));

  const screen = useMemo(() => {
    if (!adv) return ["basics", "front", "proxy", "protect", "review"][step];
    return ["basics", "front", "proxy", "rules", "apisec", "rate", "antibot", "geoip", "headers", "advanced", "review"][step];
  }, [adv, step]);

  // Dry-run on entering Review. Non-fatal: if the endpoint is unreachable the
  // wizard still lets you deploy — this is a pre-flight check, not a gate that
  // should strand an operator when the control plane is having a bad minute.
  useEffect(() => {
    if (screen !== "review") { setProblems(null); return; }
    let alive = true;
    setChecking(true);
    api.sites.validate({ ...formToPayload(form), ...(siteId ? { site_id: siteId } : {}) })
      .then(r => { if (alive) setProblems(r.problems ?? []); })
      .catch(() => { if (alive) setProblems(null); })
      .finally(() => { if (alive) setChecking(false); });
    return () => { alive = false; };
  }, [screen]); // eslint-disable-line react-hooks/exhaustive-deps

  function setServer(i: number, patch: Partial<UpstreamServer>) {
    upd({ servers: form.servers.map((s, idx) => idx === i ? { ...s, ...patch } : s) });
  }
  function addServer() { upd({ servers: [...form.servers, { host: "127.0.0.1", port: 8080, weight: 1, tls: false }] }); }
  function rmServer(i: number) { upd({ servers: form.servers.filter((_, idx) => idx !== i) }); }
  function setHeader(i: number, patch: Partial<CustomHeader>) {
    upd({ custom_headers: form.custom_headers.map((h, idx) => idx === i ? { ...h, ...patch } : h) });
  }
  function choosePreset(p: PresetKey) { setForm(f => applyPreset(f, p)); }

  function validateAll(): string | null {
    if (!form.name.trim()) return "Site name is required (Basics)";
    if (form.domains.length === 0) return "Add at least one domain (Basics)";
    if (form.servers.length === 0) return "Add at least one upstream server (Reverse Proxy)";
    if (form.servers.some(s => !s.host || !s.port)) return "Every upstream server needs a host and port (Reverse Proxy)";
    {
      // A non-number or out-of-range port used to pass this check and then become
      // 80 in formToPayload (`Number(port) || 80`) — a silent change of origin.
      const bad = form.servers.find(s => { const n = Number(s.port); return !Number.isInteger(n) || n < 1 || n > 65535; });
      if (bad) return `Port "${bad.port}" for ${bad.host} is not a port number (1–65535) (Reverse Proxy)`;
    }
    if (form.tls_mode === "auto" && form.front_https && !form.acme_email.trim()) return "An email is required for automatic certificates (Front Service)";
    // "existing" with nothing selected is valid: the data plane matches a
    // repository certificate to the domain by name (SNI), or serves its
    // self-signed fallback — exactly what a site with no TLS settings does.
    if (form.tls_mode === "manual" && form.custom_priority === "data" && (!form.cert_pem.trim() || !form.key_pem.trim())) return "Paste both the certificate and private key (Front Service)";
    {
      const limitError = checkSiteLimits(form).find(c => c.level === "error");
      if (limitError) {
        const where = limitError.field === "paranoia_level" || limitError.field === "anomaly_threshold" ? "WAF Rules" : "Advanced";
        return `${limitError.message} (${where})`;
      }
    }
    if (form.tls_mode === "manual" && form.custom_priority === "file" && (!form.cert_path.trim() || !form.key_path.trim())) return "Provide both certificate and key paths (Front Service)";
    if (form.geo_mode !== "off") {
      const bad = form.geo_countries.find(c => !isCountryCode(c));
      if (bad) return `${countryCodeProblem(bad)} Remove it (Geo & IP)`;
    }
    {
      const bad = [...form.ip_allow, ...form.ip_block].find(e => !isIpOrCidr(e));
      if (bad) return `"${bad}" is not an IP address or CIDR range — remove it (Geo & IP)`;
    }
    return null;
  }

  function next() { setStep(s => Math.min(s + 1, steps.length - 1)); }
  function back() { setStep(s => Math.max(s - 1, 0)); }

  /** Best-effort TLS provisioning after the site is saved. Never blocks deploy. */
  async function provisionTls() {
    if (!form.front_https || form.tls_mode === "off") return;
    // Repository cert: nothing to issue/upload — the data plane already serves it
    // by SNI (incl. wildcard), so it's shared across every matching site.
    if (form.tls_mode === "existing") {
      if (form.tls_existing_cert)
        showToast(`Using "${form.tls_existing_cert}" from the certificate repository — served via SNI, no upload`, "i");
      return;
    }
    // DNS-01 / wildcard issuance is roadmap — config is stored, issuance skipped.
    if (form.tls_mode === "auto" && (form.acme_challenge === "dns_01" || form.acme_wildcard)) {
      showToast("Wildcard/DNS-01 saved as config — issuance via DNS-01 is on the roadmap", "i");
      return;
    }
    try {
      if (form.tls_mode === "auto") {
        const provider = form.acme_staging ? "letsencrypt_staging" : form.acme_provider;
        await api.certs.requestAcme({
          domains: form.domains, email: form.acme_email.trim(),
          provider, challenge: form.acme_challenge as "http_01" | "tls_alpn_01",
        });
        showToast(`Certificate requested for ${form.domains[0]}`, "s");
      } else if (form.tls_mode === "manual" && form.custom_priority === "data") {
        await api.certs.uploadManual({ domain: form.domains[0], cert_pem: form.cert_pem, key_pem: form.key_pem });
        showToast(`Certificate installed for ${form.domains[0]}`, "s");
      } else {
        showToast("Custom certificate paths saved — loaded by the node from disk", "i");
      }
    } catch (e) {
      showToast(`Site saved, TLS pending: ${e instanceof Error ? e.message : "cert error"}`, "e");
    }
  }

  async function save() {
    const err = validateAll();
    if (err) { showToast(err, "e"); return; }
    setSaving(true);
    try {
      const payload = formToPayload(form);
      if (mode === "edit" && siteId) { await api.sites.update(siteId, payload); await provisionTls(); showToast("Site updated", "s"); }
      else { await api.sites.create(payload); await provisionTls(); showToast("Site deployed", "s"); }
      onSaved(form.domains[0]);
    } catch (e) {
      showToast(e instanceof Error ? e.message : "Save failed", "e");
    } finally { setSaving(false); }
  }

  // For a key the edited site's policy leaves out, the field shows the server's
  // default, and a save keeps the key unset unless the value is changed.
  const serverDefaultHint = (key: "paranoia_level" | "anomaly_threshold") =>
    policyKeyUnset(form, key) && Number(form[key]) === SERVER_POLICY_DEFAULTS[key]
      ? `Not set on this site: the server default (${SERVER_POLICY_DEFAULTS[key]}) applies, and saving keeps it unset unless you change it.`
      : undefined;

  const toggleCat = (k: string) => upd({ rule_categories: form.rule_categories.includes(k) ? form.rule_categories.filter(x => x !== k) : [...form.rule_categories, k] });
  const toggleMethod = (m: string) => upd({ allowed_methods: form.allowed_methods.includes(m) ? form.allowed_methods.filter(x => x !== m) : [...form.allowed_methods, m] });

  const scheme = form.front_https ? "https" : "http";
  const primary = form.servers[0] ?? { host: "127.0.0.1", port: 8080, weight: 1, tls: false };

  return (
    <motion.div
      style={{ position: "fixed", inset: 0, zIndex: 1000, background: "var(--scrim)", display: "flex", alignItems: "center", justifyContent: "center", padding: 24 }}
      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      onClick={e => { if (e.target === e.currentTarget) onClose(); }}>
      <motion.div
        role="dialog" aria-modal="true" aria-label={mode === "edit" ? "Edit site" : "Add site"}
        initial={{ opacity: 0, scale: 0.96, y: 16 }} animate={{ opacity: 1, scale: 1, y: 0 }}
        transition={{ type: "spring", duration: 0.32, bounce: 0 }}
        style={{ width: "min(1100px, 96vw)", height: "min(760px, 94vh)", display: "flex", background: "var(--bg2)", border: "1px solid var(--card-bd)", borderRadius: 16, overflow: "hidden", boxShadow: "var(--shadow-modal)" }}>

        {/* Sidebar / stepper */}
        <div style={{ width: 256, flexShrink: 0, padding: "22px 18px", display: "flex", flexDirection: "column", background: "var(--fill-soft)", borderRight: "1px solid var(--sep)", overflowY: "auto" }}>
          <div style={{ fontFamily: "var(--font-display)", fontWeight: 700, fontSize: 17, color: "var(--text)", letterSpacing: "-0.012em" }}>
            {mode === "edit" ? "Edit Site" : "New Protected Site"}
          </div>
          <div style={{ fontSize: 14, color: "var(--text3)", marginTop: 4, fontFamily: "var(--font-sans)" }}>
            {mode === "edit" ? form.name : "Reverse proxy + WAF in minutes"}
          </div>
          <div style={{ display: "flex", gap: 4, margin: "16px 0 18px", padding: 3, background: "var(--fill)", borderRadius: 10 }}>
            {(["Easy", "Advanced"] as const).map((m, i) => {
              const active = (i === 1) === adv;
              return (
                <button key={m} type="button" onClick={() => { setAdv(i === 1); setStep(0); }}
                  style={{ flex: 1, padding: "6px 0", borderRadius: 8, border: "none", cursor: "pointer", fontSize: 13, fontWeight: 600, fontFamily: "var(--font-sans)", background: active ? "var(--seg-on)" : "transparent", color: active ? "var(--text)" : "var(--text2)", boxShadow: active ? "0 1px 2px rgba(0,0,0,.18), 0 0 0 0.5px rgba(0,0,0,.04)" : "none", transition: "background-color .18s, color .18s" }}>{m}</button>
              );
            })}
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            {steps.map((s, i) => {
              const done = i < step, cur = i === step;
              return (
                <div key={s} onClick={() => setStep(i)}
                  style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 10px", borderRadius: 8, cursor: "pointer", background: cur ? "var(--sel)" : "transparent", border: "1px solid transparent", transition: "background .15s" }}
                  onMouseEnter={e => { if (!cur) e.currentTarget.style.background = "var(--fill-soft)"; }}
                  onMouseLeave={e => { if (!cur) e.currentTarget.style.background = "transparent"; }}>
                  <div style={{ width: 22, height: 22, borderRadius: "50%", flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 14, fontWeight: 700, background: done ? "var(--switch-on)" : cur ? "var(--accent-fill)" : "var(--fill)", color: done || cur ? "#ffffff" : "var(--text3)" }}>{done ? "✓" : i + 1}</div>
                  <span style={{ fontSize: 14, color: cur ? "var(--text)" : "var(--text2)", fontWeight: cur ? 600 : 400 }}>{s}</span>
                </div>
              );
            })}
          </div>
          <div style={{ marginTop: "auto", paddingTop: 16, fontSize: 11, color: "var(--text3)", fontFamily: "var(--font-sans)", lineHeight: 1.6 }}>
            Public traffic enters on the WAF&rsquo;s <span style={{ color: "var(--cyan)" }}>{scheme}</span> listener and is proxied to your upstreams.
          </div>
        </div>

        {/* Content */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "16px 22px", borderBottom: "1px solid var(--card-bd)" }}>
            <div style={{ fontFamily: "var(--font-display)", fontSize: 16, fontWeight: 700, color: "var(--text)" }}>{steps[step]}</div>
            <button onClick={onClose} style={{ background: "none", border: "none", color: "var(--text3)", fontSize: 20, cursor: "pointer" }}>✕</button>
          </div>

          <div style={{ flex: 1, overflowY: "auto", padding: "20px 22px" }}>
            <AnimatePresence mode="wait">
              <motion.div key={screen} initial={{ opacity: 0, x: 12 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -12 }} transition={{ duration: 0.18 }} style={{ display: "flex", flexDirection: "column", gap: 16 }}>

                {/* ───────── BASICS ───────── */}
                {screen === "basics" && (<>
                  <StepHead title="Basics" sub="Name this site, choose enforcement mode and the domains it protects." tag="enforced" />
                  <Row>
                    <Field label="Site Name" hint="Internal identifier (e.g. shop-prod)">
                      <input className="fin2" placeholder="my-app" value={form.name} onChange={e => upd({ name: e.target.value })} />
                    </Field>
                    {/* Learning is listed FIRST and is the default. A new site
                        protects an application whose false-positive rate nobody
                        has measured, so enforcing on day one blocks real users
                        on evidence that does not exist yet. The runbook, the
                        onboarding checklist and first-site.sh all say soak in
                        learning first; this control used to say the opposite by
                        defaulting to Blocking with no warning at all. */}
                    <Field label="Security Mode" hint="Learning observes and records; Blocking enforces">
                      <select className="fin2 fsel2" value={form.mode} onChange={e => upd({ mode: e.target.value as SiteForm["mode"] })}>
                        <option value="learning">Learning (recommended for a new site)</option>
                        <option value="blocking">Blocking</option>
                        <option value="off">Off</option>
                      </select>
                    </Field>
                  </Row>
                  {form.mode === "blocking" && (
                    <div style={{
                      margin: "4px 0 10px", padding: "10px 12px", borderRadius: 8,
                      border: "1px solid var(--amber)", background: "var(--amber-t)",
                      fontSize: "var(--fs-sm)", lineHeight: 1.6, color: "var(--text2)",
                    }}>
                      ⚠ <strong>Blocking enforces immediately.</strong> This application&rsquo;s
                      false-positive rate has not been measured, so legitimate requests may be
                      rejected from the moment you deploy. The recommended sequence is Learning →
                      review the would-have-blocked report → exclude the false positives → then
                      switch to Blocking. You can change mode later without a restart.
                    </div>
                  )}
                  <Field label="Server Names / Domains" hint="Bare hostnames only (no http:// or port). Press Enter to add.">
                    <ChipInput values={form.domains} onChange={v => upd({ domains: v })} placeholder="app.example.com" transform={normalizeDomain} />
                  </Field>
                  <GroupLabel>Security Template</GroupLabel>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 10 }}>
                    {(Object.keys(PRESETS) as Array<keyof typeof PRESETS>).map(k => {
                      const p = PRESETS[k]; const active = form.preset === k;
                      return (
                        <div key={k} onClick={() => choosePreset(k)} style={{ cursor: "pointer", padding: 14, borderRadius: 12, background: active ? "var(--accent-tint)" : "var(--fill-soft)", border: active ? "1px solid var(--accent-line)" : "1px solid var(--card-bd)" }}>
                          <Icon name={p.icon as IconName} size={21} />
                          <div style={{ fontWeight: 700, fontSize: 15, color: "var(--text)", marginTop: 6 }}>{p.label}</div>
                          <div style={{ fontSize: 14, color: "var(--text3)", marginTop: 4, lineHeight: 1.5 }}>{p.desc}</div>
                          <div style={{ fontSize: 11, color: "var(--cyan)", marginTop: 8, fontFamily: "var(--font-mono)" }}>PL{p.paranoia_level} · thr {p.anomaly_threshold}</div>
                        </div>
                      );
                    })}
                  </div>
                </>)}

                {/* ───────── FRONT SERVICE (exposure + full TLS) ───────── */}
                {screen === "front" && (<>
                  <StepHead title="Front Service" sub="The public, client-facing side of this site: how it's exposed and its TLS certificate." tag="stored" />

                  {/* exposure
                      Force HTTPS IS enforced (control plane → tls.redirect_http → the
                      data plane's 308), once a certificate covers the host. The other
                      toggles are still STORED only: TLS termination and http2/http3
                      are LISTENER properties with no per-site plumbing, and HSTS is
                      set under Security headers. */}
                  <InfoBox tone="amber">
                    <strong>Force HTTPS is enforced; the other switches here are saved, not applied per site.</strong>{" "}
                    Plain-HTTP requests are redirected (308) to HTTPS once a certificate
                    for the host is installed — ACME challenges excepted, and never for a
                    request a trusted load balancer already received over HTTPS. TLS
                    termination and the HTTP protocol set are properties of the WAF
                    <em> listener</em>, shared by every site on this node. The TLS
                    certificate you choose below <em>is</em> applied.
                  </InfoBox>
                  <Row cols={adv ? "1fr 1fr" : "1fr 1fr"}>
                    <SectionToggle label="Serve HTTPS" desc="Terminate TLS on the public listener" on={form.front_https} set={v => upd({ front_https: v })} />
                    <SectionToggle label="Force HTTPS redirect" desc="308 plain HTTP → HTTPS once a certificate covers the host" on={form.force_https} set={v => upd({ force_https: v })} />
                  </Row>
                  {adv && (
                    <Row>
                      <SectionToggle label="HTTP/2" desc="Multiplexed connections (TLS)" on={form.http2} set={v => upd({ http2: v })} />
                      <SectionToggle label="HTTP/3 (QUIC)" desc="UDP-based, lower latency" on={form.http3} set={v => upd({ http3: v })} />
                    </Row>
                  )}
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                    {form.domains.length === 0
                      ? <InfoBox tone="amber">Add a domain in <strong>Basics</strong> to see the public endpoint.</InfoBox>
                      : form.domains.map(d => (
                        <span key={d} style={{ padding: "5px 11px", borderRadius: 8, background: "var(--accent-tint)", border: "1px solid var(--card-bd)", fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--cyan)" }}>
                          {scheme}://{d}
                        </span>
                      ))}
                  </div>
                  {/* This used to append "→ :9443" (or :9080). Both were wrong, and
                      9443 was actively unsafe advice: it is the MANAGEMENT listener
                      (role: management in sentinel.proxy.yaml) which bypasses the WAF
                      pipeline and serves the admin console. Customer traffic is served
                      by the http/https listeners, and the port a client actually dials
                      is the PUBLISHED port, which the dashboard cannot know from here —
                      compose maps 8080→80 and 8443→443. So we show the endpoint the
                      customer uses and state the listener facts rather than guessing. */}
                  {form.domains.length > 0 && (
                    <div style={{ fontSize: "var(--fs-label)", color: "var(--text3)", marginTop: 8, lineHeight: 1.6 }}>
                      Point this domain&rsquo;s DNS at the WAF node. Traffic is served by the{" "}
                      <code style={{ fontFamily: "var(--font-mono)" }}>{form.front_https ? "https" : "http"}</code>{" "}
                      listener — never the management port, which serves this console only.
                    </div>
                  )}

                  {/* TLS mode */}
                  <GroupLabel>TLS Certificate</GroupLabel>

                  {/* WHAT IS SERVED TODAY — not what this form has selected.
                      The data plane resolves certificates by SNI out of the
                      shared store, so a site is often already served a valid
                      certificate while the selector below is empty. That empty
                      selector reads as "no certificate": on the first customer
                      deployment it sent the operator hunting for a fault in a
                      certificate that was working. State the truth first. */}
                  {form.front_https && form.domains.length > 0 && (() => {
                    const rows = form.domains.map(d => {
                      const cert = servingCertFor(repoCerts, d);
                      return { host: d, cert, covered: cert ? certCoversHost(certNames(cert), d) : false };
                    });
                    const served = rows.filter(r => r.cert);
                    if (served.length === 0) return null;
                    const allGood = rows.every(r => r.cert && r.covered);
                    return (
                      <InfoBox tone={allGood ? "green" : "amber"}>
                        <strong style={{ color: "var(--text2)" }}>Currently served</strong> — the WAF matches by hostname (SNI), so this is live whether or not a certificate is selected below:
                        <div style={{ marginTop: 6, display: "grid", gap: 3 }}>
                          {rows.map(r => {
                            const days = r.cert && r.cert.expires_at > 0
                              ? Math.round((r.cert.expires_at * 1000 - Date.now()) / 86400000) : null;
                            return (
                              <div key={r.host} style={{ fontFamily: "var(--font-mono)", fontSize: 13 }}>
                                {r.host}{" → "}
                                {r.cert ? (<>
                                  <strong style={{ color: r.covered ? "var(--green)" : "var(--amber)" }}>
                                    {r.cert.name ? `${r.cert.name} (${r.cert.domain})` : r.cert.domain}
                                  </strong>
                                  {r.cert.source ? ` · ${r.cert.source}` : ""}
                                  {days !== null && ` · expires in ${days} day${days === 1 ? "" : "s"}`}
                                  {!r.covered && " · ⚠ does not present this name — browsers will warn"}
                                </>) : (
                                  <span style={{ color: "var(--amber)" }}>no stored certificate — a self-signed one is generated, browsers will warn</span>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      </InfoBox>
                    );
                  })()}

                  {!form.front_https && <InfoBox tone="amber">HTTPS is off above — enable &ldquo;Serve HTTPS&rdquo; to configure certificates.</InfoBox>}
                  {form.front_https && (
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(2,1fr)", gap: 10 }}>
                      {([
                        ["auto", "Automatic (ACME)", "Free Let's Encrypt / ZeroSSL cert, auto-renewed"],
                        ["existing", "From Repository", "Reuse an uploaded cert (e.g. wildcard) — no re-upload"],
                        ["manual", "Upload New", "Paste your own certificate (saved to the repository)"],
                        ["off", "No certificate", "Plain HTTP only (not recommended)"],
                      ] as const).map(([k, label, desc]) => {
                        const active = form.tls_mode === k;
                        return (
                          <div key={k} onClick={() => upd({ tls_mode: k })} style={{ cursor: "pointer", padding: 13, borderRadius: 12, background: active ? "var(--accent-tint)" : "var(--fill-soft)", border: active ? "1px solid var(--accent-line)" : "1px solid var(--card-bd)" }}>
                            <div style={{ fontWeight: 700, fontSize: 14.5, color: "var(--text)" }}>{label}</div>
                            <div style={{ fontSize: 14, color: "var(--text3)", marginTop: 5, lineHeight: 1.5 }}>{desc}</div>
                          </div>
                        );
                      })}
                    </div>
                  )}

                  {/* FROM REPOSITORY — select an existing cert (enterprise wildcard etc.) */}
                  {form.front_https && form.tls_mode === "existing" && (<>
                    {repoCerts.length === 0 ? (
                      <InfoBox tone="amber">No certificates in the repository yet. Upload one on the <strong>Certificates</strong> page (or choose <strong>Upload New</strong>), then it&apos;s reusable across every matching site.</InfoBox>
                    ) : (<>
                      <Field label="Certificate" hint="One cert (e.g. a wildcard) can protect many sites — no re-upload">
                        <select className="fin2 fsel2" value={form.tls_existing_cert} onChange={e => upd({ tls_existing_cert: e.target.value })}>
                          <option value="">Match by domain name (or self-signed)</option>
                          {repoCerts.map(c => {
                            const names = certNames(c);
                            const wild = names.some(n => n.startsWith("*."));
                            const days = c.expires_at > 0 ? Math.round((c.expires_at * 1000 - Date.now()) / 86400000) : null;
                            const label = c.name ? `${c.name} (${c.domain})` : c.domain;
                            return <option key={c.domain} value={c.domain}>{label}{wild ? " (wildcard)" : ""}{c.san && c.san.length > 1 ? ` +${c.san.length - 1} SAN` : ""}{days !== null ? ` · ${days}d left` : ""}</option>;
                          })}
                        </select>
                      </Field>
                      {form.tls_existing_cert && (() => {
                        const sel = repoCerts.find(c => c.domain === form.tls_existing_cert);
                        if (!sel) return null;
                        const names = certNames(sel);
                        const covered = form.domains.filter(d => certCoversHost(names, d));
                        const uncovered = form.domains.filter(d => !certCoversHost(names, d));
                        return (
                          <InfoBox tone={uncovered.length === 0 && form.domains.length > 0 ? "green" : "amber"}>
                            <strong style={{ color: "var(--text2)" }}>{sel.domain}</strong> presents: {names.join(", ")}.<br />
                            {form.domains.length === 0 ? "Add domains in Basics to check coverage." : <>
                              {covered.length > 0 && <>Covers: <strong style={{ color: "var(--green)" }}>{covered.join(", ")}</strong>. </>}
                              {uncovered.length > 0 && <>⚠ Not covered: <strong style={{ color: "var(--amber)" }}>{uncovered.join(", ")}</strong> — these will fall back to a self-signed cert.</>}
                            </>}
                          </InfoBox>
                        );
                      })()}
                    </>)}
                  </>)}

                  {/* AUTO / ACME */}
                  {form.front_https && form.tls_mode === "auto" && (<>
                    <Row>
                      <Field label="Certificate Authority" hint="Which ACME authority issues the certificate. Let's Encrypt unless you have a reason to change it.">
                        <select className="fin2 fsel2" value={form.acme_provider} onChange={e => upd({ acme_provider: e.target.value as SiteForm["acme_provider"] })}>
                          {ACME_PROVIDERS.map(p => <option key={p.key} value={p.key}>{p.label}</option>)}
                        </select>
                      </Field>
                      <Field label="Contact Email" hint="Expiry notices + ACME account">
                        <input className="fin2" value={form.acme_email} placeholder="admin@example.com" onChange={e => upd({ acme_email: e.target.value })} />
                      </Field>
                    </Row>
                    <Row>
                      <Field label="Challenge Type" hint="HTTP-01 needs :80 · TLS-ALPN-01 needs :443 · DNS-01 for wildcards">
                        <select className="fin2 fsel2" value={form.acme_challenge} onChange={e => upd({ acme_challenge: e.target.value as SiteForm["acme_challenge"] })}>
                          <option value="http_01">HTTP-01</option>
                          <option value="tls_alpn_01">TLS-ALPN-01</option>
                          <option value="dns_01">DNS-01 (wildcard)</option>
                        </select>
                      </Field>
                      <div style={{ display: "flex", flexDirection: "column", gap: 8, justifyContent: "center" }}>
                        <SectionToggle label="Use staging" desc="Test certs · avoids rate limits" on={form.acme_staging} set={v => upd({ acme_staging: v })} />
                        <SectionToggle label="Wildcard (*.domain)" desc="Requires DNS-01" on={form.acme_wildcard} set={v => upd({ acme_wildcard: v, acme_challenge: v ? "dns_01" : form.acme_challenge })} />
                      </div>
                    </Row>
                    {adv && (
                      <Field label="Custom CA Directory URL" hint="Override the ACME directory endpoint (blank = provider default)">
                        <input className="fin2" value={form.acme_ca_server} placeholder="https://acme-v02.api.letsencrypt.org/directory" style={{ fontFamily: "var(--font-mono)", fontSize: 13 }} onChange={e => upd({ acme_ca_server: e.target.value })} />
                      </Field>
                    )}
                    {adv && form.acme_provider === "zerossl" && (<>
                      <GroupLabel>ZeroSSL API <Tag kind="stored" /></GroupLabel>
                      <Row>
                        <Field label="ZeroSSL API Key" hint="From your ZeroSSL dashboard. Needed only for ZeroSSL's EAB registration."><SecretInput value={form.zerossl_api_key} set={v => upd({ zerossl_api_key: v })} /></Field>
                        <Field label="API Retries" hint="How many times a failed issuance request is retried."><input className="fin2" type="number" value={form.zerossl_retries} onChange={e => upd({ zerossl_retries: Number(e.target.value) })} /></Field>
                      </Row>
                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
                        <Field label="Retry Delay (s)" hint="Seconds to wait between issuance retries."><input className="fin2" type="number" value={form.zerossl_retry_delay} onChange={e => upd({ zerossl_retry_delay: Number(e.target.value) })} /></Field>
                        <Field label="Connect Timeout (s)" hint="Seconds to wait for the authority to answer before giving up."><input className="fin2" type="number" value={form.zerossl_connect_timeout} onChange={e => upd({ zerossl_connect_timeout: Number(e.target.value) })} /></Field>
                        <Field label="Max Time (s)" hint="Overall ceiling for one issuance attempt, retries included."><input className="fin2" type="number" value={form.zerossl_max_time} onChange={e => upd({ zerossl_max_time: Number(e.target.value) })} /></Field>
                      </div>
                    </>)}
                    {adv && (form.acme_challenge === "dns_01" || form.acme_wildcard) && (<>
                      <GroupLabel>DNS-01 Automation <Tag kind="stored" /></GroupLabel>
                      <InfoBox tone="amber">DNS-01 issuance is on the roadmap. These settings are saved with the site; the cert is not auto-issued yet — use HTTP-01/TLS-ALPN-01 or upload a wildcard cert manually.</InfoBox>
                      <Row cols="1fr 1fr 1fr">
                        <Field label="DNS Provider" hint="Used for the DNS-01 challenge — the only challenge that can obtain a wildcard certificate."><input className="fin2" value={form.dns_provider} placeholder="cloudflare" onChange={e => upd({ dns_provider: e.target.value })} /></Field>
                        <Field label="Propagation" hint="How long to wait for the DNS record to become visible before asking the authority to check. “default” lets the provider decide."><input className="fin2" value={form.dns_propagation} onChange={e => upd({ dns_propagation: e.target.value })} /></Field>
                        <Field label="Credential Item" hint="The DNS provider's API token, as KEY=value."><input className="fin2" value={form.dns_credential} placeholder="CF_TOKEN=…" onChange={e => upd({ dns_credential: e.target.value })} /></Field>
                      </Row>
                    </>)}
                    <InfoBox>On deploy we request a certificate for <strong style={{ color: "var(--cyan)" }}>{form.domains.join(", ") || "your domains"}</strong>. If DNS isn&apos;t pointed here yet, the site still deploys and issuance retries automatically.</InfoBox>
                  </>)}

                  {/* MANUAL */}
                  {form.front_https && form.tls_mode === "manual" && (<>
                    <Field label="Certificate Source" hint="Paste the PEM here, or point at a file already present on the WAF node.">
                      <select className="fin2 fsel2" value={form.custom_priority} onChange={e => upd({ custom_priority: e.target.value as SiteForm["custom_priority"] })}>
                        <option value="data">Paste PEM data</option>
                        <option value="file">Path on WAF node</option>
                      </select>
                    </Field>
                    {form.custom_priority === "data" ? (<>
                      <Field label="Certificate (PEM)" hint="Full chain: leaf + intermediates">
                        <textarea className="fin2" rows={4} value={form.cert_pem} placeholder="-----BEGIN CERTIFICATE-----" style={{ fontFamily: "var(--font-mono)", fontSize: 14, resize: "vertical" }} onChange={e => upd({ cert_pem: e.target.value })} />
                      </Field>
                      <Field label="Private Key (PEM)" hint="Stays on your control plane">
                        <textarea className="fin2" rows={3} value={form.key_pem} placeholder="-----BEGIN PRIVATE KEY-----" style={{ fontFamily: "var(--font-mono)", fontSize: 14, resize: "vertical" }} onChange={e => upd({ key_pem: e.target.value })} />
                      </Field>
                    </>) : (
                      <Row>
                        <Field label="Certificate Path" hint="On the WAF node"><input className="fin2" value={form.cert_path} placeholder="/etc/ssl/site.crt" style={{ fontFamily: "var(--font-mono)", fontSize: 13 }} onChange={e => upd({ cert_path: e.target.value })} /></Field>
                        <Field label="Key Path" hint="Path on the WAF node. Read by the data plane only."><input className="fin2" value={form.key_path} placeholder="/etc/ssl/site.key" style={{ fontFamily: "var(--font-mono)", fontSize: 13 }} onChange={e => upd({ key_path: e.target.value })} /></Field>
                      </Row>
                    )}
                  </>)}

                  {form.front_https && form.tls_mode !== "off" && (
                    <SectionToggle label="HSTS (Strict-Transport-Security)" desc={`max-age ${form.hsts_max_age}s · force HTTPS in browsers`} on={form.hsts} set={v => upd({ hsts: v })} />
                  )}
                </>)}

                {/* ───────── REVERSE PROXY ───────── */}
                {screen === "proxy" && (<>
                  <StepHead title="Reverse Proxy" sub="The upstream application server(s) the WAF protects." tag="enforced" />
                  {!adv ? (<>
                    {/* Easy: one clear host + port */}
                    <Row cols="2fr 1fr">
                      <Field label="Application Host" hint="Where your app runs (IP or hostname)">
                        <input className="fin2" value={primary.host} placeholder="127.0.0.1" onChange={e => setServer(0, { host: e.target.value })} />
                      </Field>
                      <Field label="Port" hint="Your app's port">
                        <input className="fin2" type="number" value={primary.port} placeholder="8080" onChange={e => setServer(0, { port: Number(e.target.value) })} />
                      </Field>
                    </Row>
                    <SectionToggle label="Upstream uses HTTPS" desc="The app behind the WAF serves TLS — its certificate must be verifiable" on={primary.tls} set={v => setServer(0, { tls: v })} />
                    {/* The origin connector verifies the origin's certificate against
                        the public roots plus any CA in SENTINEL_UPSTREAM_CA_FILE. It
                        used to be the public roots ONLY, with no override and nothing
                        in this UI saying so, so an internal-CA backend — the ordinary
                        enterprise case — 502'd for ever with no explanation. */}
                    {primary.tls && (
                      <InfoBox tone="amber">
                        <strong>The origin's certificate is verified.</strong> If it is
                        signed by an internal or corporate CA rather than a public one,
                        point <code>SENTINEL_UPSTREAM_CA_FILE</code> at that CA's PEM
                        bundle on each WAF node — otherwise the handshake fails and this
                        site returns <strong>502</strong>. A self-signed origin
                        certificate must likewise have its own certificate in that file.
                      </InfoBox>
                    )}
                    <InfoBox>Traffic to <strong style={{ color: "var(--cyan)" }}>{scheme}://{form.domains[0] || "your-domain"}</strong> will be proxied to <strong style={{ color: "var(--cyan)" }}>{primary.tls ? "https" : "http"}://{primary.host || "host"}:{primary.port || "port"}</strong>. Need load balancing or health checks? Switch to <strong>Advanced</strong>.</InfoBox>
                  </>) : (<>
                    <Field label="Load Balancing" hint="Strategy across upstream servers">
                      <select className="fin2 fsel2" value={form.lb} onChange={e => upd({ lb: e.target.value as SiteForm["lb"] })}>
                        <option value="round_robin">Round Robin</option>
                        <option value="least_conn">Least Connections</option>
                        <option value="ip_hash">IP Hash (sticky)</option>
                        <option value="random">Random</option>
                        <option value="adaptive">Adaptive (latency-aware)</option>
                      </select>
                    </Field>
                    <GroupLabel>Upstream Servers</GroupLabel>
                    {form.servers.map((s, i) => (
                      // Align on the INPUT row, not the bottom of the cell.
                      //
                      // This was `alignItems: "end"`, which bottom-aligns every
                      // column. The three fields carry hints of different
                      // lengths — Weight's wraps to three lines where Port's
                      // wraps to one — so the tallest cell pushed its own label
                      // and input upward, while the cells with no hint at all,
                      // TLS and the remove button, sank to the bottom. Nothing
                      // in the row lined up with anything else.
                      //
                      // Starting from the top lines the labels up, and since
                      // every label is a single line the inputs line up beneath
                      // them. The hints then hang below at whatever height they
                      // need, which is where variable-length text belongs.
                      <div key={i} style={{ display: "grid", gridTemplateColumns: "2fr 1fr 0.8fr auto auto", gap: 8, alignItems: "start" }}>
                        <Field label={`Host #${i + 1}`} hint="The origin as the WAF reaches it — a hostname or address on your network, not the public domain."><input className="fin2" value={s.host} placeholder="127.0.0.1" onChange={e => setServer(i, { host: e.target.value })} /></Field>
                        <Field label="Port" hint="The port your application listens on."><input className="fin2" type="number" value={s.port} onChange={e => setServer(i, { port: Number(e.target.value) })} /></Field>
                        <Field label="Weight" hint="Relative share of traffic when several origins are listed. Equal weights spread evenly."><input className="fin2" type="number" value={s.weight} onChange={e => setServer(i, { weight: Number(e.target.value) })} /></Field>
                        <div style={{ display: "flex", flexDirection: "column", gap: 4, alignItems: "center" }}><label className="flbl2">TLS</label><Sw on={s.tls} set={v => setServer(i, { tls: v })} /></div>
                        <div style={{ display: "flex", flexDirection: "column", gap: 4, alignItems: "center" }}>
                          {/* A spacer, not a label: it reserves the label row so
                              the button lands on the input line. aria-hidden so
                              it is never announced as an empty label. */}
                          <label className="flbl2" aria-hidden style={{ visibility: "hidden" }}>&nbsp;</label>
                          <button className="btn bg-btn btn-sm" type="button" disabled={form.servers.length === 1} onClick={() => rmServer(i)} style={{ opacity: form.servers.length === 1 ? 0.4 : 1 }}><Icon name="trash" size={14} title="Remove" /></button>
                        </div>
                      </div>
                    ))}
                    <button className="btn bg-btn btn-sm" type="button" onClick={addServer} style={{ alignSelf: "flex-start" }}>＋ Add Server</button>
                    <SectionToggle label="Active Health Checks" desc="Probe upstreams and route around failures" on={form.health.enabled} set={v => upd({ health: { ...form.health, enabled: v } })} />
                    {form.health.enabled && (
                      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr", gap: 12 }}>
                        <Field label="Path" hint="The URL requested on each origin to decide whether it is up."><input className="fin2" value={form.health.path} onChange={e => upd({ health: { ...form.health, path: e.target.value } })} /></Field>
                        <Field label="Interval" hint="How often each origin is checked."><input className="fin2" value={form.health.interval} onChange={e => upd({ health: { ...form.health, interval: e.target.value } })} /></Field>
                        <Field label="Timeout" hint="How long a check may take before that origin counts as down."><input className="fin2" value={form.health.timeout} onChange={e => upd({ health: { ...form.health, timeout: e.target.value } })} /></Field>
                      </div>
                    )}
                    {/* Every control in this group is now read by the data plane. The
                        `Enforced` tag says so, and it is a claim: buildRustUpstream()
                        in the control plane is an allowlist, so a control added here
                        without a forwarding entry AND data-plane code to read it is
                        stored, echoed back, and silently dropped. Mark such a control
                        `unavailable` rather than leaving it looking live. */}
                    <GroupLabel>Proxy Options <Tag kind="enforced" /></GroupLabel>
                    <Row>
                      <Field label="Custom Host Header" hint="Override Host sent upstream (blank = pass-through)">
                        <input className="fin2" value={form.proxy_host_header} placeholder="app.internal" onChange={e => upd({ proxy_host_header: e.target.value })} />
                      </Field>
                      <Field label="SSL SNI Name" hint="Presented to an HTTPS origin; required when addressing it by IP">
                        <input className="fin2" value={form.proxy_ssl_sni_name} placeholder="backend.example.com" onChange={e => upd({ proxy_ssl_sni_name: e.target.value, proxy_ssl_sni: !!e.target.value })} title="The origin's certificate must be valid for this name — it is used both as the SNI sent and as the name the certificate is verified against, so a wrong value fails the handshake rather than connecting insecurely. Only applies to a server with TLS enabled." />
                      </Field>
                    </Row>
                    <Row>
                      <SectionToggle label="WebSocket / Upgrade" desc="Allow Connection: Upgrade passthrough" on={form.proxy_websocket} set={v => upd({ proxy_websocket: v })} />
                      <SectionToggle label="Upstream Keep-Alive" desc="Reuse upstream connections (off = a new connection per request)"
                                     on={form.proxy_keepalive} set={v => upd({ proxy_keepalive: v })} />
                    </Row>
                    <Row>
                      <Field label="Connect Timeout" hint="How long to wait to establish a connection to the origin."><input className="fin2" value={form.proxy_connect_timeout} placeholder="node default (10s)" onChange={e => upd({ proxy_connect_timeout: e.target.value })} title="How long TCP (plus TLS) to the origin may take, e.g. 5s. Narrower than Read Timeout: it fails fast on an unreachable origin without shortening the budget of one that is merely slow. Blank = node default. Capped at 60s." /></Field>
                      <Field label="Read Timeout" hint="How long to wait for the origin's response. Raise it for long-running requests."><input className="fin2" value={form.proxy_read_timeout} placeholder="node default (30s)" onChange={e => upd({ proxy_read_timeout: e.target.value })} title="How long the origin may take to return response headers (e.g. 60s, 5m). Raise it for slow report/export endpoints. It does not limit download or SSE stream duration. Blank = node default (30s)." /></Field>
                    </Row>
                  </>)}
                </>)}

                {/* ───────── PROTECTION (easy) ───────── */}
                {screen === "protect" && (<>
                  <StepHead title="Protection" sub="Core WAF settings. Switch to Advanced for full control." tag="enforced" />
                  <Row>
                    <Field label="Paranoia Level" hint={serverDefaultHint("paranoia_level") ?? "1 = fewer false positives · 4 = strictest"}><input className="fin2" type="number" min={1} max={4} value={form.paranoia_level} onChange={e => upd({ paranoia_level: Number(e.target.value), preset: "custom" })} /></Field>
                    <Field label="Anomaly Threshold" hint={serverDefaultHint("anomaly_threshold") ?? "Score needed to block a request"}><input className="fin2" type="number" value={form.anomaly_threshold} onChange={e => upd({ anomaly_threshold: Number(e.target.value), preset: "custom" })} /></Field>
                  </Row>
                  <LimitNotes checks={checkSiteLimits(form)} fields={["paranoia_level", "anomaly_threshold"]} />
                  <SectionToggle label="Per-IP Rate Limiting" desc={`${form.rl_per_ip.rps} req/s · burst ${form.rl_per_ip.burst}`} on={form.rate_limit_enabled} set={v => upd({ rate_limit_enabled: v })} />
                  <SectionToggle label="Bot Detection (JA4 fingerprinting)" desc="Identify automated clients by TLS fingerprint" on={form.bot_ja4} set={v => upd({ bot_ja4: v })} />
                  <InfoBox>All OWASP CRS categories are enabled by this template. Switch to <strong style={{ color: "var(--cyan)" }}>Advanced</strong> to fine-tune rules, antibot, GeoIP, headers, anti-DDoS and ML.</InfoBox>
                </>)}

                {/* ───────── WAF RULES (advanced) ───────── */}
                {screen === "rules" && (<>
                  <StepHead title="WAF Rules" sub="OWASP CRS categories, paranoia level and per-rule exclusions." tag="enforced" />
                  <Row>
                    <Field label="Paranoia Level" hint={serverDefaultHint("paranoia_level") ?? "1–4 · higher = stricter"}><input className="fin2" type="number" min={1} max={4} value={form.paranoia_level} onChange={e => upd({ paranoia_level: Number(e.target.value) })} /></Field>
                    <Field label="Anomaly Threshold" hint={serverDefaultHint("anomaly_threshold") ?? "Total rule score at which a request is refused. Lower blocks more — the balanced preset uses 10."}><input className="fin2" type="number" value={form.anomaly_threshold} onChange={e => upd({ anomaly_threshold: Number(e.target.value) })} /></Field>
                  </Row>
                  <LimitNotes checks={checkSiteLimits(form)} fields={["paranoia_level", "anomaly_threshold"]} />
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <GroupLabel>Request Inspection ({form.rule_categories.filter(k => !ALL_CRS_RESPONSE_KEYS.includes(k)).length}/{CRS_REQUEST_CATEGORIES.length})</GroupLabel>
                    <div style={{ display: "flex", gap: 6 }}>
                      <button className="btn bg-btn btn-xs" type="button" onClick={() => upd({ rule_categories: [...ALL_CRS_KEYS, ...form.rule_categories.filter(k => ALL_CRS_RESPONSE_KEYS.includes(k))] })}>All</button>
                      <button className="btn bg-btn btn-xs" type="button" onClick={() => upd({ rule_categories: [...CRS_REQUEST_CATEGORIES.filter(c => c.core).map(c => c.key), ...form.rule_categories.filter(k => ALL_CRS_RESPONSE_KEYS.includes(k))] })}>Core only</button>
                    </div>
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                    {CRS_REQUEST_CATEGORIES.map(c => <CatTile key={c.key} c={c} on={form.rule_categories.includes(c.key)} onClick={() => toggleCat(c.key)} />)}
                  </div>

                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <GroupLabel>Response Inspection ({form.rule_categories.filter(k => ALL_CRS_RESPONSE_KEYS.includes(k)).length}/{CRS_RESPONSE_CATEGORIES.length})</GroupLabel>
                    <div style={{ display: "flex", gap: 6 }}>
                      <button className="btn bg-btn btn-xs" type="button" onClick={() => upd({ rule_categories: [...form.rule_categories.filter(k => !ALL_CRS_RESPONSE_KEYS.includes(k)), ...ALL_CRS_RESPONSE_KEYS] })}>All</button>
                      <button className="btn bg-btn btn-xs" type="button" onClick={() => upd({ rule_categories: form.rule_categories.filter(k => !ALL_CRS_RESPONSE_KEYS.includes(k)) })}>None</button>
                    </div>
                  </div>
                  <div style={{ fontSize: 11, color: "var(--text3)", lineHeight: 1.5, padding: "2px 0 4px" }}>
                    Off by default. These inspect what your <strong>origin sends back</strong>, catching database
                    errors, stack traces and web shells before they reach a visitor. Two costs to know about:
                    HTML, plain-text and XML responses are <strong>buffered</strong> instead of streamed (scripts,
                    stylesheets, JSON and media still stream), and a response is judged on its own score against a
                    response threshold of 4 — so one critical match, such as an SQL error, blocks it. Enable in
                    learning mode first if a page legitimately prints error text.
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                    {CRS_RESPONSE_CATEGORIES.map(c => <CatTile key={c.key} c={c} on={form.rule_categories.includes(c.key)} onClick={() => toggleCat(c.key)} />)}
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                    {CRS_CATEGORIES.map(c => {
                      const on = form.rule_categories.includes(c.key);
                      return (
                        <div key={c.key} onClick={() => toggleCat(c.key)} style={{ cursor: "pointer", padding: "8px 11px", borderRadius: 8, display: "flex", justifyContent: "space-between", gap: 8, background: on ? "var(--green-t)" : "var(--fill-soft)", border: on ? "1px solid color-mix(in srgb, var(--green) 32%, transparent)" : "1px solid var(--card-bd)" }}>
                          <div><div style={{ fontSize: 13, fontWeight: 600, color: "var(--text)" }}>{c.label}</div><div style={{ fontSize: 11, color: "var(--text3)", marginTop: 2 }}>{c.desc}</div></div>
                          <div style={{ fontSize: 15, color: on ? "var(--green)" : "var(--text3)" }}>{on ? "✓" : "○"}</div>
                        </div>
                      );
                    })}
                  </div>
                  <GroupLabel>Rule Exclusions (false-positive tuning)</GroupLabel>
                  {form.rule_exclusions.map((ex, i) => (
                    <div key={i} style={{ display: "grid", gridTemplateColumns: "1fr 2fr auto", gap: 8, alignItems: "start" }}>
                      <Field label="Rule ID" hint="Numeric CRS or custom rule id to exclude, e.g. 942100."><input className="fin2" type="number" value={ex.rule_id} onChange={e => upd({ rule_exclusions: form.rule_exclusions.map((x, idx) => idx === i ? { ...x, rule_id: Number(e.target.value) } : x) })} /></Field>
                      <Field label="Exclude Targets" hint="comma-separated (e.g. ARGS:id, REQUEST_HEADERS:Referer)"><input className="fin2" value={ex.exclude_targets.join(", ")} onChange={e => upd({ rule_exclusions: form.rule_exclusions.map((x, idx) => idx === i ? { ...x, exclude_targets: e.target.value.split(",").map(t => t.trim()).filter(Boolean) } : x) })} /></Field>
                      <div style={{ display: "flex", flexDirection: "column", gap: 4, alignItems: "center" }}>
                          {/* Spacer, not a label: reserves the label row so the
                              button lands on the input line. */}
                          <label className="flbl2" aria-hidden style={{ visibility: "hidden" }}>&nbsp;</label>
                          <button className="btn bg-btn btn-sm" type="button" onClick={() => upd({ rule_exclusions: form.rule_exclusions.filter((_, idx) => idx !== i) })}><Icon name="trash" size={14} title="Remove" /></button>
                      </div>
                    </div>
                  ))}
                  <button className="btn bg-btn btn-xs" type="button" style={{ alignSelf: "flex-start" }} onClick={() => upd({ rule_exclusions: [...form.rule_exclusions, { rule_id: 0, exclude_targets: [] }] })}>＋ Add Exclusion</button>
                </>)}

                {/* ───────── API SECURITY (advanced) ───────── */}
                {screen === "apisec" && (<>
                  <StepHead title="API Security" sub="Edge JWT/OAuth2 enforcement, GraphQL depth/complexity limits and a gRPC firewall — protect APIs, not just web apps." tag="enforced" />

                  {/* JWT / OAuth2 */}
                  <SectionToggle label="Edge JWT / OAuth2 validation" desc="Verify Bearer tokens (signature · expiry · issuer/audience · scopes) before proxying" on={form.jwt_enabled} set={v => upd({ jwt_enabled: v })} />
                  {form.jwt_enabled && (<>
                    <SectionToggle label="Require a valid token" desc="On = reject missing/invalid tokens · Off = verify only when present" on={form.jwt_required} set={v => upd({ jwt_required: v })} />
                    <Row>
                      <Field label="Issuer (iss)" hint="Expected token issuer (blank = don't check)"><input className="fin2" value={form.jwt_issuer} placeholder="https://auth.example.com/" style={{ fontFamily: "var(--font-mono)", fontSize: 13 }} onChange={e => upd({ jwt_issuer: e.target.value })} /></Field>
                      <Field label="Audience (aud)" hint="Expected audience (blank = don't check)"><input className="fin2" value={form.jwt_audience} placeholder="api://my-service" style={{ fontFamily: "var(--font-mono)", fontSize: 13 }} onChange={e => upd({ jwt_audience: e.target.value })} /></Field>
                    </Row>
                    <Field label="Allowed Algorithms" hint="Only tokens signed with these algs are accepted">
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                        {JWT_ALGORITHMS.map(a => {
                          const on = form.jwt_algorithms.includes(a);
                          return (
                            <span key={a} onClick={() => upd({ jwt_algorithms: on ? form.jwt_algorithms.filter(x => x !== a) : [...form.jwt_algorithms, a] })}
                              style={{ cursor: "pointer", padding: "4px 10px", borderRadius: 8, fontSize: 13, fontFamily: "var(--font-mono)", background: on ? "var(--green-t)" : "var(--fill-soft)", border: on ? "1px solid color-mix(in srgb, var(--green) 32%, transparent)" : "1px solid var(--card-bd)", color: on ? "var(--text)" : "var(--text3)" }}>{a}</span>
                          );
                        })}
                      </div>
                    </Field>
                    <GroupLabel>Signing Key <span style={{ textTransform: "none", letterSpacing: 0, color: "var(--text3)" }}>— pick one</span></GroupLabel>
                    <Field label="JWKS URL" hint="Recommended: keys fetched + cached, rotated by token kid"><input className="fin2" value={form.jwt_jwks_url} placeholder="https://auth.example.com/.well-known/jwks.json" style={{ fontFamily: "var(--font-mono)", fontSize: 13 }} onChange={e => upd({ jwt_jwks_url: e.target.value })} /></Field>
                    <Row>
                      <Field label="HS256 Shared Secret" hint="Symmetric — for HS* algorithms"><SecretInput value={form.jwt_hs_secret} set={v => upd({ jwt_hs_secret: v })} /></Field>
                      <Field label="Scope Claim" hint="Claim carrying scopes (default: scope)"><input className="fin2" value={form.jwt_scope_claim} placeholder="scope" style={{ fontFamily: "var(--font-mono)", fontSize: 13 }} onChange={e => upd({ jwt_scope_claim: e.target.value })} /></Field>
                    </Row>
                    <Field label="Public Key (PEM)" hint="Asymmetric static key — for RS*/ES* (blank if using JWKS)"><textarea className="fin2" rows={3} value={form.jwt_public_key_pem} placeholder="-----BEGIN PUBLIC KEY-----" style={{ fontFamily: "var(--font-mono)", fontSize: 13, resize: "vertical" }} onChange={e => upd({ jwt_public_key_pem: e.target.value })} /></Field>
                    <Field label="Required Scopes" hint="All must be present in the token to pass"><ChipInput values={form.jwt_required_scopes} onChange={v => upd({ jwt_required_scopes: v })} placeholder="read:orders" /></Field>
                  </>)}

                  {/* GraphQL */}
                  <GroupLabel>GraphQL Firewall</GroupLabel>
                  <SectionToggle label="GraphQL protection" desc="Enforce query depth/complexity limits and block introspection" on={form.graphql_enabled} set={v => upd({ graphql_enabled: v })} />
                  {form.graphql_enabled && (<>
                    <Row>
                      <Field label="Max Query Depth" hint="Reject deeply nested queries (DoS)"><input className="fin2" type="number" value={form.graphql_max_depth} onChange={e => upd({ graphql_max_depth: Number(e.target.value) })} /></Field>
                      <Field label="Max Complexity" hint="Cost budget per query"><input className="fin2" type="number" value={form.graphql_max_complexity} onChange={e => upd({ graphql_max_complexity: Number(e.target.value) })} /></Field>
                    </Row>
                    <SectionToggle label="Block introspection" desc="Refuse __schema / __type queries (hide the API surface)" on={form.graphql_block_introspection} set={v => upd({ graphql_block_introspection: v })} />
                  </>)}

                  {/* gRPC */}
                  <GroupLabel>gRPC Firewall</GroupLabel>
                  <SectionToggle label="gRPC protection" desc="Message/frame caps + method allow/deny for application/grpc traffic" on={form.grpc_enabled} set={v => upd({ grpc_enabled: v })} />
                  {form.grpc_enabled && (<>
                    <Row cols="1fr 1fr 1fr">
                      <Field label="Max Message (KB)" hint="Per-message size cap"><input className="fin2" type="number" value={form.grpc_max_message_kb} onChange={e => upd({ grpc_max_message_kb: Number(e.target.value) })} /></Field>
                      <Field label="Max Frames" hint="Cap on the number of frames in one gRPC message, which bounds frame-flood."><input className="fin2" type="number" value={form.grpc_max_frames} onChange={e => upd({ grpc_max_frames: Number(e.target.value) })} /></Field>
                      <div style={{ display: "flex", alignItems: "flex-end" }}><SectionToggle label="Block reflection" desc="Hide schema" on={form.grpc_block_reflection} set={v => upd({ grpc_block_reflection: v })} /></div>
                    </Row>
                    <Row>
                      <Field label="Allowed Methods" hint="/pkg.Service/Method — if set, only these pass"><ChipInput values={form.grpc_allowed_methods} onChange={v => upd({ grpc_allowed_methods: v })} placeholder="/orders.OrderService/Get" /></Field>
                      <Field label="Blocked Methods" hint="Explicitly denied methods"><ChipInput values={form.grpc_blocked_methods} onChange={v => upd({ grpc_blocked_methods: v })} placeholder="/admin.Admin/Wipe" /></Field>
                    </Row>
                  </>)}

                  {!form.jwt_enabled && !form.graphql_enabled && !form.grpc_enabled &&
                    <InfoBox>These controls run only for matching traffic (Bearer tokens · GraphQL bodies · <span style={{ color: "var(--cyan)" }}>application/grpc</span>) — enabling them never affects ordinary web requests.</InfoBox>}
                </>)}

                {/* ───────── RATE & DDOS (advanced) ───────── */}
                {screen === "rate" && (<>
                  <StepHead title="Rate & DDoS" sub="Token-bucket rate limits and connection-rate anti-DDoS." tag="enforced" />
                  <SectionToggle label="Rate Limiting" desc="Token-bucket limits per IP and globally" on={form.rate_limit_enabled} set={v => upd({ rate_limit_enabled: v })} />
                  {form.rate_limit_enabled && (
                    <Row>
                      <div style={{ display: "flex", flexDirection: "column", gap: 10, padding: 12, borderRadius: 10, border: "1px solid var(--card-bd)" }}>
                        <div style={{ fontSize: 13, fontWeight: 700, color: "var(--cyan)" }}>Per-IP</div>
                        <Field label="Requests / sec" hint="Sustained requests allowed from a single client address."><input className="fin2" type="number" value={form.rl_per_ip.rps} onChange={e => upd({ rl_per_ip: { ...form.rl_per_ip, rps: Number(e.target.value) } })} /></Field>
                        <Field label="Burst" hint="Extra requests one address may make above the sustained rate before limiting starts."><input className="fin2" type="number" value={form.rl_per_ip.burst} onChange={e => upd({ rl_per_ip: { ...form.rl_per_ip, burst: Number(e.target.value) } })} /></Field>
                      </div>
                      <div style={{ display: "flex", flexDirection: "column", gap: 10, padding: 12, borderRadius: 10, border: "1px solid var(--card-bd)" }}>
                        <div style={{ fontSize: 13, fontWeight: 700, color: "var(--cyan)" }}>Global</div>
                        <Field label="Requests / sec" hint="Sustained requests allowed across all clients of this site."><input className="fin2" type="number" value={form.rl_global.rps} onChange={e => upd({ rl_global: { ...form.rl_global, rps: Number(e.target.value) } })} /></Field>
                        <Field label="Burst" hint="Extra requests allowed site-wide above the sustained rate."><input className="fin2" type="number" value={form.rl_global.burst} onChange={e => upd({ rl_global: { ...form.rl_global, burst: Number(e.target.value) } })} /></Field>
                      </div>
                    </Row>
                  )}
                  <SectionToggle label="Connection-rate Anti-DDoS" desc="Block IPs opening too many connections per second" on={form.antiddos_enabled} set={v => upd({ antiddos_enabled: v })} />
                  {form.antiddos_enabled && (
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
                      <Field label="Conn/s limit" hint="New connections per second from one address before it is blocked."><input className="fin2" type="number" value={form.antiddos_conn_rate} onChange={e => upd({ antiddos_conn_rate: Number(e.target.value) })} /></Field>
                      <Field label="Burst" hint="Connections allowed above that rate before blocking starts."><input className="fin2" type="number" value={form.antiddos_burst} onChange={e => upd({ antiddos_burst: Number(e.target.value) })} /></Field>
                      <Field label="Block (secs)" hint="How long an address stays blocked once it trips the limit."><input className="fin2" type="number" value={form.antiddos_block_secs} onChange={e => upd({ antiddos_block_secs: Number(e.target.value) })} /></Field>
                    </div>
                  )}
                </>)}

                {/* ───────── ANTIBOT (advanced) ───────── */}
                {screen === "antibot" && (<>
                  <StepHead title="Antibot" sub="Fingerprint and challenge automated clients before they reach your app." tag="enforced" />
                  <SectionToggle label="JA4 Bot Fingerprinting" desc="Detect automated clients by TLS fingerprint" on={form.bot_ja4} set={v => upd({ bot_ja4: v })} />
                  <Field label="Challenge Type" hint="Challenge suspicious clients before passing them upstream">
                    <select className="fin2 fsel2" value={form.bot_challenge} onChange={e => upd({ bot_challenge: e.target.value as SiteForm["bot_challenge"] })}>
                      <option value="off">Off</option>
                      <option value="native_pow">Native Proof-of-Work (no third party)</option>
                      <option value="recaptcha">Google reCAPTCHA</option>
                      <option value="hcaptcha">hCaptcha</option>
                      <option value="turnstile">Cloudflare Turnstile</option>
                    </select>
                  </Field>
                  {form.bot_challenge === "recaptcha" && (<>
                    <Row>
                      <Field label="reCAPTCHA Site Key" hint="Public key, rendered into the challenge page."><input className="fin2" value={form.bot_recaptcha_sitekey} onChange={e => upd({ bot_recaptcha_sitekey: e.target.value })} /></Field>
                      <Field label="v3 Score Threshold" hint="0 = lenient · 1 = strict"><input className="fin2" type="number" min={0} max={1} step={0.1} value={form.bot_recaptcha_score} onChange={e => upd({ bot_recaptcha_score: Number(e.target.value) })} /></Field>
                    </Row>
                    <Field label="reCAPTCHA Secret" hint="The server-side key. Used to verify a solved challenge and never sent to the browser."><SecretInput value={form.bot_recaptcha_secret} set={v => upd({ bot_recaptcha_secret: v })} /></Field>
                  </>)}
                  {form.bot_challenge === "hcaptcha" && (
                    <Row>
                      <Field label="hCaptcha Site Key" hint="Public key, rendered into the challenge page."><input className="fin2" value={form.bot_hcaptcha_sitekey} onChange={e => upd({ bot_hcaptcha_sitekey: e.target.value })} /></Field>
                      <Field label="hCaptcha Secret" hint="Server-side key, used to verify a solved challenge."><SecretInput value={form.bot_hcaptcha_secret} set={v => upd({ bot_hcaptcha_secret: v })} /></Field>
                    </Row>
                  )}
                  {form.bot_challenge === "turnstile" && (
                    <Row>
                      <Field label="Turnstile Site Key" hint="Public key, rendered into the challenge page."><input className="fin2" value={form.bot_turnstile_sitekey} onChange={e => upd({ bot_turnstile_sitekey: e.target.value })} /></Field>
                      <Field label="Turnstile Secret" hint="Server-side key, used to verify a solved challenge."><SecretInput value={form.bot_turnstile_secret} set={v => upd({ bot_turnstile_secret: v })} /></Field>
                    </Row>
                  )}
                  {form.bot_challenge === "native_pow" && <InfoBox tone="green">Native proof-of-work runs entirely on the WAF — no third-party keys, no external requests, fully on-prem.</InfoBox>}
                </>)}

                {/* ───────── GEO & IP (advanced) ───────── */}
                {screen === "geoip" && (<>
                  <StepHead title="Geo & IP" sub="Country filtering, IP allow/block lists and external blacklist sources." tag="enforced" />
                  <Field label="GeoIP Filtering" hint="Allow-list takes precedence over block-list · country data: IP Geolocation by DB-IP (fetched monthly by the geoip.refresh job)">
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
                            style={{ cursor: "pointer", padding: "4px 9px", borderRadius: 12, fontSize: 14, fontFamily: "var(--font-mono)", background: on ? (form.geo_mode === "allow" ? "var(--green-t)" : "var(--red-t)") : "var(--fill-soft)", border: on ? `1px solid ${form.geo_mode === "allow" ? "color-mix(in srgb, var(--green) 32%, transparent)" : "color-mix(in srgb, var(--red) 32%, transparent)"}` : "1px solid var(--card-bd)", color: on ? "var(--text)" : "var(--text3)" }}>{c.code} {c.name}</span>
                        );
                      })}
                    </div>
                  )}
                  {form.geo_mode !== "off" && (
                    <Field label={form.geo_mode === "allow" ? "Allowed countries" : "Blocked countries"}
                      hint="Every selected country, including ones not in the quick list above. Add any ISO 3166 two-letter code (IN, US, GB…).">
                      <ChipInput values={form.geo_countries} onChange={v => upd({ geo_countries: v })} placeholder="e.g. NP"
                        transform={s => s.trim().toUpperCase()} validate={isCountryCode}
                        invalidMessage={s => countryCodeProblem(s) ?? "Invalid country code"}
                        label={c => isCountryCode(c) ? `${c} ${countryName(c)}` : c} />
                    </Field>
                  )}
                  <Row>
                    <Field label="IP / CIDR Allow-list" hint="Trusted for this site: skips every check — rules, rate limits, bans, bot and GeoIP checks (response data-leak checks still apply). Keep it to addresses you control. An address or a range."><ChipInput values={form.ip_allow} onChange={v => upd({ ip_allow: v })} placeholder="10.0.0.0/8 or 192.0.2.10"
                      validate={isIpOrCidr} invalidMessage={s => `"${s}" is not an IP address or CIDR range`} /></Field>
                    <Field label="IP / CIDR Block-list" hint="Always denied. An address or a range."><ChipInput values={form.ip_block} onChange={v => upd({ ip_block: v })} placeholder="203.0.113.7 or 203.0.113.0/24"
                      validate={isIpOrCidr} invalidMessage={s => `"${s}" is not an IP address or CIDR range`} /></Field>
                  </Row>
                  {form.ip_block.length > 0 && (
                    <SectionToggle label="Drop block-list sources in the kernel (XDP)" desc="Faster, but node-wide: these sources are then blocked for every site on this node, not just this one. Leave off unless the block is meant for the whole edge." on={form.ip_block_xdp} set={v => upd({ ip_block_xdp: v })} />
                  )}
                  <GroupLabel>Blacklist Sources <Tag kind="stored" /></GroupLabel>
                  <SectionToggle label="DNSBL (DNS blacklists)" desc="Reject IPs listed on the configured DNSBL servers" on={form.dnsbl_enabled} set={v => upd({ dnsbl_enabled: v })} />
                  {form.dnsbl_enabled && <Field label="DNSBL Servers" hint="e.g. bl.blocklist.de, sbl.spamhaus.org"><ChipInput values={form.dnsbl_servers} onChange={v => upd({ dnsbl_servers: v })} placeholder="bl.blocklist.de" /></Field>}
                  <Row>
                    <Field label="Block User-Agents" hint="Substring match"><ChipInput values={form.blacklist_user_agents} onChange={v => upd({ blacklist_user_agents: v })} placeholder="sqlmap" /></Field>
                    <Field label="Block URI Patterns" hint="Substring match"><ChipInput values={form.blacklist_uris} onChange={v => upd({ blacklist_uris: v })} placeholder="/.env" /></Field>
                  </Row>
                  <GroupLabel>External Threat-Intel Feeds <Tag kind="enforced" /></GroupLabel>
                  <InfoBox>Auto-refreshed IP blocklists (AbuseIPDB, Spamhaus DROP, FireHOL, …). Loaded at startup and refreshed on the interval — matched IPs are blocked before rules run.</InfoBox>
                  {form.ip_feeds.map((feed, i) => (
                    <div key={i} style={{ display: "grid", gridTemplateColumns: "2.4fr 0.8fr 0.9fr auto", gap: 8, alignItems: "start" }}>
                      <Field label={`Feed URL #${i + 1}`} hint="HTTP(S) URL of an IP blocklist. Fetched by the data plane on the refresh interval."><input className="fin2" value={feed.url} placeholder="https://iplists.firehol.org/…/firehol_level1.netset" style={{ fontFamily: "var(--font-mono)", fontSize: 13 }} onChange={e => upd({ ip_feeds: form.ip_feeds.map((x, idx) => idx === i ? { ...x, url: e.target.value } : x) })} /></Field>
                      <Field label="Refresh" hint="e.g. 1h"><input className="fin2" value={feed.interval} placeholder="1h" onChange={e => upd({ ip_feeds: form.ip_feeds.map((x, idx) => idx === i ? { ...x, interval: e.target.value } : x) })} /></Field>
                      <Field label="Format" hint="How this feed's file is laid out: one CIDR per line, or JSON.">
                        <select className="fin2 fsel2" value={feed.format} onChange={e => upd({ ip_feeds: form.ip_feeds.map((x, idx) => idx === i ? { ...x, format: e.target.value as IpFeed["format"] } : x) })}>
                          <option value="cidr">CIDR list</option>
                          <option value="json">JSON</option>
                        </select>
                      </Field>
                      <div style={{ display: "flex", flexDirection: "column", gap: 4, alignItems: "center" }}>
                          {/* Spacer, not a label: reserves the label row so the
                              button lands on the input line. */}
                          <label className="flbl2" aria-hidden style={{ visibility: "hidden" }}>&nbsp;</label>
                          <button className="btn bg-btn btn-sm" type="button" onClick={() => upd({ ip_feeds: form.ip_feeds.filter((_, idx) => idx !== i) })}><Icon name="trash" size={14} title="Remove" /></button>
                      </div>
                    </div>
                  ))}
                  <button className="btn bg-btn btn-xs" type="button" style={{ alignSelf: "flex-start" }} onClick={() => upd({ ip_feeds: [...form.ip_feeds, { url: "", interval: "1h", format: "cidr" }] })}>＋ Add Feed</button>
                </>)}

                {/* ───────── HTTP HEADERS (advanced) ───────── */}
                {screen === "headers" && (<>
                  <StepHead title="HTTP Headers" sub="Response security headers. The WAF always injects secure defaults; these override per-site." tag="enforced" />
                  <InfoBox>Secure defaults (X-Content-Type-Options, X-Frame-Options, X-XSS-Protection) are always applied. The values below override them for this site.</InfoBox>
                  <Field label="Content-Security-Policy" hint="Leave blank to omit CSP"><input className="fin2" value={form.csp} placeholder="default-src 'self'" style={{ fontFamily: "var(--font-mono)", fontSize: 13 }} onChange={e => upd({ csp: e.target.value })} /></Field>
                  <Row>
                    {/* "Not set" is a real choice, not a missing one: the data
                        plane then keeps the origin's header (or adds its own
                        default), where a value here replaces the origin's. */}
                    <Field label="Referrer-Policy" hint="How much of the current URL a browser sends when following a link away from this site.">
                      <select className="fin2 fsel2" value={form.referrer_policy} onChange={e => upd({ referrer_policy: e.target.value })}>
                        <option value="">Not set (the origin&apos;s, else strict-origin-when-cross-origin)</option>
                        {["no-referrer", "no-referrer-when-downgrade", "strict-origin", "strict-origin-when-cross-origin", "same-origin", "origin"].map(v => <option key={v} value={v}>{v}</option>)}
                      </select>
                    </Field>
                    <Field label="Cookie Flags" hint="Applied to Set-Cookie. Blank leaves cookies as the origin sets them."><input className="fin2" value={form.cookie_flags} placeholder="Not set, e.g. * HttpOnly SameSite=Lax" style={{ fontFamily: "var(--font-mono)", fontSize: 13 }} onChange={e => upd({ cookie_flags: e.target.value })} /></Field>
                  </Row>
                  <Field label="Permissions-Policy" hint="Which browser features (camera, microphone, geolocation, …) pages on this site may use. Blank keeps the origin's, else geolocation=(), microphone=(), camera=()."><input className="fin2" value={form.permissions_policy} placeholder="Not set" style={{ fontFamily: "var(--font-mono)", fontSize: 13 }} onChange={e => upd({ permissions_policy: e.target.value })} /></Field>
                  <SectionToggle label="CORS (Access-Control-Allow-Origin)" desc="Add cross-origin response headers" on={form.cors_enabled} set={v => upd({ cors_enabled: v })} />
                  {form.cors_enabled && <Field label="Allowed Origins" hint="* or comma-separated origins"><input className="fin2" value={form.cors_origins} style={{ fontFamily: "var(--font-mono)", fontSize: 13 }} onChange={e => upd({ cors_origins: e.target.value })} /></Field>}
                  <GroupLabel>Custom Headers</GroupLabel>
                  {form.custom_headers.map((h, i) => (
                    <div key={i} style={{ display: "grid", gridTemplateColumns: "1fr 1.5fr auto", gap: 8, alignItems: "start" }}>
                      <Field label="Name" hint="Header name added to every response from this site."><input className="fin2" value={h.name} placeholder="X-Custom" onChange={e => setHeader(i, { name: e.target.value })} /></Field>
                      <Field label="Value" hint="Value sent with that header."><input className="fin2" value={h.value} onChange={e => setHeader(i, { value: e.target.value })} /></Field>
                      <div style={{ display: "flex", flexDirection: "column", gap: 4, alignItems: "center" }}>
                          {/* Spacer, not a label: reserves the label row so the
                              button lands on the input line. */}
                          <label className="flbl2" aria-hidden style={{ visibility: "hidden" }}>&nbsp;</label>
                          <button className="btn bg-btn btn-sm" type="button" onClick={() => upd({ custom_headers: form.custom_headers.filter((_, idx) => idx !== i) })}><Icon name="trash" size={14} title="Remove" /></button>
                      </div>
                    </div>
                  ))}
                  <button className="btn bg-btn btn-xs" type="button" style={{ alignSelf: "flex-start" }} onClick={() => upd({ custom_headers: [...form.custom_headers, { name: "", value: "" }] })}>＋ Add Header</button>

                  <GroupLabel>Block Page</GroupLabel>
                  <InfoBox>What a blocked visitor sees. The page shows a <strong>Support ID</strong> — paste it into Threat Search to find the exact request, however long ago it was blocked. API clients (anything not asking for HTML) keep getting JSON.</InfoBox>
                  <SectionToggle label="Branded block page" desc="Serve an HTML page to browsers instead of raw JSON" on={form.block_page_enabled} set={v => upd({ block_page_enabled: v })} />
                  {form.block_page_enabled && (<>
                    <Field label="Heading" hint="Default: “Request blocked”"><input className="fin2" value={form.block_page_title} placeholder="Request blocked" onChange={e => upd({ block_page_title: e.target.value })} /></Field>
                    <Field label="Message" hint="Tell the visitor what to DO — not what was detected">
                      <input className="fin2" value={form.block_page_message} placeholder="If you believe this is a mistake, contact support and quote the Support ID below." onChange={e => upd({ block_page_message: e.target.value })} />
                    </Field>
                    <Row>
                      <Field label="Contact" hint="Email, phone or URL — linked automatically"><input className="fin2" value={form.block_page_contact} placeholder="soc@example.com" onChange={e => upd({ block_page_contact: e.target.value })} /></Field>
                      <Field label="Logo URL" hint="https:// or a site-relative /path"><input className="fin2" value={form.block_page_logo} placeholder="https://cdn.example.com/logo.png" onChange={e => upd({ block_page_logo: e.target.value })} /></Field>
                    </Row>
                  </>)}
                  <SectionToggle
                    label="Show detection reason to the visitor"
                    desc="⚠ Leave OFF in production. The reason names which control fired (rule, threat-intel feed, IP reputation), letting an attacker permute payloads and read back exactly what caught them. Internal/staging sites only."
                    on={form.block_page_show_reason}
                    set={v => upd({ block_page_show_reason: v })}
                  />
                </>)}

                {/* ───────── ADVANCED ───────── */}
                {screen === "advanced" && (<>
                  <StepHead title="Advanced" sub="Request limits, allowed methods, ML anomaly detection and API discovery." tag="enforced" />
                  <GroupLabel>Request Limits</GroupLabel>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
                    <Field label="Max Body (MB)" hint="Largest request body accepted. Anything larger is refused, not truncated."><input className="fin2" type="number" value={form.max_body_size_mb} onChange={e => upd({ max_body_size_mb: Number(e.target.value) })} /></Field>
                    <Field label="Max URI (bytes)" hint="Longest request line accepted."><input className="fin2" type="number" value={form.max_uri_length} onChange={e => upd({ max_uri_length: Number(e.target.value) })} /></Field>
                    <Field label="Max Headers" hint="Most headers one request may carry."><input className="fin2" type="number" value={form.max_header_count} onChange={e => upd({ max_header_count: Number(e.target.value) })} /></Field>
                  </div>
                  <LimitNotes checks={checkSiteLimits(form)} fields={["max_body_size_mb", "max_uri_length", "max_header_count"]} />
                  <GroupLabel>Inspection Limits</GroupLabel>
                  <div style={{ fontSize: 12, color: "var(--text3)", lineHeight: 1.6 }}>
                    What inspecting one request may cost. A request past one is never inspected in part: Blocking mode refuses it (413, or 403 for the time budget) and Learning mode records it. Leave blank for the default; 0 means no limit.
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
                    <Field label="Max Inspected Arguments" hint={`Query, form, JSON, XML and multipart arguments together. Default ${INSPECTION_LIMIT_DEFAULTS.max_inspected_args}.`}><input className="fin2" type="number" min={0} value={form.max_inspected_args} placeholder={String(INSPECTION_LIMIT_DEFAULTS.max_inspected_args)} onChange={e => upd({ max_inspected_args: optionalNumber(e.target.value) })} /></Field>
                    <Field label="Max Argument Text (KiB)" hint={`Argument names and values, and a body read as text (base64 uploads, text/plain, CSV). Default ${INSPECTION_LIMIT_DEFAULTS.max_inspected_arg_kib}.`}><input className="fin2" type="number" min={0} value={form.max_inspected_arg_kib} placeholder={String(INSPECTION_LIMIT_DEFAULTS.max_inspected_arg_kib)} onChange={e => upd({ max_inspected_arg_kib: optionalNumber(e.target.value) })} /></Field>
                    <Field label="Inspection Time Budget (ms)" hint={`CPU time the rules may spend on one phase of a request. Default ${INSPECTION_LIMIT_DEFAULTS.inspection_time_budget_ms}.`}><input className="fin2" type="number" min={0} value={form.inspection_time_budget_ms} placeholder={String(INSPECTION_LIMIT_DEFAULTS.inspection_time_budget_ms)} onChange={e => upd({ inspection_time_budget_ms: optionalNumber(e.target.value) })} /></Field>
                  </div>
                  <LimitNotes checks={checkSiteLimits(form)} fields={["max_inspected_args", "max_inspected_arg_kib", "inspection_time_budget_ms"]} />
                  <GroupLabel>Allowed HTTP Methods</GroupLabel>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                    {HTTP_METHODS.map(m => {
                      const on = form.allowed_methods.includes(m);
                      return (
                        <span key={m} onClick={() => toggleMethod(m)} style={{ cursor: "pointer", padding: "5px 11px", borderRadius: 8, fontSize: 13, fontWeight: 600, fontFamily: "var(--font-mono)", background: on ? "var(--green-t)" : "var(--fill-soft)", border: on ? "1px solid color-mix(in srgb, var(--green) 32%, transparent)" : "1px solid var(--card-bd)", color: on ? "var(--text)" : "var(--text3)" }}>{m}</span>
                      );
                    })}
                  </div>
                  <SectionToggle label="ML Anomaly Detection" desc="Score requests with the bundled ML models" on={form.ml_enabled} set={v => upd({ ml_enabled: v })} />
                  {form.ml_enabled && (<>
                    <Field label={`ML Sensitivity (${form.ml_sensitivity})`} hint="0 = lenient · 1 = aggressive">
                      <input type="range" min={0} max={1} step={0.05} value={form.ml_sensitivity} onChange={e => upd({ ml_sensitivity: Number(e.target.value) })} style={{ width: "100%" }} />
                    </Field>
                    <Field label="Specific Models" hint="Blank = all bundled models (isolation-forest, n-gram, logistic). Name models to restrict."><ChipInput values={form.ml_models} onChange={v => upd({ ml_models: v })} placeholder="isolation_forest" /></Field>
                  </>)}
                  <SectionToggle label="API Discovery" desc="Learn and document API endpoints automatically" on={form.api_discovery} set={v => upd({ api_discovery: v })} />

                  <GroupLabel>WebAssembly Plugins <Tag kind="enforced" /></GroupLabel>
                  {installedPlugins.length === 0 ? (
                    <InfoBox>
                      No plugins installed. Install one from <strong style={{ color: "var(--cyan)" }}>Plugins</strong> — the
                      catalogue ships a scanner guard — then tick it here to run it on this site.
                    </InfoBox>
                  ) : (<>
                    <InfoBox tone="amber">
                      A plugin runs on this site only when it is ticked here, and only while it is <em>enabled</em> on the
                      Plugins page. That is deliberate: it lets you try a plugin on one site before trusting it with the rest.
                    </InfoBox>
                    <div style={{ display: "grid", gap: 8 }}>
                      {installedPlugins.map(p => {
                        const on = form.site_plugins.includes(p.name);
                        const perms = Object.entries(p.permissions ?? {}).filter(([, v]) => v).map(([k]) => k);
                        const decides = perms.includes("host_set_decision") || perms.includes("host_add_score");
                        return (
                          <label key={p.name} style={{ display: "flex", gap: 10, alignItems: "flex-start", border: "1px solid var(--border2)", borderRadius: 8, padding: "9px 11px", cursor: "pointer" }}>
                            <input type="checkbox" checked={on} style={{ marginTop: 3 }}
                              onChange={e => upd({ site_plugins: e.target.checked ? [...form.site_plugins, p.name] : form.site_plugins.filter(x => x !== p.name) })} />
                            <div style={{ minWidth: 0 }}>
                              <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                                <span style={{ fontWeight: 600 }}>{p.name}</span>
                                <span className="bdg bgr">v{p.version}</span>
                                {!p.enabled && <span className="bdg ba" title="Installed but not enabled — it will not run until you enable it on the Plugins page">NOT ENABLED</span>}
                                {decides && <span className="bdg ba" title="This plugin can block a request or add to its anomaly score">CHANGES VERDICTS</span>}
                              </div>
                              <div style={{ fontSize: 12, color: "var(--text3)", marginTop: 3, lineHeight: 1.5 }}>{p.description}</div>
                            </div>
                          </label>
                        );
                      })}
                    </div>
                  </>)}

                  {/* Response DLP */}
                  <GroupLabel>Response Data-Loss Prevention</GroupLabel>
                  <SectionToggle label="Response DLP scanning" desc="Detect PII/PAN/SSN/secrets in responses — block, mask, or log" on={form.dlp_enabled} set={v => upd({ dlp_enabled: v })} />
                  {form.dlp_enabled && (<>
                    <Field label="On Detection" hint="What to do when sensitive data is found in a response body">
                      <select className="fin2 fsel2" value={form.dlp_action} onChange={e => upd({ dlp_action: e.target.value as SiteForm["dlp_action"] })}>
                        <option value="block">Block the response</option>
                        <option value="mask">Mask / redact in place</option>
                        <option value="detect">Detect only (log)</option>
                      </select>
                    </Field>
                    <Field label="Extra Patterns" hint="Additional regexes on top of the built-in detectors (cards, SSN, keys)"><ChipInput values={form.dlp_patterns} onChange={v => upd({ dlp_patterns: v })} placeholder="\bMY-SECRET-[0-9]{6}\b" /></Field>
                  </>)}

                  {/* Weighted verdict fusion */}
                  <GroupLabel>Weighted Verdict Fusion</GroupLabel>
                  <SectionToggle label="Weighted fusion + soft LIMIT tier" desc="Combine engine scores with weights; add a 429 LIMIT tier below hard block to cut false positives" on={form.fusion_enabled} set={v => upd({ fusion_enabled: v })} />
                  {form.fusion_enabled && (<>
                    <InfoBox>Each engine&apos;s anomaly score is multiplied by its weight, summed, then compared to the per-paranoia thresholds. Weight 1.0 = neutral; below the block threshold but above the LIMIT threshold returns a soft <strong style={{ color: "var(--cyan)" }}>{form.fusion_limit_status}</strong>.</InfoBox>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                      {FUSION_ENGINES.map(eng => (
                        <Field key={eng.key} label={`${eng.label} × weight`} hint={eng.desc}>
                          <input className="fin2" type="number" step={0.1} value={form.fusion_weights[eng.key] ?? 1}
                            onChange={e => upd({ fusion_weights: { ...form.fusion_weights, [eng.key]: Number(e.target.value) } })} />
                        </Field>
                      ))}
                    </div>
                    <Row cols="1fr 1fr">
                      <Field label="Block thresholds (PL1–PL4)" hint="Hard-block score per paranoia level">
                        <input className="fin2" value={form.fusion_block_thresholds.join(", ")} style={{ fontFamily: "var(--font-mono)", fontSize: 13 }}
                          onChange={e => upd({ fusion_block_thresholds: e.target.value.split(",").map(s => Number(s.trim())).filter(n => Number.isFinite(n)) })} />
                      </Field>
                      <Field label="LIMIT thresholds (PL1–PL4)" hint="Soft-limit score per level (blank = no LIMIT tier)">
                        <input className="fin2" value={form.fusion_limit_thresholds.join(", ")} style={{ fontFamily: "var(--font-mono)", fontSize: 13 }}
                          onChange={e => upd({ fusion_limit_thresholds: e.target.value.split(",").map(s => Number(s.trim())).filter(n => Number.isFinite(n)) })} />
                      </Field>
                    </Row>
                    <Field label="LIMIT HTTP Status" hint="Status returned for the soft-limit tier (e.g. 429)"><input className="fin2" type="number" value={form.fusion_limit_status} onChange={e => upd({ fusion_limit_status: Number(e.target.value) })} /></Field>
                  </>)}
                </>)}

                {/* ───────── REVIEW ───────── */}
                {screen === "review" && (
                  <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                    <StepHead title="Review" sub={`Confirm your configuration, then ${mode === "edit" ? "save changes" : "deploy"}. Protection activates in ~5s.`} />
                  <LimitNotes checks={checkSiteLimits(form)} fields={["max_body_size_mb", "max_uri_length", "max_header_count", "max_inspected_args", "max_inspected_arg_kib", "inspection_time_budget_ms", "paranoia_level", "anomaly_threshold"]} />
                  {checking && (
                    <InfoBox tone="cyan">Validating this configuration against the data-plane converter…</InfoBox>
                  )}
                  {!checking && problems !== null && problems.length === 0 && (
                    <InfoBox tone="green">
                      <strong>Configuration valid.</strong> The control plane converted this
                      site successfully, so it will reach the proxy on the next sync.
                    </InfoBox>
                  )}
                  {!checking && problems !== null && problems.length > 0 && (
                    <InfoBox tone="amber">
                      <strong>{problems.length} problem{problems.length > 1 ? "s" : ""} found.</strong>{" "}
                      This site would not protect anything until they are fixed:
                      <ul style={{ margin: "8px 0 0", paddingLeft: 18, lineHeight: 1.7 }}>
                        {problems.map((pr, i) => (
                          <li key={i}>
                            <code style={{ fontFamily: "var(--font-mono)" }}>{pr.field}</code> — {pr.problem}
                          </li>
                        ))}
                      </ul>
                    </InfoBox>
                  )}
                    {[
                      ["Name", form.name || "—"],
                      ["Domains", form.domains.join(", ") || "—"],
                      ["Mode", form.mode.toUpperCase()],
                      ["Public", `${scheme}${form.force_https || form.http2 || form.http3 ? ` · recorded: ${[form.force_https && "force-https", form.http2 && "h2", form.http3 && "h3"].filter(Boolean).join(" · ")}` : ""}`],
                      ["TLS", form.tls_mode === "off" || !form.front_https ? "off" : form.tls_mode === "auto" ? `auto · ${form.acme_staging ? "staging" : form.acme_provider} · ${form.acme_challenge}${form.acme_wildcard ? " · wildcard" : ""}` : form.tls_mode === "existing" ? `repository · ${form.tls_existing_cert || "—"}` : `custom (${form.custom_priority})`],
                      ["Upstreams", form.servers.map(s => `${s.host}:${s.port}${s.tls ? " (TLS)" : ""}`).join(", ")],
                      ["Load Balancer", form.lb],
                      ["Paranoia / Threshold", `PL${form.paranoia_level} · ${form.anomaly_threshold}`],
                      ["CRS Categories", `${form.rule_categories.length} enabled · ${form.rule_exclusions.length} exclusions`],
                      ["Allowed Methods", form.allowed_methods.join(" ")],
                      ["Rate Limit", form.rate_limit_enabled ? `${form.rl_per_ip.rps}/s per IP` : "off"],
                      ["Anti-DDoS", form.antiddos_enabled ? `${form.antiddos_conn_rate} conn/s` : "off"],
                      ["Antibot", `${form.bot_ja4 ? "JA4" : ""}${form.bot_ja4 && form.bot_challenge !== "off" ? " · " : ""}${form.bot_challenge !== "off" ? form.bot_challenge : ""}` || "off"],
                      ["GeoIP", form.geo_mode === "off" ? "off" : `${form.geo_mode} ${form.geo_countries.join(",")}`],
                      ["IP / Blacklist", `${form.ip_allow.length} allow · ${form.ip_block.length} block${form.dnsbl_enabled ? " · DNSBL" : ""}`],
                      ["Plugins", form.site_plugins.length ? form.site_plugins.join(", ") : "none"],
                      ["Headers", `${form.csp ? "CSP " : ""}${form.cors_enabled ? "CORS " : ""}${form.hsts ? "HSTS " : ""}${form.custom_headers.filter(h => h.name).length} custom`],
                      ["ML", form.ml_enabled ? `on (${form.ml_sensitivity})${form.ml_models.length ? ` · ${form.ml_models.length} models` : ""}` : "off"],
                      ["API Auth (JWT)", form.jwt_enabled ? `on${form.jwt_jwks_url ? " · JWKS" : form.jwt_hs_secret ? " · HS" : form.jwt_public_key_pem ? " · PEM" : ""}${form.jwt_required_scopes.length ? ` · ${form.jwt_required_scopes.length} scopes` : ""}` : "off"],
                      ["GraphQL / gRPC", `${form.graphql_enabled ? `GraphQL(d${form.graphql_max_depth})` : ""}${form.graphql_enabled && form.grpc_enabled ? " · " : ""}${form.grpc_enabled ? "gRPC" : ""}` || "off"],
                      ["Response DLP", form.dlp_enabled ? form.dlp_action : "off"],
                      ["Verdict Fusion", form.fusion_enabled ? `on · LIMIT ${form.fusion_limit_status}` : "off"],
                      ["Threat-intel feeds", form.ip_feeds.filter(x => x.url.trim()).length ? `${form.ip_feeds.filter(x => x.url.trim()).length} feeds` : "off"],
                    ].map(([k, v]) => (
                      <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "7px 12px", background: "var(--fill-soft)", borderRadius: 8, fontSize: 13 }}>
                        <span style={{ color: "var(--text3)" }}>{k}</span>
                        <span style={{ color: "var(--text)", fontFamily: "var(--font-mono)", textAlign: "right", maxWidth: "62%" }}>{v}</span>
                      </div>
                    ))}
                  </div>
                )}
              </motion.div>
            </AnimatePresence>
          </div>

          {/* Footer */}
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "14px 22px", borderTop: "1px solid var(--card-bd)" }}>
            <div style={{ fontSize: 14, color: "var(--text3)", fontFamily: "var(--font-sans)" }}>Step {step + 1} / {steps.length}</div>
            <div style={{ display: "flex", gap: 8 }}>
              <button className="btn bg-btn" type="button" onClick={step === 0 ? onClose : back}>{step === 0 ? "Cancel" : "← Back"}</button>
              {step < steps.length - 1 && <button className="btn bg-btn" type="button" onClick={next}>Next →</button>}
              <button className="btn bp" type="button" disabled={saving} onClick={save}>{saving ? <span className="btn-spin" /> : (mode === "edit" ? "Save Changes" : "Deploy Site")}</button>
            </div>
          </div>
        </div>
      </motion.div>
    </motion.div>
  );
}
