"use client";
import { useState } from "react";
import { motion } from "framer-motion";
import { api } from "@/lib/api";
import { emptyForm, formToPayload, PRESETS, type SiteForm } from "@/lib/siteConfig";
import { showToast } from "@/components/ui/Toast";

/**
 * Create a working site from three fields.
 *
 * The full wizard asks 127 labelled fields across five steps in Easy mode and
 * ten in Advanced. Every one of them has a sensible default already — the
 * defaults in `emptyForm()` are the considered ones (learning mode, the balanced
 * preset, HTTPS with force-https, health checks on) — so nearly all of that is a
 * form an operator fills in to say "yes, the defaults". The comparison product
 * creates a site from six fields in one modal, and that difference is most of
 * the perceived gap between the two consoles.
 *
 * This path does NOT build its own payload. It takes `emptyForm()`, sets three
 * values, and hands it to the same `formToPayload()` the wizard calls. That
 * matters more than it looks: `buildRustWaf` on the Go side is an ALLOWLIST, so
 * a second hand-rolled payload is how a key gets stored, echoed back, and
 * silently dropped before it reaches the data plane. There is one conversion,
 * and both paths use it.
 *
 * It also dry-runs `sites.validate` before creating, so a bad upstream is a
 * message in this modal rather than a site that exists and 502s.
 */
export default function QuickAddSite({
  onClose, onCreated, onAdvanced,
}: {
  onClose: () => void;
  onCreated: (domain: string) => void;
  /** Hand off to the full wizard, carrying whatever has been typed so far. */
  onAdvanced: (initial: SiteForm) => void;
}) {
  const [name, setName] = useState("");
  const [domain, setDomain] = useState("");
  const [upstream, setUpstream] = useState("");
  // The automatic certificate needs a contact email: without one the control
  // plane turns TLS off, and Quick Add said "automatic certificate" while none
  // was ever requested.
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  // "host:port", "host", "http://host:port" all mean the same thing to an
  // operator typing quickly. Accept them all rather than rejecting on shape.
  function parseUpstream(raw: string): { host: string; port: number } | null {
    const v = raw.trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "");
    if (!v) return null;
    const tls = /^https:\/\//i.test(raw.trim());
    const m = v.match(/^\[(.+)\]:(\d+)$/);           // [::1]:8080
    if (m) return { host: m[1], port: Number(m[2]) };
    const parts = v.split(":");
    if (parts.length === 2 && /^\d+$/.test(parts[1])) {
      return { host: parts[0], port: Number(parts[1]) };
    }
    if (parts.length > 2) return { host: v, port: tls ? 443 : 80 };  // bare IPv6
    return { host: v, port: tls ? 443 : 80 };
  }

  function buildForm(): SiteForm {
    const f = emptyForm();
    const up = parseUpstream(upstream);
    f.name = name.trim() || domain.trim();
    f.domains = domain.trim() ? [domain.trim()] : [];
    f.acme_email = email.trim();
    if (up) {
      const tls = /^https:\/\//i.test(upstream.trim()) || up.port === 443;
      f.servers = [{ host: up.host, port: up.port, weight: 1, tls }];
    }
    return f;
  }

  const ready = domain.trim().length > 0 && parseUpstream(upstream) !== null;

  async function create() {
    setError("");
    const up = parseUpstream(upstream);
    if (!domain.trim()) { setError("A domain or IP address is required — this is what visitors will use."); return; }
    if (!up) { setError("Give the origin as host:port, for example 10.0.0.5:8080."); return; }
    if (!Number.isFinite(up.port) || up.port < 1 || up.port > 65535) {
      setError(`${up.port} is not a usable port.`); return;
    }
    setBusy(true);
    try {
      const payload = formToPayload(buildForm());
      // Dry-run first: the same conversion the config sync runs, so a green
      // result means the data plane will accept this.
      try {
        const v = await api.sites.validate(payload);
        if (v && v.valid === false) {
          const first = (v.problems ?? [])[0];
          setError(first
            ? `${first.field}: ${first.problem}`
            : "The data plane rejected this configuration.");
          setBusy(false);
          return;
        }
      } catch {
        // Validation being unavailable must not block creation — it is a
        // pre-flight, not the gate.
      }
      await api.sites.create(payload);
      showToast("Site created in learning mode", "s");
      onCreated(domain.trim());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not create the site.");
    } finally {
      setBusy(false);
    }
  }

  const p = PRESETS.balanced;

  return (
    <motion.div
      style={{ position: "fixed", inset: 0, zIndex: 1000, background: "var(--scrim)",
               display: "flex", alignItems: "center",
               justifyContent: "center", padding: 24 }}
      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      onClick={e => { if (e.target === e.currentTarget) onClose(); }}>
      <motion.div
        initial={{ opacity: 0, scale: 0.96, y: 16 }} animate={{ opacity: 1, scale: 1, y: 0 }}
        transition={{ type: "spring", duration: 0.32, bounce: 0 }}
        style={{ width: "min(560px, 96vw)", background: "var(--bg2)",
                 border: "1px solid var(--card-bd)", borderRadius: 16,
                 boxShadow: "var(--shadow-modal)", padding: 22 }}>

        <div style={{ fontFamily: "var(--font-display)", fontSize: 19, fontWeight: 700, marginBottom: 4 }}>
          Protect a site
        </div>
        <div className="td3" style={{ fontSize: 13, marginBottom: 18, lineHeight: 1.5 }}>
          Three fields. Everything else takes the defaults, which you can change
          afterwards on the site&apos;s own page.
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <label style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            <span style={{ fontSize: 12.5, color: "var(--text2)", fontWeight: 600 }}>
              Domain visitors will use
            </span>
            <input className="fin2" autoFocus value={domain} onChange={e => setDomain(e.target.value)}
              placeholder="shop.example.com — or an IP address"
              style={{ fontFamily: "var(--font-mono)" }}
              onKeyDown={e => { if (e.key === "Enter" && ready) create(); }} />
          </label>

          <label style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            <span style={{ fontSize: 12.5, color: "var(--text2)", fontWeight: 600 }}>
              Where the traffic should go
            </span>
            <input className="fin2" value={upstream} onChange={e => setUpstream(e.target.value)}
              placeholder="10.0.0.5:8080"
              style={{ fontFamily: "var(--font-mono)" }}
              onKeyDown={e => { if (e.key === "Enter" && ready) create(); }} />
            <span className="td3" style={{ fontSize: 12 }}>
              Your application&apos;s own address, which visitors no longer reach directly.
            </span>
          </label>

          <label style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            <span style={{ fontSize: 12.5, color: "var(--text2)", fontWeight: 600 }}>
              Name <span className="td3" style={{ fontWeight: 400 }}>— optional</span>
            </span>
            <input className="fin2" value={name} onChange={e => setName(e.target.value)}
              placeholder={domain.trim() || "defaults to the domain"}
              onKeyDown={e => { if (e.key === "Enter" && ready) create(); }} />
          </label>
          <label style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            <span style={{ fontSize: 12.5, color: "var(--text2)", fontWeight: 600 }}>
              Certificate email <span className="td3" style={{ fontWeight: 400 }}>— for the automatic Let&apos;s Encrypt certificate</span>
            </span>
            <input className="fin2" type="email" value={email} onChange={e => setEmail(e.target.value)}
              placeholder="ops@example.com — leave empty to upload a certificate later"
              onKeyDown={e => { if (e.key === "Enter" && ready) create(); }} />
          </label>
        </div>

        {/* State what the defaults ARE. "Takes the defaults" is only reassuring
            if the operator can see which ones, and mode is the one that changes
            what happens to real traffic. */}
        <div style={{ marginTop: 16, padding: "11px 13px", borderRadius: 9,
                      border: "1px solid var(--cyan-ring)", background: "var(--cyan-dim)" }}>
          <div style={{ fontSize: 12.5, color: "var(--text2)", fontWeight: 600, marginBottom: 4 }}>
            What you get
          </div>
          <div className="td3" style={{ fontSize: 12.5, lineHeight: 1.6 }}>
            <strong>Learning mode</strong> — attacks are inspected, scored and logged, and
            nothing is blocked until you switch the site to blocking. That is deliberate:
            it lets you see this application&apos;s false positives before they reject a
            real customer.<br />
            OWASP CRS at paranoia level {p.paranoia_level}, anomaly threshold{" "}
            {p.anomaly_threshold} · HTTPS with HSTS ·{" "}
            {email.trim() ? "automatic certificate" : "no certificate requested until you add an email or upload one"}{" "}
            · rate limiting on · health checks on.
          </div>
        </div>

        {error && (
          <div role="alert" style={{ marginTop: 12, fontSize: 12.5, color: "var(--red-b)", lineHeight: 1.5 }}>
            {error}
          </div>
        )}

        <div style={{ display: "flex", alignItems: "center", gap: 10, marginTop: 18 }}>
          <motion.button className="btn bp" disabled={busy || !ready} onClick={create} whileTap={{ scale: 0.97 }}>
            {busy ? "Creating…" : "Create site"}
          </motion.button>
          <button className="btn bg-btn" onClick={onClose} disabled={busy}>Cancel</button>
          <span style={{ flex: 1 }} />
          <button className="btn bg-btn btn-sm" disabled={busy}
            onClick={() => onAdvanced(buildForm())}
            title="Open the full wizard, keeping what you have typed">
            All settings →
          </button>
        </div>
      </motion.div>
    </motion.div>
  );
}
