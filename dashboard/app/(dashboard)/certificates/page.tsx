"use client";
import { useState, useEffect, useMemo } from "react";
import { motion } from "framer-motion";
import { showToast } from "@/components/ui/Toast";
import EmptyState from "@/components/ui/EmptyState";
import { PRODUCT_NAME } from "@/lib/version";
import {
  api,
  type Certificate,
  type CertSource,
  type AcmeProvider,
  type AcmeChallenge,
  type Site,
} from "@/lib/api";
import { certCoversHost } from "@/lib/siteConfig";
import { staggerContainer, cardVariants, fadeUp } from "@/lib/animations";

/** All names a cert presents (primary + SANs). */
function certNames(c: Certificate): string[] {
  return [c.domain, ...(c.san ?? [])].filter(Boolean);
}
/** Is this cert a wildcard? */
function isWildcard(c: Certificate): boolean {
  return certNames(c).some(n => n.startsWith("*."));
}
/** Configured sites this cert protects (exact or wildcard match on any domain). */
function protectedSites(c: Certificate, sites: Site[]): Site[] {
  const names = certNames(c);
  return sites.filter(s => (s.domains ?? []).some(d => certCoversHost(names, d)));
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function sourceLabel(s: CertSource): { text: string; cls: string } {
  if (s === "manual") return { text: "Manual", cls: "bcy" };
  if (s === "self_signed") return { text: "Self-signed", cls: "ba" };
  if (typeof s === "object" && "acme" in s) {
    const p = s.acme.provider.toLowerCase();
    const pretty = p.includes("staging")
      ? "LE Staging"
      : p.includes("zerossl")
      ? "ZeroSSL"
      : "Let's Encrypt";
    return { text: `ACME · ${pretty}`, cls: "bgg" };
  }
  return { text: "Unknown", cls: "bgr" };
}

function daysUntil(expiresAt: number): number | null {
  if (!expiresAt) return null;
  return Math.floor((expiresAt * 1000 - Date.now()) / 86_400_000);
}

function statusOf(c: Certificate): { label: string; cls: string } {
  const d = daysUntil(c.expires_at);
  if (d === null) return { label: "UNKNOWN", cls: "bgr" };
  if (d <= 0) return { label: "EXPIRED", cls: "br blink" };
  if (d <= 7) return { label: "CRITICAL", cls: "br" };
  if (d <= 30) return { label: "EXPIRING", cls: "ba" };
  return { label: "VALID", cls: "bgg" };
}

function fmtDate(unix: number): string {
  if (!unix) return "—";
  return new Date(unix * 1000).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

// 90-day lifetime bar (LE default). Width = fraction of life remaining.
function lifeBar(c: Certificate) {
  const d = daysUntil(c.expires_at);
  if (d === null) return null;
  const pct = Math.max(0, Math.min(100, (d / 90) * 100));
  const color = d <= 7 ? "var(--red)" : d <= 30 ? "var(--amber)" : "var(--green)";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <div style={{ flex: 1, height: 6, background: "var(--fill)", borderRadius: 3, overflow: "hidden", minWidth: 80 }}>
        <div style={{ width: `${pct}%`, height: "100%", background: color, transition: "width .4s" }} />
      </div>
      <span className="td3" style={{ minWidth: 64, textAlign: "right" }}>
        {d <= 0 ? "expired" : `${d}d left`}
      </span>
    </div>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function CertificatesPage() {
  const [certs, setCerts]   = useState<Certificate[]>([]);
  const [sites, setSites]   = useState<Site[]>([]);
  const [loading, setLoading] = useState(true);
  const [wafUp, setWafUp]   = useState(true);
  const [busy, setBusy]     = useState<string | null>(null);
  const [tab, setTab]       = useState<"acme" | "manual">("acme");
  const [rootCA, setRootCA] = useState<{ available: boolean; subject?: string; not_after?: number; fingerprint?: string } | null>(null);

  // ACME form
  const [acmeDomains, setAcmeDomains]   = useState("");
  const [acmeEmail, setAcmeEmail]       = useState("");
  const [acmeProvider, setAcmeProvider] = useState<AcmeProvider>("letsencrypt");
  const [acmeChallenge, setAcmeChallenge] = useState<AcmeChallenge>("http_01");

  // Manual form
  const [manualDomain, setManualDomain] = useState("");
  const [manualName, setManualName]     = useState("");
  const [manualCert, setManualCert]     = useState("");
  const [manualKey, setManualKey]       = useState("");

  async function load() {
    setLoading(true);
    try {
      // Independent calls — fetch concurrently. Sites are optional, so swallow
      // their failure without failing the whole load.
      const [res, s, ca] = await Promise.all([
        api.certs.list(),
        api.sites.list().catch(() => ({ sites: [] as Site[] })),
        api.certs.rootCAInfo().catch(() => ({ available: false })),
      ]);
      setCerts(res.certs ?? []);
      setWafUp(res.waf_running);
      setSites(s.sites ?? []);
      setRootCA(ca);
    } catch {
      showToast("Failed to load certificates", "e");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  async function downloadRootCA() {
    setBusy("rootca");
    try {
      await api.certs.downloadRootCA();
      showToast("Root CA downloaded — import it as a trusted root authority for a green lock", "s");
    } catch {
      showToast("Failed to download root CA", "e");
    } finally {
      setBusy(null);
    }
  }

  // Map each cert → the sites it protects once per certs/sites change, instead
  // of recomputing the O(certs × sites) match for every row on every render.
  const coveredByDomain = useMemo(() => {
    const m = new Map<string, Site[]>();
    for (const c of certs) m.set(c.domain, protectedSites(c, sites));
    return m;
  }, [certs, sites]);

  const counts = {
    total:    certs.length,
    valid:    certs.filter(c => { const d = daysUntil(c.expires_at); return d !== null && d > 30; }).length,
    expiring: certs.filter(c => { const d = daysUntil(c.expires_at); return d !== null && d > 0 && d <= 30; }).length,
    expired:  certs.filter(c => { const d = daysUntil(c.expires_at); return d !== null && d <= 0; }).length,
  };

  // Sort soonest-expiring first so at-risk certs surface at the top of the
  // table; unknown expiry (expires_at 0 → null) sinks to the bottom.
  const sortedCerts = useMemo(
    () => [...certs].sort((a, b) => (daysUntil(a.expires_at) ?? Infinity) - (daysUntil(b.expires_at) ?? Infinity)),
    [certs],
  );

  async function submitAcme() {
    const domains = acmeDomains.split(/[\s,]+/).map(s => s.trim()).filter(Boolean);
    if (domains.length === 0) return showToast("Enter at least one domain", "e");
    if (!acmeEmail) return showToast("ACME account email is required", "e");
    setBusy("acme");
    showToast("Requesting certificate — validating domain ownership…", "i");
    try {
      const res = await api.certs.requestAcme({
        domains, email: acmeEmail, provider: acmeProvider, challenge: acmeChallenge,
      });
      showToast(`Issued certificate for ${res.issued.join(", ")}`, "s");
      setAcmeDomains(""); setAcmeEmail("");
      load();
    } catch (e) {
      showToast(`ACME failed: ${(e as Error).message}`, "e");
    } finally {
      setBusy(null);
    }
  }

  async function submitManual() {
    if (!manualDomain || !manualCert || !manualKey)
      return showToast("Domain, certificate and key are all required", "e");
    setBusy("manual");
    try {
      await api.certs.uploadManual({ domain: manualDomain, name: manualName.trim(), cert_pem: manualCert, key_pem: manualKey });
      showToast(`Installed certificate ${manualName.trim() || manualDomain}`, "s");
      setManualDomain(""); setManualName(""); setManualCert(""); setManualKey("");
      load();
    } catch (e) {
      showToast(`Upload failed: ${(e as Error).message}`, "e");
    } finally {
      setBusy(null);
    }
  }

  async function rename(c: Certificate) {
    const current = c.name ?? "";
    const next = window.prompt(`Profile name for ${c.domain}`, current);
    if (next === null || next.trim() === current) return;
    setBusy(c.domain);
    try {
      await api.certs.rename(c.domain, next.trim());
      showToast(`Renamed to "${next.trim() || c.domain}"`, "s");
      load();
    } catch (e) {
      showToast(`Rename failed: ${(e as Error).message}`, "e");
    } finally { setBusy(null); }
  }

  async function renew(domain: string) {
    setBusy(domain);
    showToast(`Renewing ${domain}…`, "i");
    try {
      await api.certs.renew(domain);
      showToast(`Renewed ${domain}`, "s");
      load();
    } catch (e) {
      showToast(`Renew failed: ${(e as Error).message}`, "e");
    } finally {
      setBusy(null);
    }
  }

  async function remove(domain: string) {
    if (!confirm(`Delete the certificate for ${domain}? The site will fall back to a self-signed cert.`)) return;
    setBusy(domain);
    try {
      await api.certs.delete(domain);
      showToast(`Deleted ${domain}`, "s");
      setCerts(p => p.filter(c => c.domain !== domain));
    } catch (e) {
      showToast(`Delete failed: ${(e as Error).message}`, "e");
    } finally {
      setBusy(null);
    }
  }

  const kpis = [
    { cls: "kg", lbl: "Total Certs", val: counts.total, valCls: "g" },
    { cls: "kg", lbl: "Valid",       val: counts.valid, valCls: "g" },
    { cls: "kc", lbl: "Expiring ≤30d", val: counts.expiring, valCls: "c" },
    { cls: "",   lbl: "Expired",     val: counts.expired, valCls: "r" },
  ];

  return (
    <motion.div className="sec" variants={staggerContainer} initial="hidden" animate="visible">
      <motion.div variants={fadeUp} style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 14 }}>
        <div>
          <div className="sec-title">Certificate Repository</div>
          <div className="sec-sub">
            Upload once, assign to many sites · wildcards cover every subdomain · ACME auto-renew · hot-swap ·{" "}
            {wafUp ? <span style={{ color: "var(--green)" }}>data plane online</span>
                   : <span style={{ color: "var(--amber)" }}>data plane offline</span>}
          </div>
        </div>
        <motion.button className="btn bg-btn btn-sm" onClick={load} whileTap={{ scale: 0.97 }}>⟳ Refresh</motion.button>
      </motion.div>

      {rootCA?.available && (
        <motion.div className="panel" variants={fadeUp}
          style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 14, flexWrap: "wrap" }}>
          <div style={{ minWidth: 0 }}>
            <div style={{ fontWeight: 600 }}>Trust this WAF (import the Root CA)</div>
            <div className="sec-sub" style={{ marginTop: 4 }}>
              Browsers warn on the WAF&apos;s HTTPS-by-IP endpoint until they trust our private CA. Download it
              once and install it as a <em>trusted root authority</em> to get a green lock — encryption is
              already on regardless.
              {rootCA.subject ? <> · <span style={{ opacity: .85 }}>{rootCA.subject}</span></> : null}
              {rootCA.not_after ? <> · valid to {fmtDate(rootCA.not_after)}</> : null}
            </div>
          </div>
          <motion.button className="btn bc btn-sm" disabled={busy === "rootca"} onClick={downloadRootCA} whileTap={{ scale: 0.97 }}>
            {busy === "rootca" ? "Downloading…" : "Download Root CA"}
          </motion.button>
        </motion.div>
      )}

      <motion.div variants={staggerContainer} initial="hidden" animate="visible" style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 12 }}>
        {kpis.map((k, i) => (
          <motion.div key={i} className={`kpi ${k.cls}`} variants={cardVariants}>
            <div className="kpi-lbl">{k.lbl}</div>
            <div className={`kpi-val ${k.valCls}`}>{k.val}</div>
          </motion.div>
        ))}
      </motion.div>

      {/* Issue / upload */}
      <motion.div className="panel" variants={fadeUp}>
        <div className="ph">
          <div className="ptitle">Add Certificate</div>
          <div style={{ display: "flex", gap: 8 }}>
            <button className={`btn btn-sm ${tab === "acme" ? "bc" : "bg-btn"}`} onClick={() => setTab("acme")}>Auto SSL (ACME)</button>
            <button className={`btn btn-sm ${tab === "manual" ? "bc" : "bg-btn"}`} onClick={() => setTab("manual")}>Manual Upload</button>
          </div>
        </div>

        <div style={{ padding: 16 }}>
          {tab === "acme" ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              <div style={{ fontSize: 14, color: "var(--text2)" }}>
                {PRODUCT_NAME} speaks ACME natively (no certbot). Domains must resolve to this WAF and be reachable
                on port 80 (HTTP-01) or 443 (TLS-ALPN-01). Certs auto-renew 30 days before expiry.
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                <label style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  <span className="td3">Domains (comma or space separated)</span>
                  <input className="fi2" placeholder="example.com www.example.com" value={acmeDomains} onChange={e => setAcmeDomains(e.target.value)} />
                </label>
                <label style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  <span className="td3">ACME account email</span>
                  <input className="fi2" type="email" placeholder="ops@example.com" value={acmeEmail} onChange={e => setAcmeEmail(e.target.value)} />
                </label>
                <label style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  <span className="td3">Provider</span>
                  <select className="fsel" value={acmeProvider} onChange={e => setAcmeProvider(e.target.value as AcmeProvider)}>
                    <option value="letsencrypt">Let&apos;s Encrypt (production)</option>
                    <option value="letsencrypt_staging">Let&apos;s Encrypt (staging / testing)</option>
                    <option value="zerossl">ZeroSSL</option>
                  </select>
                </label>
                <label style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  <span className="td3">Challenge type</span>
                  <select className="fsel" value={acmeChallenge} onChange={e => setAcmeChallenge(e.target.value as AcmeChallenge)}>
                    <option value="http_01">HTTP-01 (port 80)</option>
                    <option value="tls_alpn_01">TLS-ALPN-01 (port 443, no port 80 needed)</option>
                  </select>
                </label>
              </div>
              <div>
                <motion.button className="btn bc" disabled={busy === "acme"} onClick={submitAcme} whileTap={{ scale: 0.97 }}>
                  {busy === "acme" ? "Requesting…" : "Request Certificate"}
                </motion.button>
              </div>
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              <div style={{ fontSize: 14, color: "var(--text2)" }}>
                Paste a PEM certificate chain and its private key. Installed instantly via hot-swap — no restart.
                Once uploaded it lives in the repository and can be assigned to any matching site from the Add-Site wizard
                (<strong>Front Service → From Repository</strong>) — no re-upload. Enter a <strong>wildcard</strong> like
                <code style={{ color: "var(--cyan)" }}> *.company.com</code> to cover every subdomain with a single cert.
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, maxWidth: 540 }}>
                <label style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  <span className="td3">Profile name (optional, e.g. &ldquo;Corp Wildcard 2026&rdquo;)</span>
                  <input className="fi2" placeholder="Corp Wildcard" value={manualName} onChange={e => setManualName(e.target.value)} />
                </label>
                <label style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  <span className="td3">Domain (use *.company.com for a wildcard)</span>
                  <input className="fi2" placeholder="*.company.com" value={manualDomain} onChange={e => setManualDomain(e.target.value)} />
                </label>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                <label style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  <span className="td3">Certificate (PEM, full chain)</span>
                  <textarea className="fi2" rows={8} style={{ fontFamily: "var(--font-mono)", fontSize: 13, resize: "vertical" }}
                    placeholder="-----BEGIN CERTIFICATE-----" value={manualCert} onChange={e => setManualCert(e.target.value)} />
                </label>
                <label style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  <span className="td3">Private Key (PEM)</span>
                  <textarea className="fi2" rows={8} style={{ fontFamily: "var(--font-mono)", fontSize: 13, resize: "vertical" }}
                    placeholder="-----BEGIN PRIVATE KEY-----" value={manualKey} onChange={e => setManualKey(e.target.value)} />
                </label>
              </div>
              <div>
                <motion.button className="btn bc" disabled={busy === "manual"} onClick={submitManual} whileTap={{ scale: 0.97 }}>
                  {busy === "manual" ? "Installing…" : "Install Certificate"}
                </motion.button>
              </div>
            </div>
          )}
        </div>
      </motion.div>

      {/* Cert table */}
      <motion.div className="panel" variants={fadeUp}>
        <div className="ph">
          <div className="ptitle">Installed Certificates ({certs.length})</div>
          {(counts.expiring + counts.expired) > 0 && (
            <span className={`bdg ${counts.expired > 0 ? "br" : "ba"}`}><span className="bdr" />
              {counts.expired > 0 ? `${counts.expired} expired · ` : ""}{counts.expiring} expiring ≤30d
            </span>
          )}
        </div>
        <div className="tw">
          {loading ? (
            <div style={{ padding: 24, textAlign: "center", fontFamily: "var(--font-sans)", fontSize: 13, color: "var(--text3)" }}>Loading certificates…</div>
          ) : certs.length === 0 ? (
            <EmptyState icon="lock" title="No certificates yet" hint="Sites are served with the shared self-signed certificate until one is issued. Request one with ACME or upload a PEM above — every WAF node picks it up on the next sync." />
          ) : (
            <table>
              <thead><tr><th>Domain</th><th>Protects</th><th>Source</th><th>Status</th><th>Expiry</th><th>Lifetime</th><th>Actions</th></tr></thead>
              <tbody>
                {sortedCerts.map((c, idx) => {
                  const src = sourceLabel(c.source);
                  const st = statusOf(c);
                  const isAcme = typeof c.source === "object" && "acme" in c.source;
                  const covered = coveredByDomain.get(c.domain) ?? [];
                  return (
                    <motion.tr key={c.domain} initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: idx * 0.02 }}>
                      <td style={{ maxWidth: 260 }}>
                        <div style={{ fontWeight: 600, display: "flex", alignItems: "center", gap: 6, minWidth: 0 }}>
                          <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={c.name || c.domain}>
                            {c.name ? c.name : c.domain}
                          </span>
                          {isWildcard(c) && <span className="bdg bcy" style={{ flexShrink: 0 }} title="Wildcard — covers all subdomains">wildcard</span>}
                        </div>
                        <div className="td3" style={{ fontSize: 14, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {c.name ? c.domain : ""}{c.san.length > 1 ? `${c.name ? " · " : ""}+${c.san.length - 1} SAN` : ""}
                        </div>
                      </td>
                      <td title={covered.map(s => s.name).join(", ")}>
                        {covered.length === 0
                          ? <span className="td3" style={{ fontSize: 14 }}>—</span>
                          : <span className="bdg bgg">{covered.length} site{covered.length > 1 ? "s" : ""}</span>}
                      </td>
                      <td><span className={`bdg ${src.cls}`}><span className="bdr" />{src.text}</span></td>
                      <td><span className={`bdg ${st.cls}`}><span className="bdr" />{st.label}</span></td>
                      <td className="td3">{fmtDate(c.expires_at)}</td>
                      <td style={{ minWidth: 180 }}>{lifeBar(c)}</td>
                      <td>
                        <div style={{ display: "flex", gap: 4 }}>
                          <motion.button className="btn bg-btn btn-xs" disabled={busy === c.domain} whileTap={{ scale: 0.97 }} onClick={() => rename(c)} title="Set profile name">
                            Rename
                          </motion.button>
                          {isAcme && (
                            <motion.button className="btn bg-btn btn-xs" disabled={busy === c.domain} whileTap={{ scale: 0.97 }} onClick={() => renew(c.domain)}>
                              {busy === c.domain ? "…" : "Renew"}
                            </motion.button>
                          )}
                          <motion.button className="btn bgn btn-xs" disabled={busy === c.domain} whileTap={{ scale: 0.97 }} onClick={() => remove(c.domain)}>
                            Delete
                          </motion.button>
                        </div>
                      </td>
                    </motion.tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </motion.div>
    </motion.div>
  );
}
