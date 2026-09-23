"use client";
import { PRODUCT_NAME, PRODUCT_VERSION } from "@/lib/version";
import { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import { login, clearSessionCookie, MfaRequiredError } from "@/lib/auth";
import { spring } from "@/lib/animations";
import ChunkRecovery from "@/components/layout/ChunkRecovery";
import Icon from "@/components/ui/Icon";

type AuthTab  = "std" | "sso" | "api";
type BtnState = "idle" | "loading" | "success";

// A rotating "threat feed" badge used to sit in the corner of this page,
// cycling six hardcoded strings every three seconds: "THREAT BLOCKED: SQLi
// attempt", "RATE LIMIT: 10.0.0.44", "BOT DETECTED: crawler",
// "CVE-2024-3912: patched", "DDoS DROP: SYN flood". None of it was observed
// traffic. The source IP was invented, the CVE does not exist, and the same
// six events replayed forever on every load.
//
// It was removed on 2026-09-07 because it did real harm: an operator read
// "RATE LIMIT" and "BOT DETECTED" on the login screen, concluded the WAF had
// blocked them, and went looking for a block that never existed. Nobody can
// tell decoration from telemetry on a security product's own login page — and
// the same fabrication was already deleted from the dashboard layout (the
// "LIVE THREATS" marquee) for exactly this reason. Live activity belongs on
// /events, sourced from ClickHouse, behind a login.
//
// The login page still shows measured facts: the product version, and the
// benchmark numbers under the form.

export default function LoginPage() {
  const router = useRouter();

  // ── Preserved logic state ────────────────────────────────────────────────
  const [email, setEmail]           = useState("");
  const [password, setPassword]     = useState("");
  const [mfaCode, setMfaCode]       = useState("");
  const [mfaNeeded, setMfaNeeded]   = useState(false);
  const [loginError, setLoginError] = useState("");
  // null = not asked yet, false = not configured, true = usable. The button
  // renders ONLY on true: /oidc/login answers 501 when the issuer and client
  // secret are unset, and a button that returns a JSON error would be the same
  // defect as the one it replaced.
  const [ssoReady, setSsoReady]     = useState<boolean | null>(null);

  useEffect(() => {
    let live = true;
    fetch("/api/v1/auth/oidc/status")
      .then(r => (r.ok ? r.json() : { configured: false }))
      .then(d => { if (live) setSsoReady(Boolean(d?.configured)); })
      .catch(() => { if (live) setSsoReady(false); });
    return () => { live = false; };
  }, []);
  const [btnState, setBtnState]     = useState<BtnState>("idle");

  // ── UI state ─────────────────────────────────────────────────────────────
  const [tab, setTab]               = useState<AuthTab>("std");
  const [showPwd, setShowPwd]       = useState(false);

  // ── Refs ─────────────────────────────────────────────────────────────────
  const canvasRef   = useRef<HTMLCanvasElement>(null);
  const scanlineRef = useRef<HTMLDivElement>(null);
  const lpRef       = useRef<HTMLDivElement>(null);

  // ── Clear any stale session cookie on login page mount ───────────────────
  useEffect(() => { clearSessionCookie(); }, []);

  // ── Canvas animation (ported from sentinel_waf_login.html) ───────────────
  useEffect(() => {
    const c  = canvasRef.current;
    if (!c) return;
    const cx = c.getContext("2d");
    if (!cx) return;

    function rsz() {
      if (!c) return;
      c.width  = c.offsetWidth;
      c.height = c.offsetHeight;
    }
    rsz();

    type Node = { x: number; y: number; vx: number; vy: number; r: number };
    const nodes: Node[] = [];
    for (let i = 0; i < 28; i++) {
      nodes.push({
        x:  Math.random() * c.width,
        y:  Math.random() * c.height,
        vx: (Math.random() - 0.5) * 0.25,
        vy: (Math.random() - 0.5) * 0.25,
        r:  Math.random() * 1.8 + 0.5,
      });
    }

    type Stream = { x: number; y: number; spd: number; ch: string[]; len: number; a: number };
    const streams: Stream[] = [];
    const gl = "01><#$@ABCDEFabcdef";

    function addS() {
      if (!c) return;
      streams.push({ x: Math.random() * c.width, y: 0, spd: 0.5 + Math.random(), ch: [], len: 5 + Math.floor(Math.random() * 8), a: 0.15 + Math.random() * 0.2 });
    }
    for (let i = 0; i < 12; i++) setTimeout(addS, i * 200);
    const streamInt = setInterval(addS, 400);

    let t = 0;
    let rafId: number;

    function draw() {
      if (!c || !cx) return;
      cx.clearRect(0, 0, c.width, c.height);
      // Paint the dark backdrop only in the dark theme. This canvas covers the
      // whole left panel, and it used to paint near-black every frame whatever
      // the theme — so in light mode the stylesheet's light panel never showed,
      // while the text on it switched to light-theme (dark) colours: a dark-grey
      // headline on near-black. In light mode the canvas stays transparent and
      // draws only its accents, over the light gradient from globals.css.
      if (document.documentElement.getAttribute("data-theme") !== "light") {
        cx.fillStyle = "rgba(4,7,15,0.85)";
        cx.fillRect(0, 0, c.width, c.height);
      }
      t++;

      for (let x = 0; x < c.width; x += 50) {
        for (let y = 0; y < c.height; y += 50) {
          cx.beginPath(); cx.arc(x, y, 1, 0, Math.PI * 2);
          cx.fillStyle = "rgba(59,130,246,0.12)"; cx.fill();
        }
      }

      nodes.forEach(n => {
        n.x += n.vx; n.y += n.vy;
        if (n.x < 0 || n.x > c!.width)  n.vx *= -1;
        if (n.y < 0 || n.y > c!.height) n.vy *= -1;
      });
      nodes.forEach((n, i) => {
        nodes.forEach((m, j) => {
          if (j <= i) return;
          const d = Math.hypot(n.x - m.x, n.y - m.y);
          if (d < 100) {
            cx!.beginPath(); cx!.moveTo(n.x, n.y); cx!.lineTo(m.x, m.y);
            cx!.strokeStyle = `rgba(59,130,246,${0.12 * (1 - d / 100)})`;
            cx!.lineWidth = 0.5; cx!.stroke();
          }
        });
        const p = 0.3 + 0.3 * Math.sin(t * 0.04 + i);
        cx!.beginPath(); cx!.arc(n.x, n.y, n.r, 0, Math.PI * 2);
        cx!.fillStyle = `rgba(96,165,250,${p})`; cx!.fill();
      });

      cx.font = "9px var(--font-mono)";
      for (let idx = streams.length - 1; idx >= 0; idx--) {
        const s = streams[idx];
        s.y += s.spd;
        for (let i = 0; i < s.len; i++) {
          if (t % 5 === 0) s.ch[i] = gl[Math.floor(Math.random() * gl.length)];
          const sy = s.y - i * 11;
          if (sy < 0 || sy > c!.height) continue;
          cx!.fillStyle = `rgba(59,130,246,${i === 0 ? s.a : (1 - i / s.len) * s.a * 0.6})`;
          cx!.fillText(s.ch[i] ?? "0", s.x, sy);
        }
        if (s.y > c!.height + s.len * 11) streams.splice(idx, 1);
      }

      const ra = (t * 0.008) % (Math.PI * 2);
      cx.save(); cx.translate(70, c.height - 70);
      cx.beginPath(); cx.moveTo(0, 0); cx.arc(0, 0, 55, ra - 0.5, ra); cx.closePath();
      cx.fillStyle = "rgba(59,130,246,0.07)"; cx.fill();
      [55, 38, 20].forEach(r => {
        cx!.beginPath(); cx!.arc(0, 0, r, 0, Math.PI * 2);
        cx!.strokeStyle = "rgba(59,130,246,0.12)"; cx!.lineWidth = 0.5; cx!.stroke();
      });
      cx.beginPath(); cx.moveTo(0, 0); cx.lineTo(55 * Math.cos(ra), 55 * Math.sin(ra));
      cx.strokeStyle = "rgba(96,165,250,0.5)"; cx.lineWidth = 1; cx.stroke();
      cx.restore();

      rafId = requestAnimationFrame(draw);
    }
    draw();

    const onResize = () => rsz();
    window.addEventListener("resize", onResize);
    return () => {
      cancelAnimationFrame(rafId);
      clearInterval(streamInt);
      window.removeEventListener("resize", onResize);
    };
  }, []);

  // ── Scanline RAF ──────────────────────────────────────────────────────────
  useEffect(() => {
    const el = scanlineRef.current;
    const lp = lpRef.current;
    if (!el || !lp) return;
    let sy = 0;
    let rafId: number;
    function ss() {
      sy = (sy + 1.2) % lp!.offsetHeight;
      el!.style.top = `${sy}px`;
      rafId = requestAnimationFrame(ss);
    }
    rafId = requestAnimationFrame(ss);
    return () => cancelAnimationFrame(rafId);
  }, []);

  // ── Login handler (preserved exactly) ────────────────────────────────────
  async function doLogin() {
    if (btnState !== "idle") return;
    setBtnState("loading");
    setLoginError("");
    try {
      await login(email, password, mfaCode || undefined);
      const token = typeof window !== "undefined"
        ? localStorage.getItem("sentinel_access_token")
        : null;
      if (token) {
        document.cookie = `sentinel_token=${token}; path=/; max-age=604800; SameSite=Lax`;
      }
      setBtnState("success");
      setTimeout(() => router.push("/overview"), 900);
    } catch (err: unknown) {
      setBtnState("idle");
      clearSessionCookie();
      if (err instanceof MfaRequiredError) {
        // Second step, not a failure: reveal the code field and say so.
        setMfaNeeded(true);
        setLoginError(mfaCode ? err.message : "");
        return;
      }
      setLoginError(err instanceof Error ? err.message : "Login failed");
    }
  }

  return (
    <motion.div
      id="LR"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.5 }}
    >
      {/* A stale tab after a dashboard roll lands HERE, so recovery belongs here too. */}
      <ChunkRecovery />
      {/* ══ LEFT PANEL ══════════════════════════════════════════════════════ */}
      <div id="LP" ref={lpRef}>
        <canvas id="LC" ref={canvasRef} />

        <div ref={scanlineRef} style={{
          position: "absolute", left: 0, width: "100%", height: 1,
          background: "rgba(59,130,246,0.12)", zIndex: 1, pointerEvents: "none",
        }} />

        <div id="LP-content">
          <motion.div id="shield" initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2, ...spring }}>
            <motion.div id="shield-icon" animate={{ boxShadow: ["0 0 12px rgba(59,130,246,.3)", "0 0 24px rgba(59,130,246,.5)", "0 0 12px rgba(59,130,246,.3)"] }} transition={{ duration: 3, repeat: Infinity }}>
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
                <path d="M12 2L3 6.5V12c0 5.5 3.8 10.7 9 12 5.2-1.3 9-6.5 9-12V6.5L12 2z"
                  stroke="#3b82f6" strokeWidth="1.5" fill="rgba(59,130,246,0.1)" />
                <path d="M8.5 12l2.5 2.5 4.5-4.5"
                  stroke="#60a5fa" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </motion.div>
            <div>
              <div id="brand-text"><span className="w">{PRODUCT_NAME}</span></div>
              <div id="brand-sub">Web Application Firewall</div>
            </div>
          </motion.div>

          <motion.div id="hero-title" initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.35, ...spring }}>
            Protect every<br />request. <span>Instantly.</span>
          </motion.div>
          <motion.div id="hero-desc" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.45, duration: 0.4 }}>
            Web Application Firewall with a Rust data plane, rule engine plus ML
            detection, eBPF kernel-level DDoS mitigation, and HTTP/3 with JA4 fingerprinting.
          </motion.div>

          {/* No figures here. This page used to show benchmark results (GoTestWAF
              detection, benign pass rate, p99) as if they were statistics — on the
              login page of a CUSTOMER's deployment, where they read as this
              installation's own numbers. They were also stale (99.5% while the
              measured composite had moved on). Benchmarks belong in the benchmark
              report; this page shows nothing it has not looked up. */}
          <motion.div id="feats" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.65 }}>
            {["eBPF / XDP","OWASP CRS v4","WASM Plugins","LLM Copilot",
              "HTTP/3 + JA4","Leader-elected HA","GraphQL / gRPC FW","Outbound DLP"].map(f => (
              <div key={f} className="feat-pill">{f}</div>
            ))}
          </motion.div>
        </div>

        <div id="LP-bottom">
          <div id="lp-footer">
            <div className="lp-dot" />
            <span>{PRODUCT_NAME} &nbsp;·&nbsp; v{PRODUCT_VERSION}</span>
          </div>
        </div>
      </div>

      {/* ══ RIGHT PANEL ═════════════════════════════════════════════════════ */}
      <div id="RP">
        <motion.div
          id="form-box"
          initial={{ opacity: 0, x: 30, scale: 0.96 }}
          animate={{ opacity: 1, x: 0, scale: 1 }}
          transition={{ delay: 0.15, ...spring }}
        >
          <div id="form-header">
            <div id="form-title">Welcome back</div>
            <div id="form-sub">Sign in to your {PRODUCT_NAME} dashboard</div>
          </div>

          {/* Auth tabs */}
          <div id="auth-tabs">
            {(["std", "sso", "api"] as AuthTab[]).map(t => (
              <div
                key={t}
                className={`atab${tab === t ? " active" : ""}`}
                onClick={() => setTab(t)}
              >
                {t === "std" ? "Password" : t === "sso" ? "SSO / OIDC" : "API Key"}
              </div>
            ))}
          </div>

          {/* Email */}
          <div className="fg">
            <label className="fl">Email address</label>
            <div className="fi-wrap">
              <input
                className="fi"
                type="email"
                placeholder="name@company.com"
                autoComplete="username"
                value={email}
                onChange={e => setEmail(e.target.value)}
              />
              <span className="fi-icon"><Icon name="mail" size={15} /></span>
            </div>
          </div>

          {/* Password */}
          <div className="fg">
            <label className="fl">Password</label>
            <div className="fi-wrap">
              <input
                className="fi"
                type={showPwd ? "text" : "password"}
                placeholder="Enter password"
                autoComplete="current-password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                onKeyDown={e => { if (e.key === "Enter") doLogin(); }}
              />
              <button className="fi-icon" onClick={() => setShowPwd(p => !p)}>
                <Icon name={showPwd ? "eye-off" : "eye"} size={16} />
              </button>
            </div>
          </div>

          {/* Second factor — shown only once the control plane has asked for it */}
          {mfaNeeded && (
            <motion.div className="fg" initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }}>
              <label className="fl">Authenticator code</label>
              <div className="fi-wrap">
                <input
                  className="fi"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  placeholder="6-digit code"
                  maxLength={8}
                  autoFocus
                  value={mfaCode}
                  onChange={e => setMfaCode(e.target.value.replace(/\s+/g, ""))}
                  onKeyDown={e => { if (e.key === "Enter") doLogin(); }}
                  style={{ letterSpacing: ".14em", fontFamily: "var(--font-mono)" }}
                />
                <span className="fi-icon"><Icon name="lock" size={15} /></span>
              </div>
              <div style={{ fontSize: 12, color: "var(--text3)", marginTop: 6 }}>
                Two-factor authentication is on for this account. Enter the code from your authenticator app.
              </div>
            </motion.div>
          )}

          {/* Remember + Forgot */}
          <div id="extras">
            <label className="remember">
              <input type="checkbox" defaultChecked />
              Remember this device
            </label>
            <a id="forgot" href="/forgot-password">Forgot password?</a>
          </div>

          {/* Error */}
          {loginError && (
            <motion.div className="login-error" initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }}>
              ⚠ {loginError}
            </motion.div>
          )}

          {/* Submit */}
          <motion.button
            id="sub-btn"
            className={btnState === "loading" ? "loading" : btnState === "success" ? "success" : ""}
            onClick={doLogin}
            disabled={btnState !== "idle"}
            whileHover={btnState === "idle" ? { scale: 1.02, y: -1 } : {}}
            whileTap={btnState === "idle" ? { scale: 0.98 } : {}}
          >
            {btnState === "idle"    && `Sign in to ${PRODUCT_NAME}`}
            {btnState === "loading" && <><span className="btn-spin" /> Authenticating...</>}
            {btnState === "success" && "✓ Access granted"}
          </motion.button>

          {/* Only shown when there is in fact something else to continue with. */}
            {ssoReady && (
              <div className="div-row">
            <div className="div-line" />
            <div className="div-text">or continue with</div>
            <div className="div-line" />
          </div>
            )}

          {/* Single sign-on. OIDC is the only SSO this control plane implements — there
              is no SAML and no LDAP anywhere in it. This button previously read
              "Sign in with SAML / LDAP" and called the password handler. */}
          {ssoReady && (
            <motion.button
              id="sso-btn"
              type="button"
              onClick={() => { window.location.href = "/api/v1/auth/oidc/login"; }}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <circle cx="12" cy="12" r="10" stroke="#94a3b8" strokeWidth="1.5" />
                <path d="M2 12h20M12 2a15.3 15.3 0 010 20M12 2a15.3 15.3 0 000 20"
                  stroke="#94a3b8" strokeWidth="1.5" fill="none" />
              </svg>
              Sign in with single sign-on
            </motion.button>
          )}

          <div id="form-footer">
            All authentication attempts are logged and audited
          </div>
        </motion.div>
      </div>
    </motion.div>
  );
}