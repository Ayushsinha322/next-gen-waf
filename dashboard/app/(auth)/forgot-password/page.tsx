"use client";
import { useState } from "react";
import Link from "next/link";
import { motion } from "framer-motion";
import { api } from "@/lib/api";

/**
 * Request a password reset link.
 *
 * The success screen is shown for EVERY submitted address, including ones with
 * no account and including a backend failure. That is not a UI shortcut — the
 * API deliberately returns one response for all of those cases so this endpoint
 * cannot be used to discover which email addresses are registered, and branching
 * here on anything would reintroduce exactly the oracle the backend removes.
 */
export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [sent, setSent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      await api.auth.forgotPassword(email.trim());
      setSent(true);
    } catch (err) {
      // The API answers 200 for every outcome it can control — unknown address
      // included — so anything reaching here is a transport or server fault, not
      // a statement about the account. Show what the server said when it said
      // something, and never imply whether the address exists.
      setError(err instanceof Error && err.message
        ? err.message
        : "Could not reach the WAF console. Check your connection and try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={wrap}>
      <motion.div id="form-box" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}>

        {sent ? (
          <>
            <div id="form-header">
              <div id="form-title">Check your email</div>
              <div id="form-sub">
                If <strong style={{ color: "var(--text)" }}>{email.trim()}</strong> has an account,
                a password reset link is on its way. The link works once and expires in 30 minutes.
              </div>
            </div>
            <div style={hint}>
              Nothing arrived? Check the spam folder, then request another link. If your
              deployment has no mail relay configured yet, ask your WAF administrator —
              they can send you a reset link from Settings → Users.
            </div>
            <Link href="/login" style={backLink}>← Back to sign in</Link>
          </>
        ) : (
          <>
            <div id="form-header">
              <div id="form-title">Reset your password</div>
              <div id="form-sub">
                Enter the email address for your console account and we&apos;ll send you a
                link to set a new password.
              </div>
            </div>

            <form onSubmit={submit} style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              <div className="fg">
                <label className="fl" htmlFor="fp-email">Email address</label>
                <div className="fi-wrap">
                  <input
                    id="fp-email"
                    className="fi"
                    type="email"
                    required
                    autoFocus
                    autoComplete="email"
                    placeholder="you@example.com"
                    value={email}
                    onChange={e => setEmail(e.target.value)}
                  />
                </div>
              </div>

              {error && (
                <motion.div className="login-error" initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }}>
                  {error}
                </motion.div>
              )}

              <button id="sub-btn" type="submit" disabled={busy || !email.trim()}>
                {busy ? "Sending…" : "Send reset link"}
              </button>
            </form>

            <Link href="/login" style={backLink}>← Back to sign in</Link>
          </>
        )}
      </motion.div>
    </div>
  );
}

const wrap: React.CSSProperties = {
  minHeight: "100vh", display: "flex", alignItems: "center",
  justifyContent: "center", padding: "40px 24px", background: "var(--bg)",
};
const hint: React.CSSProperties = {
  background: "var(--accent-tint)", border: "1px solid var(--card-bd)",
  borderRadius: "var(--r2)", padding: "12px 14px",
  fontSize: 14, lineHeight: 1.6, color: "var(--text2)", fontFamily: "var(--font-sans)",
};
const backLink: React.CSSProperties = {
  color: "var(--cyan)", fontSize: 14, fontFamily: "var(--font-sans)", textAlign: "center",
};
