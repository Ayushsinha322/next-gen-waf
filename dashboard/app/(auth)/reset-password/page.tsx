"use client";
import { Suspense, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { motion } from "framer-motion";
import { api } from "@/lib/api";
import { logout } from "@/lib/auth";
import Icon from "@/components/ui/Icon";

/** Mirrors the server's rule (control-plane validatePassword). Checked here only
 *  to give immediate feedback — the server is the authority and re-checks. */
function localPasswordProblem(pw: string): string {
  if (pw.length < 12) return "Use at least 12 characters.";
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter(re => re.test(pw)).length;
  if (classes < 2) return "Mix at least two of: lower case, upper case, digits, symbols.";
  return "";
}

function ResetPasswordForm() {
  const router = useRouter();
  const params = useSearchParams();
  const token = params.get("token") ?? "";

  const [pw, setPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);

  const localProblem = pw ? localPasswordProblem(pw) : "";
  const mismatch = confirm.length > 0 && pw !== confirm;
  const canSubmit = !!token && !!pw && !localProblem && !mismatch && !busy;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError("");
    try {
      await api.auth.resetPassword(token, pw);
      // The reset invalidated every session for this account, so any stale
      // tokens in this browser are now dead. Clearing them stops the app from
      // trying to use one and bouncing the user through a confusing 401.
      logout();
      setDone(true);
      setTimeout(() => router.push("/login"), 2600);
    } catch (err) {
      setError(err instanceof Error ? err.message
        : "This reset link is invalid or has expired — request a new one.");
    } finally {
      setBusy(false);
    }
  }

  if (!token) {
    return (
      <>
        <div id="form-header">
          <div id="form-title">Link is incomplete</div>
          <div id="form-sub">
            This page needs a reset token, and the address you opened has none.
            Use the full link from your email, or request a new one.
          </div>
        </div>
        <Link href="/forgot-password" style={backLink}>Request a new link →</Link>
      </>
    );
  }

  if (done) {
    return (
      <>
        <div id="form-header">
          <div id="form-title">Password updated</div>
          <div id="form-sub">
            All existing sessions for your account were signed out. Taking you to
            the sign-in page…
          </div>
        </div>
        <Link href="/login" style={backLink}>Sign in now →</Link>
      </>
    );
  }

  return (
    <>
      <div id="form-header">
        <div id="form-title">Set a new password</div>
        <div id="form-sub">
          Choose a password of at least 12 characters. Signing in everywhere else
          will stop working once you save.
        </div>
      </div>

      <form onSubmit={submit} style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        <div className="fg">
          <label className="fl" htmlFor="rp-pw">New password</label>
          <div className="fi-wrap">
            <input
              id="rp-pw"
              className="fi"
              type={show ? "text" : "password"}
              required
              autoFocus
              autoComplete="new-password"
              placeholder="At least 12 characters"
              value={pw}
              onChange={e => setPw(e.target.value)}
            />
            <button type="button" className="fi-icon" onClick={() => setShow(s => !s)}
              aria-label={show ? "Hide password" : "Show password"}>
              <Icon name={show ? "eye-off" : "eye"} size={16} />
            </button>
          </div>
          {localProblem && <div style={inlineHint}>{localProblem}</div>}
        </div>

        <div className="fg">
          <label className="fl" htmlFor="rp-confirm">Confirm new password</label>
          <div className="fi-wrap">
            <input
              id="rp-confirm"
              className="fi"
              type={show ? "text" : "password"}
              required
              autoComplete="new-password"
              placeholder="Type it again"
              value={confirm}
              onChange={e => setConfirm(e.target.value)}
            />
          </div>
          {mismatch && <div style={inlineHint}>Both entries must match.</div>}
        </div>

        {error && (
          <motion.div className="login-error" initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }}>
            {error}
          </motion.div>
        )}

        <button id="sub-btn" type="submit" disabled={!canSubmit}>
          {busy ? "Saving…" : "Set new password"}
        </button>
      </form>

      <Link href="/login" style={backLink}>← Back to sign in</Link>
    </>
  );
}

export default function ResetPasswordPage() {
  return (
    <div style={wrap}>
      <motion.div id="form-box" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}>
        {/* useSearchParams needs a Suspense boundary in the app router. */}
        <Suspense fallback={<div id="form-sub">Loading…</div>}>
          <ResetPasswordForm />
        </Suspense>
      </motion.div>
    </div>
  );
}

const wrap: React.CSSProperties = {
  minHeight: "100vh", display: "flex", alignItems: "center",
  justifyContent: "center", padding: "40px 24px", background: "var(--bg)",
};
const inlineHint: React.CSSProperties = {
  fontSize: 13, color: "var(--text3)", fontFamily: "var(--font-sans)",
};
const backLink: React.CSSProperties = {
  color: "var(--cyan)", fontSize: 14, fontFamily: "var(--font-sans)", textAlign: "center",
};
