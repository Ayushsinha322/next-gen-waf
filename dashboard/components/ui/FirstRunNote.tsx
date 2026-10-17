"use client";
import { useEffect, useState, type ReactNode } from "react";

/**
 * A one-time explainer at the top of a page: what this screen is for, and the
 * one thing that is not obvious about it.
 *
 * The console exposes far more than the products we are measured against, and
 * a first-time operator meeting a dense screen has no way to tell which of the
 * numbers on it are configuration and which are live. SafeLine puts a
 * dismissible banner on its non-obvious screens; we had none anywhere.
 *
 * Dismissal is per-browser, by design. This is orientation, not a setting, so
 * it does not belong in the tenant's configuration — and a colleague opening
 * the console on their own machine should get the explanation too.
 *
 * `id` is the storage key and must be stable: changing it re-shows the banner
 * to everyone who had already dismissed it. Change it deliberately when the
 * text changes enough that a returning operator should read it again.
 */
export default function FirstRunNote({
  id, title, children, icon = "ⓘ",
}: {
  id: string;
  title: string;
  children: ReactNode;
  icon?: ReactNode;
}) {
  const key = `sentinel_firstrun_${id}`;
  // Start hidden and reveal after reading storage. The other order flashes a
  // banner at every operator who dismissed it months ago, on every page load.
  const [show, setShow] = useState(false);

  useEffect(() => {
    try {
      if (localStorage.getItem(key) !== "dismissed") setShow(true);
    } catch {
      // Private mode, or site data blocked. Showing the explainer is the safe
      // side of that failure — it is one line of text, not a modal.
      setShow(true);
    }
  }, [key]);

  if (!show) return null;

  function dismiss(remember: boolean) {
    if (remember) {
      try { localStorage.setItem(key, "dismissed"); } catch { /* nothing to do */ }
    }
    setShow(false);
  }

  return (
    <div role="note" style={{
      display: "flex", gap: 12, alignItems: "flex-start",
      padding: "12px 14px", marginBottom: 14,
      border: "1px solid var(--cyan-ring)", background: "var(--cyan-dim)",
      borderRadius: 10,
    }}>
      <span aria-hidden style={{ fontSize: 15, lineHeight: 1.4, opacity: .9 }}>{icon}</span>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{
          fontSize: 13.5, fontWeight: 700, color: "var(--text2)",
          fontFamily: "var(--font-display)", letterSpacing: "-0.005em", marginBottom: 3,
        }}>{title}</div>
        <div style={{ fontSize: 13, color: "var(--text3)", lineHeight: 1.55 }}>{children}</div>
      </div>
      <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
        <button className="btn btn-sm" onClick={() => dismiss(true)}
          title="Do not show this on this screen again, in this browser">
          Don&apos;t show again
        </button>
        <button className="btn btn-sm" onClick={() => dismiss(false)} aria-label="Dismiss" title="Hide until next visit">
          ✕
        </button>
      </div>
    </div>
  );
}
