"use client";
import type { ReactNode } from "react";
import { openModal, closeModal } from "@/components/ui/Modal";

export interface ConfirmOptions {
  title: string;
  /** What will happen, in the operator's terms — the consequence, not the mechanism. */
  body: ReactNode;
  confirmLabel: string;
  /** "danger" for actions that remove protection or service; "warn" otherwise. */
  tone?: "danger" | "warn";
}

/**
 * Ask before an action whose effect is hard to notice and easy to regret.
 *
 * Switching a site to Off, Blocking or Pause, deleting it, and blocking a country
 * on every site were each a single click with no question asked. One of them —
 * Off — once froze configuration for the whole fleet. Resolves true only on the
 * confirm button; ✕, the backdrop, Escape and Cancel all resolve false.
 */
export function confirmAction(o: ConfirmOptions): Promise<boolean> {
  return new Promise(resolve => {
    let settled = false;
    const done = (v: boolean) => { if (!settled) { settled = true; resolve(v); } };
    const color = o.tone === "danger" ? "var(--red)" : "var(--amber)";
    openModal({
      title: o.title,
      body: <div style={{ fontSize: 15, lineHeight: 1.6, color: "var(--text2)" }}>{o.body}</div>,
      footer: (
        <div style={{ display: "flex", gap: 10, justifyContent: "flex-end" }}>
          <button className="btn bg-btn" autoFocus onClick={() => { done(false); closeModal(); }}>Cancel</button>
          <button className="btn" style={{ background: color, color: "#fff", borderColor: color }}
            onClick={() => { done(true); closeModal(); }}>{o.confirmLabel}</button>
        </div>
      ),
      onClose: () => done(false),
    });
  });
}
