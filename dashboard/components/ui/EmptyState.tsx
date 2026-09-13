"use client";
import type { ReactNode } from "react";
import Icon, { type IconName } from "@/components/ui/Icon";

/**
 * One empty state for every list in the console: what is empty, why that is
 * fine (or not), and the ONE thing to do next. Pages used to render a lone
 * "No X found" in mono grey; the Plugins page set the pattern this follows.
 */
export default function EmptyState({
  icon = "info", title, hint, action, compact = false,
}: {
  icon?: IconName;
  title: string;
  hint?: ReactNode;
  /** Primary next step. `href` renders a link, `onClick` a button. */
  action?: { label: string; onClick?: () => void; href?: string };
  compact?: boolean;
}) {
  return (
    <div role="status" style={{
      padding: compact ? "18px 16px" : "36px 24px", textAlign: "center",
      display: "flex", flexDirection: "column", alignItems: "center", gap: 8,
    }}>
      <Icon name={icon} size={compact ? 22 : 30} strokeWidth={1.5} style={{ color: "var(--text3)" }} />
      <div style={{ fontSize: compact ? 13 : 15, fontWeight: 700, color: "var(--text2)", fontFamily: "var(--font-display)", letterSpacing: .3 }}>{title}</div>
      {hint && <div style={{ fontSize: 13, color: "var(--text3)", fontFamily: "var(--font-mono)", maxWidth: 520, lineHeight: 1.5 }}>{hint}</div>}
      {action && (action.href
        ? <a className="btn bp btn-sm" href={action.href} style={{ marginTop: 6 }}>{action.label}</a>
        : <button className="btn bp btn-sm" onClick={action.onClick} style={{ marginTop: 6 }}>{action.label}</button>)}
    </div>
  );
}
