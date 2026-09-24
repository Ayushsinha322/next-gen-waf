"use client";
import { useEffect, useState } from "react";
import type { CopilotStatus } from "@/lib/copilot";

type State = CopilotStatus;

/**
 * The copilot's real status. The header used to be the literal text "Online ·
 * Ready to assist" (and "Online · DeepSeek R1" on the floating panel): with no
 * key configured every question failed, and from the management console the
 * request never reached the copilot at all, under a green dot either way.
 */
export function useCopilotStatus(): State {
  const [s, setS] = useState<State>({ kind: "checking" });
  useEffect(() => {
    let cancelled = false;
    fetch("/api/copilot", { method: "GET", credentials: "same-origin" })
      .then(async r => {
        if (!r.ok) throw new Error(String(r.status));
        const d = (await r.json()) as { configured?: boolean; model?: string };
        if (!cancelled) setS(d.configured ? { kind: "ready", model: d.model ?? "" } : { kind: "unconfigured" });
      })
      .catch(() => { if (!cancelled) setS({ kind: "unreachable" }); });
    return () => { cancelled = true; };
  }, []);
  return s;
}

/** Takes the status from the caller, whose greeting and model badge read the same one. */
export function CopilotStatusLine({ status: s, fontSize = 11 }: { status: State; fontSize?: number }) {
  const [color, text] =
    s.kind === "ready"        ? ["var(--green)", `Online · ${s.model}`] :
    s.kind === "unconfigured" ? ["var(--amber)", "Not configured — no model key is set on the console server"] :
    s.kind === "unreachable"  ? ["var(--red)",   "Unavailable — the copilot service did not answer"] :
                                ["var(--text3)", "Checking…"];
  return (
    <div style={{ fontFamily: "var(--font-mono)", fontSize, color: "#9B60E0", display: "flex", alignItems: "center", gap: 5, marginTop: 2 }}>
      <span style={{ width: 5, height: 5, borderRadius: "50%", background: color, boxShadow: `0 0 5px ${color}`, display: "inline-block", flexShrink: 0 }} />
      {text}
    </div>
  );
}
