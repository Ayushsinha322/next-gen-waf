// Copilot hand-off: open the AI Copilot WITH the thing the operator was looking
// at, instead of an empty chat.
//
// The copilot's value is in the row — "explain this alert", "draft an exclusion
// for this false positive", "write a virtual patch for this CVE" — so pages push
// a small context object here and navigate; the copilot page picks it up, shows
// what it loaded, and sends the first prompt itself. The hand-off rides in
// sessionStorage (one tab, gone on close) rather than the URL so a full alert
// record never lands in browser history or a proxy log.
//
// Recent hand-offs are kept per browser (localStorage) and replace the fake
// "conversation history" the copilot page used to render.

export interface CopilotHandoff {
  /** Short label shown as the loaded-context chip and in the recent list. */
  title: string;
  /** What to ask. The context below is appended as JSON. */
  prompt: string;
  /** The record the question is about — an alert, an event, a rule. */
  context?: unknown;
  /** Where it came from, for the chip ("alerts", "threat-search", "rules"). */
  source: string;
  at: number;
}

const HANDOFF_KEY = "sentinel.copilot.handoff";
const RECENT_KEY = "sentinel.copilot.recent";
const RECENT_MAX = 12;
/** Cap the JSON we quote into a prompt; the server caps text at 8000 chars. */
const CONTEXT_CHARS = 5000;

type Router = { push: (href: string) => void };

/** Store the hand-off, remember it in the recent list, and go to the copilot. */
export function openCopilotWith(router: Router, h: Omit<CopilotHandoff, "at">): void {
  const full: CopilotHandoff = { ...h, at: Date.now() };
  try { sessionStorage.setItem(HANDOFF_KEY, JSON.stringify(full)); } catch { /* private mode: still navigate */ }
  rememberRecent(full);
  router.push("/copilot");
}

/** Consume the pending hand-off (once). */
export function takeCopilotHandoff(): CopilotHandoff | null {
  try {
    const raw = sessionStorage.getItem(HANDOFF_KEY);
    if (!raw) return null;
    sessionStorage.removeItem(HANDOFF_KEY);
    const h = JSON.parse(raw) as CopilotHandoff;
    return typeof h?.prompt === "string" && typeof h?.title === "string" ? h : null;
  } catch { return null; }
}

export function listRecentHandoffs(): CopilotHandoff[] {
  try {
    const raw = localStorage.getItem(RECENT_KEY);
    const list = raw ? (JSON.parse(raw) as CopilotHandoff[]) : [];
    return Array.isArray(list) ? list.filter(x => typeof x?.title === "string") : [];
  } catch { return []; }
}

export function rememberRecent(h: CopilotHandoff): void {
  try {
    const list = listRecentHandoffs().filter(x => x.title !== h.title);
    list.unshift(h);
    localStorage.setItem(RECENT_KEY, JSON.stringify(list.slice(0, RECENT_MAX)));
  } catch { /* ignore */ }
}

export function clearRecentHandoffs(): void {
  try { localStorage.removeItem(RECENT_KEY); } catch { /* ignore */ }
}

/** The text actually sent to the model: the question plus the record as JSON. */
export function buildCopilotMessage(h: Pick<CopilotHandoff, "prompt" | "context">): string {
  if (h.context === undefined || h.context === null) return h.prompt;
  let json: string;
  try { json = JSON.stringify(h.context, null, 1); } catch { json = String(h.context); }
  if (json.length > CONTEXT_CHARS) json = json.slice(0, CONTEXT_CHARS) + "\n… (truncated)";
  return `${h.prompt}\n\nContext (JSON):\n\`\`\`json\n${json}\n\`\`\``;
}

// ── Prompt builders used by the pages ────────────────────────────────────────

export function explainAlertPrompt(alert: { kind: string; severity: string; summary: string; details?: unknown; created_at?: string }): Omit<CopilotHandoff, "at"> {
  return {
    source: "alerts",
    title: `Explain alert: ${alert.summary}`.slice(0, 80),
    prompt:
      `Explain this WAF alert to an operator: what happened, how confident we should be that it is a real attack ` +
      `rather than a false positive, what to check next, and whether to block the source. Be concise and concrete.`,
    context: { kind: alert.kind, severity: alert.severity, summary: alert.summary, created_at: alert.created_at, details: alert.details },
  };
}

export function explainEventPrompt(ev: Record<string, unknown>): Omit<CopilotHandoff, "at"> {
  const rule = typeof ev.rule === "string" ? ev.rule : "";
  const path = typeof ev.path === "string" ? ev.path : "";
  return {
    source: "threat-search",
    title: `Explain event ${rule ? `rule ${rule} ` : ""}on ${path || "request"}`.slice(0, 80),
    prompt:
      `Explain this WAF detection: which rule fired and why, whether the matched text looks like a real attack or ` +
      `a false positive, and what an operator should do. Be concise.`,
    context: ev,
  };
}

export function draftExclusionPrompt(ev: Record<string, unknown>): Omit<CopilotHandoff, "at"> {
  const rule = typeof ev.rule === "string" ? ev.rule : "";
  const path = typeof ev.path === "string" ? ev.path : "";
  return {
    source: "threat-search",
    title: `Draft exclusion for rule ${rule || "?"} on ${path || "path"}`.slice(0, 80),
    prompt:
      `This detection is a suspected FALSE POSITIVE. Draft the narrowest rule exclusion that stops it without ` +
      `disabling the rule globally: prefer excluding only the matched target (e.g. one argument name) for this ` +
      `path. Give it as a site rule_exclusion entry ({rule_id, exclude_targets} or {rule_id, disable}) and say ` +
      `what coverage is lost.`,
    context: ev,
  };
}

export function virtualPatchPrompt(cve: string, note?: string): Omit<CopilotHandoff, "at"> {
  return {
    source: "rules",
    title: `Virtual patch for ${cve}`,
    prompt:
      `Write a virtual patch for ${cve} as a Sentinel WAF custom rule in ModSecurity/SecRule syntax (the engine ` +
      `compiles CRS-style rules): match only the vulnerable request shape, block, and set a unique id in the ` +
      `9000000-9999999 range. Explain what it matches and what it deliberately does not.` +
      (note ? `\n\nNotes from the operator: ${note}` : ""),
  };
}
