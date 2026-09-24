// Client-side AI Copilot facade.
//
// Every answer is generated live by the model behind the enlight LLM gateway.
// Which model that is, and whether a key is set at all, is known only to the
// console server (lib/copilotServer.ts) and reported by GET /api/copilot — this
// module does not repeat it. There are deliberately NO canned responses and NO hard-coded
// statistics in this module: if the gateway is unreachable or unconfigured the
// call throws and the UI surfaces the error verbatim, rather than inventing a
// plausible-looking reply or fabricated metrics.
//
// SECURITY: this file runs in the browser, so it holds no credential and knows
// no external endpoint. It posts to our own /api/copilot, which authenticates
// the caller and then talks to the gateway server-side. Do not reintroduce a
// NEXT_PUBLIC_* API key here — Next.js inlines those into the client bundle,
// which would serve the gateway credential to every browser.

import { PRODUCT_NAME } from "@/lib/version";

/** What GET /api/copilot said — see components/copilot/CopilotStatus.tsx. */
export type CopilotStatus =
  | { kind: "checking" }
  | { kind: "ready"; model: string }
  | { kind: "unconfigured" }
  | { kind: "unreachable" };

const CAPABILITIES =
  "I can help:\n• Explain security alerts\n• Generate SRL WAF rules\n• Create CVE virtual patches\n• Debug false positives\n• Security reports";

/**
 * The opening message, for the status the console server actually reported.
 *
 * It was a constant: "powered by DeepSeek R1 … I can help" on every console,
 * including the ones with no model key, where every question then failed. The
 * status line under it already said "Not configured"; the greeting contradicted
 * it. Now the greeting names a model only when the server named one, and offers
 * help only when there is a model to give it. No throughput or detection numbers
 * are quoted in any variant, because none are measured here.
 */
export function greetingFor(s: CopilotStatus): string {
  switch (s.kind) {
    case "ready":
      return `Hello! I'm **${PRODUCT_NAME} AI Copilot**${s.model ? `, running on \`${s.model}\`` : ""}.\n\n${CAPABILITIES}\n\nWhat would you like to know?`;
    case "unconfigured":
      return `**${PRODUCT_NAME} AI Copilot is not configured on this console.**\n\nNo model key is set on the console server, so questions cannot be answered yet. An administrator enables it by setting \`ENLIGHT_API_KEY\` for the dashboard service and restarting that service.`;
    case "unreachable":
      return `**${PRODUCT_NAME} AI Copilot is unavailable.**\n\nThe copilot service on the console server did not answer, so questions will fail until it does. Reload the page to check again.`;
    case "checking":
      return "Checking whether the copilot is configured…";
  }
}

export interface CopilotTurn {
  role: "user" | "assistant";
  content: string;
}

/**
 * Send the running conversation plus a new user message to the model (via our
 * server-side proxy) and return its reply. Throws on transport or API errors so
 * callers can show the real failure instead of a fabricated answer.
 */
export async function askCopilot(history: CopilotTurn[], text: string): Promise<string> {
  const res = await fetch("/api/copilot", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ history, text }),
  });

  const data: unknown = await res.json().catch(() => ({}));
  const d = data as { reply?: string; error?: string };

  if (!res.ok) {
    throw new Error(d.error ?? `Copilot request failed (${res.status})`);
  }
  if (typeof d.reply !== "string") {
    throw new Error(`⚠ Unexpected response format: ${JSON.stringify(data).slice(0, 300)}`);
  }
  return d.reply;
}
