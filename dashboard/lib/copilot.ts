// Client-side AI Copilot facade.
//
// Every answer is generated live by the model behind the enlight LLM gateway
// (DeepSeek-R1). There are deliberately NO canned responses and NO hard-coded
// statistics in this module: if the gateway is unreachable or unconfigured the
// call throws and the UI surfaces the error verbatim, rather than inventing a
// plausible-looking reply or fabricated metrics.
//
// SECURITY: this file runs in the browser, so it holds no credential and knows
// no external endpoint. It posts to our own /api/copilot, which authenticates
// the caller and then talks to the gateway server-side. Do not reintroduce a
// NEXT_PUBLIC_* API key here — Next.js inlines those into the client bundle,
// which would serve the gateway credential to every browser.

export const COPILOT_MODEL = "deepseek-r1:8b";

// Opening message. Note: the model name below is the real one wired above — no
// throughput / detection numbers are quoted because none are measured here.
export const GREET =
  "Hello! I'm **Sentinel AI Copilot**, powered by DeepSeek R1.\n\nI can help:\n• Explain security alerts\n• Generate SRL WAF rules\n• Create CVE virtual patches\n• Debug false positives\n• Security reports\n\nWhat would you like to know?";

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
