// SERVER-ONLY Copilot backend client.
//
// This module must never be imported from a Client Component. It reads
// ENLIGHT_API_KEY, which is deliberately NOT prefixed NEXT_PUBLIC_ so that
// Next.js cannot inline it into the browser bundle.
//
// History: the gateway call used to live in lib/copilot.ts and read
// NEXT_PUBLIC_ENLIGHT_API_KEY from a Client Component. Next.js substitutes
// NEXT_PUBLIC_* variables into the client JavaScript at build time, so any
// production build with the copilot actually enabled would have served the
// gateway credential to every browser that loaded the dashboard — readable by
// any logged-in user, and by anyone who could fetch the static chunk. The call
// now runs server-side and the browser talks only to our own /api/copilot.
//
// Keeping it server-side also means customer request data quoted into a prompt
// (log lines, alert details) leaves from the server, where egress is
// observable and controllable, rather than from each operator's browser.

import { PRODUCT_NAME } from "@/lib/version";

export const COPILOT_MODEL = "deepseek-r1:8b";
export const COPILOT_ENDPOINT = "https://ai.enlight.dev/api/chat/completions";

const SYSTEM_PROMPT =
  `You are ${PRODUCT_NAME} AI Copilot, an elite cybersecurity assistant integrated into an enterprise Web Application Firewall (WAF). Your job is to analyze SQLi, XSS, and DDoS threats, explain logs, and help write WAF rules. Keep answers concise, technical, and accurate. Do not hallucinate.`;

export interface CopilotTurn {
  role: "user" | "assistant";
  content: string;
}

/**
 * Send the running conversation plus a new user message to the live model and
 * return its reply. Throws on transport or API errors so callers can surface the
 * real failure instead of a fabricated answer.
 */
export async function generateReply(history: CopilotTurn[], text: string): Promise<string> {
  const key = process.env.ENLIGHT_API_KEY;
  if (!key) {
    throw new Error("Copilot is not configured — ENLIGHT_API_KEY is unset.");
  }

  const res = await fetch(COPILOT_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${key}` },
    body: JSON.stringify({
      model: COPILOT_MODEL,
      messages: [{ role: "system", content: SYSTEM_PROMPT }, ...history, { role: "user", content: text }],
    }),
  });

  const data: unknown = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = data as { error?: { message?: string } };
    throw new Error(`API ${res.status}: ${err.error?.message ?? JSON.stringify(data)}`);
  }

  const d = data as {
    choices?: { message?: { content?: string } }[];
    response?: string;
    content?: string;
    message?: string;
  };
  return (
    d.choices?.[0]?.message?.content ??
    d.response ??
    d.content ??
    d.message ??
    `⚠ Unexpected response format: ${JSON.stringify(data).slice(0, 300)}`
  );
}
