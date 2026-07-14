// Real AI Copilot backend client.
//
// Every answer is generated live by the model behind the enlight LLM gateway
// (DeepSeek-R1). There are deliberately NO canned responses and NO hard-coded
// statistics in this module: if the gateway is unreachable or unconfigured the
// call throws and the UI surfaces the error verbatim, rather than inventing a
// plausible-looking reply or fabricated metrics.

export const COPILOT_MODEL = "deepseek-r1:8b";
export const COPILOT_ENDPOINT = "https://ai.enlight.dev/api/chat/completions";

const SYSTEM_PROMPT =
  "You are Sentinel AI Copilot, an elite cybersecurity assistant integrated into an enterprise Web Application Firewall (WAF). Your job is to analyze SQLi, XSS, and DDoS threats, explain logs, and help write WAF rules. Keep answers concise, technical, and accurate. Do not hallucinate.";

// Opening message. Note: the model name below is the real one wired above — no
// throughput / detection numbers are quoted because none are measured here.
export const GREET =
  "Hello! I'm **Sentinel AI Copilot**, powered by DeepSeek R1.\n\nI can help:\n• 🔍 Explain security alerts\n• 📝 Generate SRL WAF rules\n• 🛡️ Create CVE virtual patches\n• 🐛 Debug false positives\n• 📊 Security reports\n\nWhat would you like to know?";

export interface CopilotTurn {
  role: "user" | "assistant";
  content: string;
}

/**
 * Send the running conversation plus a new user message to the live model and
 * return its reply. Throws on transport or API errors so callers can show the
 * real failure instead of a fabricated answer.
 */
export async function askCopilot(history: CopilotTurn[], text: string): Promise<string> {
  const key = process.env.NEXT_PUBLIC_ENLIGHT_API_KEY;
  if (!key) {
    throw new Error("Copilot is not configured — NEXT_PUBLIC_ENLIGHT_API_KEY is unset.");
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
    `⚠️ Unexpected response format: ${JSON.stringify(data).slice(0, 300)}`
  );
}
