import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { generateReply, copilotConfigured, COPILOT_MODEL, type CopilotTurn } from "@/lib/copilotServer";

// Cap the forwarded conversation so a client cannot drive unbounded spend or
// blow past the gateway's context window.
const MAX_TURNS = 24;
const MAX_CHARS = 8000;

function isTurn(v: unknown): v is CopilotTurn {
  if (typeof v !== "object" || v === null) return false;
  const t = v as { role?: unknown; content?: unknown };
  return (t.role === "user" || t.role === "assistant") && typeof t.content === "string";
}

/**
 * Server-side proxy for the Copilot gateway.
 *
 * The gateway credential lives here (ENLIGHT_API_KEY) and never reaches the
 * browser — see lib/copilotServer.ts for why.
 *
 * This route authenticates on its own rather than relying on middleware.ts:
 * that middleware treats every /api/ path as public because it fronts the
 * control-plane REST proxy, so without the check below this endpoint would be an
 * unauthenticated open relay to a paid LLM gateway.
 */
/** Status for the copilot header: configured or not, and which model. Same auth as POST. */
export async function GET() {
  const token = cookies().get("sentinel_token")?.value;
  if (!token || token.split(".").length !== 3) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  return NextResponse.json({ configured: copilotConfigured(), model: COPILOT_MODEL });
}

export async function POST(req: Request) {
  const token = cookies().get("sentinel_token")?.value;
  if (!token || token.split(".").length !== 3) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }

  let parsed: unknown;
  try {
    parsed = await req.json();
  } catch {
    return NextResponse.json({ error: "malformed request body" }, { status: 400 });
  }

  const body = parsed as { history?: unknown; text?: unknown };
  if (typeof body.text !== "string" || body.text.trim() === "") {
    return NextResponse.json({ error: "`text` is required" }, { status: 400 });
  }
  if (body.text.length > MAX_CHARS) {
    return NextResponse.json({ error: "`text` too long" }, { status: 413 });
  }
  const history = Array.isArray(body.history) ? body.history.filter(isTurn).slice(-MAX_TURNS) : [];

  try {
    const reply = await generateReply(history, body.text);
    return NextResponse.json({ reply });
  } catch (err) {
    // Surface the real failure — the UI shows it verbatim rather than inventing
    // a plausible answer. The key is never interpolated into these messages.
    return NextResponse.json({ error: (err as Error).message }, { status: 502 });
  }
}
