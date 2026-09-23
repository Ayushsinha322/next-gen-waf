/**
 * Helpers for the live access stream (the data plane's per-request NDJSON
 * record, relayed over SSE).
 */

/** What the data plane decided — its own `action` field, never a guess. */
export type Verdict = "BLOCKED" | "WOULD BLOCK" | "ERROR" | "ALLOWED";

/**
 * The Traffic page used to label a request BLOCKED when `status === 403 ||
 * score >= 5`, so a request that scored 5 in learning mode — and was answered
 * 200 by the application — showed as BLOCKED, while the Logs page called the
 * same request PASS. The data plane writes the decision it made (BLOCK /
 * DETECT / ERROR / PASS); this only translates it. A record from a data plane
 * older than that field falls back to the one thing that is certain: a 403.
 */
export function verdictOf(action: unknown, status: number): Verdict {
  switch (String(action ?? "").toUpperCase()) {
    case "BLOCK":  return "BLOCKED";
    case "DETECT": return "WOULD BLOCK";
    case "ERROR":  return "ERROR";
    case "PASS":   return "ALLOWED";
    default:       return status === 403 ? "BLOCKED" : "ALLOWED";
  }
}

/**
 * HH:MM:SS in the viewer's local time, as Events and Logs show it. `.slice(-8)`
 * on the record's ISO timestamp ("2026-09-23T08:36:40Z") produced "8:36:40Z" —
 * the hour's first digit cut off, and UTC while every other page is local.
 */
export function clockTime(ts: unknown, now: Date = new Date()): string {
  const d = typeof ts === "string" && ts ? new Date(ts) : now;
  const t = Number.isNaN(d.getTime()) ? now : d;
  return t.toLocaleTimeString("en-GB", { hour12: false });
}
