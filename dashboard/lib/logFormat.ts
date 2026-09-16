/**
 * Line formatters for the Logs page, one per log file.
 *
 * Lifted out of the page so they can be tested. The access-log line gained
 * `rule=` and `reason=` on 2026-09-16: five modules (GraphQL, gRPC, JWT,
 * threat intel, request smuggling) block with no rule match, and until the
 * data plane started writing those two fields (`access_record` in the proxy)
 * a 403 from any of them rendered here as `[BLOCK] … 403` and nothing more.
 * Both are appended only when present, so older rows and passed requests
 * render exactly as before.
 */
export type LogKind = "access" | "waf" | "error" | "audit";

/** Path with its query string rejoined, for display only. */
export function withQuery(r: Record<string, unknown>): string {
  const path = String(r.path ?? "");
  const q = String(r.query ?? "");
  return q ? `${path}?${q}` : path;
}

/** The WAF's own verdict for a row.
 *
 * Always prefer the `action` the data plane emits (proxy log_request →
 * ctx.decision). The viewer used to infer the verdict from the HTTP status,
 * which is wrong in both directions and misrepresents what the WAF did: an
 * origin 404 or 500 rendered as BLOCK when the WAF allowed the request through,
 * and a Challenge or rate-limit rendered as PASS. Status is only a fallback for
 * older rows that predate the field. */
export function verdict(r: Record<string, unknown>): "BLOCK" | "PASS" | "CHALLENGE" | "LIMIT" {
  const a = String(r.action ?? r.decision ?? "").toUpperCase();
  if (a.startsWith("BLOCK") || a === "DENY") return "BLOCK";
  if (a.startsWith("CHALLENG")) return "CHALLENGE";
  if (a.startsWith("LIMIT") || a.startsWith("RATE")) return "LIMIT";
  if (a.startsWith("ALLOW") || a === "PASS" || a === "LOG") return "PASS";
  return Number(r.status ?? 200) === 403 ? "BLOCK" : "PASS";
}

export function fmt(kind: LogKind, r: Record<string, unknown>): string {
  const ts = String(r.ts ?? "");
  switch (kind) {
    // The query string is appended to the path here, not shown as a separate
    // field: on this page a reader wants the URL as requested. It is stored
    // separately (so per-path aggregation keeps its cardinality) and rejoined
    // only for display. Without it a blocked `/rest/products/search` gave no
    // hint of the `?q=1' UNION SELECT…` that made it an attack.
    case "access":
      return `${ts} [${verdict(r)}] ${r.ip} ${r.method} ${withQuery(r)} ${r.status} proto=${r.protocol ?? "-"} latency=${r.latency}ms waf=${r.waf_ms ?? "-"}ms bytes=${r.bytes} site=${r.site} ua="${r.ua ?? "-"}"${r.referer && r.referer !== "-" ? ` referer="${r.referer}"` : ""}${r.rule ? ` rule=${r.rule}` : ""}${r.reason ? ` reason="${r.reason}"` : ""}`;
    // `matched` is the payload the rule actually fired on — the field that lets
    // a false positive be judged without reproducing the request. Credential
    // targets arrive already redacted by the data plane.
    case "waf":
      return `${ts} [${r.action ?? "BLOCK"}] ${r.ip} ${r.method} ${withQuery(r)} rule=${r.rule ?? r.rule_id} score=${r.score} sev=${r.sev} attack="${r.attack}"${r.matched ? ` matched="${r.matched}"` : ""}${r.target ? ` target=${r.target}` : ""} proto=${r.protocol ?? "-"} site=${r.site}`;
    case "error":
      return `${ts} [${r.lvl ?? "ERROR"}] component=${r.subsystem ?? r.component} code=${r.code ?? "-"} msg="${r.msg}"`;
    case "audit":
      return `${ts} [AUDIT] user=${r.user} action=${r.action} resource=${r.resource} ip=${r.ip} result=${r.result} session=${r.session}`;
    default:
      return JSON.stringify(r);
  }
}

