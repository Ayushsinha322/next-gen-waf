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

/**
 * ` rules=9900100:50,942190:30` — every rule that added to the score, with its
 * share — when the record lists more than the leading rule. A single rule adds
 * nothing the `rule=` field does not already say.
 */
function rulesPart(r: Record<string, unknown>): string {
  const list = Array.isArray(r.rules) ? r.rules as Array<Record<string, unknown>> : [];
  if (list.length < 2) return "";
  return ` rules=${list.map(x => `${x.id}:${x.score}`).join(",")}`;
}

/** ` id=<request id>` — the Support ID on the block page — or nothing. */
function idPart(r: Record<string, unknown>): string {
  const id = r.request_id;
  return typeof id === "string" && id !== "" && id !== "-" ? ` id=${id}` : "";
}

/**
 * request id → attack name, from the waf.log rows the page already holds.
 *
 * The access record carries the rule and score but not the attack's name; the
 * waf.log record for the same request does. Both arrive on the same stream, so
 * the page joins them rather than printing a bare `rule=9900100`.
 */
export function attackByRequest(wafRows: Array<Record<string, unknown>>): Map<string, string> {
  const m = new Map<string, string>();
  for (const w of wafRows) {
    const id = w.request_id, attack = w.attack;
    if (typeof id === "string" && id && typeof attack === "string" && attack) m.set(id, attack);
  }
  return m;
}

/**
 * How a line is coloured. Same rules the page always used; lifted here so the
 * counters below and the colours cannot drift apart.
 */
export type LineTone = "block" | "warn" | "err" | "critical" | "pass" | "info";

export function toneOf(kind: LogKind, r: Record<string, unknown>): LineTone {
  switch (kind) {
    case "access": {
      // Severity follows the WAF verdict first; a 5xx from a healthy origin is
      // an error worth colouring, but it is not a block.
      const v = verdict(r);
      if (v === "BLOCK") return "block";
      if (v === "CHALLENGE" || v === "LIMIT") return "warn";
      return Number(r.status ?? 200) >= 500 ? "err" : "pass";
    }
    // A CRITICAL detection is red even when it was not blocked: in learning mode
    // that line is the "would have blocked" an operator is looking for.
    case "waf":   return r.sev === "CRITICAL" ? "critical" : isBlockAction(r.action) ? "block" : "warn";
    case "error": return r.lvl === "FATAL" ? "critical" : r.lvl === "ERROR" ? "err" : r.lvl === "WARN" ? "warn" : "info";
    case "audit": return r.result === "FAILURE" ? "err" : "info";
    default:      return "info";
  }
}

function isBlockAction(a: unknown): boolean {
  const s = String(a ?? "").toUpperCase();
  return s === "BLOCK" || s === "BLOCKED";
}

/**
 * Blocked and error counts over exactly the lines being shown.
 *
 * The counters used to tally waf.log's BLOCK rows whatever file was open and
 * whatever the search box held, so an access.log search showing two PASS lines
 * read "2 threats". "Blocked" is the WAF's own verdict on the line (not its
 * colour — a learning-mode CRITICAL is red but was not blocked); "errors" is a
 * 5xx on access.log and ERROR/FATAL on error.log.
 */
export function lineCounts(kind: LogKind, rows: Array<Record<string, unknown>>): { blocked: number; errors: number } {
  let blocked = 0, errors = 0;
  for (const r of rows) {
    if (kind === "access") {
      if (verdict(r) === "BLOCK") blocked++;
      else if (Number(r.status ?? 200) >= 500) errors++;
    } else if (kind === "waf") {
      if (isBlockAction(r.action)) blocked++;
    } else if (kind === "error") {
      if (r.lvl === "ERROR" || r.lvl === "FATAL") errors++;
    }
  }
  return { blocked, errors };
}

export function fmt(kind: LogKind, r: Record<string, unknown>): string {
  const ts = String(r.ts ?? "");
  switch (kind) {
    // The query string is appended to the path here, not shown as a separate
    // field: on this page a reader wants the URL as requested. It is stored
    // separately (so per-path aggregation keeps its cardinality) and rejoined
    // only for display. Without it a blocked `/rest/products/search` gave no
    // hint of the `?q=1' UNION SELECT…` that made it an attack.
    //
    // `score`, `attack` and `id` make a block line self-explaining the way an
    // F5 request row is: HOW bad (score), WHAT it was (attack — not in the
    // access record; the page joins it from waf.log by request id, see
    // attackByRequest), and the Support ID the visitor was shown, so the ID a
    // customer reads out can be found with this page's own search box. All
    // three are appended only when present.
    case "access":
      return `${ts} [${verdict(r)}] ${r.ip} ${r.method} ${withQuery(r)} ${r.status} proto=${r.protocol ?? "-"} latency=${r.latency}ms waf=${r.waf_ms ?? "-"}ms bytes=${r.bytes} site=${r.site} ua="${r.ua ?? "-"}"${r.referer && r.referer !== "-" ? ` referer="${r.referer}"` : ""}${r.rule ? ` rule=${r.rule}` : ""}${Number(r.score) > 0 ? ` score=${r.score}` : ""}${r.attack ? ` attack="${r.attack}"` : ""}${r.reason ? ` reason="${r.reason}"` : ""}${idPart(r)}`;
    // `matched` is the payload the rule actually fired on — the field that lets
    // a false positive be judged without reproducing the request. Credential
    // targets arrive already redacted by the data plane.
    case "waf":
      return `${ts} [${r.action ?? "BLOCK"}] ${r.ip} ${r.method} ${withQuery(r)} rule=${r.rule ?? r.rule_id} score=${r.score} sev=${r.sev} attack="${r.attack}"${r.matched ? ` matched="${r.matched}"` : ""}${r.target ? ` target=${r.target}` : ""}${rulesPart(r)} proto=${r.protocol ?? "-"} site=${r.site}${idPart(r)}`;
    case "error":
      return `${ts} [${r.lvl ?? "ERROR"}] component=${r.subsystem ?? r.component} code=${r.code ?? "-"} msg="${r.msg}"`;
    case "audit":
      return `${ts} [AUDIT] user=${r.user} action=${r.action} resource=${r.resource} ip=${r.ip} result=${r.result} session=${r.session}`;
    default:
      return JSON.stringify(r);
  }
}


function escHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/** Colour everything on a line except the request path. */
function decorate(seg: string): string {
  return seg
    .replace(/(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\d.Z]*)/g, '<span class="hl-ts">$1</span>')
    .replace(/\[(PASS)\]/g,                           '[<span class="hl-pass">$1</span>]')
    .replace(/\[(BLOCK|BLOCKED)\]/g,                  '[<span class="hl-blk">$1</span>]')
    .replace(/\[(ERROR|FATAL)\]/g,                    '[<span class="hl-err">$1</span>]')
    .replace(/\[(WARN)\]/g,                           '[<span class="hl-warn">$1</span>]')
    .replace(/\[(CHALLENGE)\]/g,                      '[<span class="hl-chal">$1</span>]')
    .replace(/\[(LIMIT)\]/g,                          '[<span class="hl-warn">$1</span>]')
    .replace(/\[(AUDIT|ML|CRS|INFO)\]/g,              '[<span class="hl-info">$1</span>]')
    .replace(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g,'<span class="hl-ip">$1</span>')
    .replace(/\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b/g, '<span class="hl-method">$1</span>')
    // The status code: the number between the path and `proto=` on an access
    // line. Anchored there, not matched anywhere, so a "201" inside a user
    // agent or referer is not coloured as a response.
    .replace(/ (\d{3})(?= proto=)/, (_m, code: string) =>
      ` <span class="${/^[45]/.test(code) ? "hl-block" : "hl-ok"}">${code}</span>`)
    .replace(/proto=(h[123]|-)/g,                     'proto=<span class="hl-method">$1</span>')
    .replace(/score=(\d+)/g,                          'score=<span class="hl-score">$1</span>');
}

/**
 * HTML for one log line: escaped first, then coloured.
 *
 * The request path is isolated BEFORE anything else is coloured, and nothing
 * is coloured inside it. The previous version ran the status-code, IP and
 * method patterns over the whole line and wrapped the path last, so a payload
 * holding a number like 201 (`?q=1%27%20OR%201%3D1--`, the commonest SQL
 * injection probe there is) or an IP (`?url=http://169.254.169.254/`) got a
 * <span> inserted mid-path; the path pattern, which stops at whitespace, then
 * cut that tag in half and the line printed ` class="hl-ok">201` as text.
 * Invariant, pinned by tests: stripping the tags gives back the escaped line.
 */
export function highlightLine(raw: string): string {
  const esc = escHtml(raw);
  // split() with a capture group keeps the path tokens at odd indexes.
  const parts = esc.split(/( \/[^\s"&;]+)/);
  return parts
    .map((seg, i) => (i % 2 === 1 ? ` <span class="hl-path">${seg.slice(1)}</span>` : decorate(seg)))
    .join("");
}
