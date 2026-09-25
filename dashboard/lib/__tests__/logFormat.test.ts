import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fmt, verdict, attackByRequest, lineCounts, toneOf } from "../logFormat";

/**
 * A module block must be explainable from the Logs page line. Until 2026-09-16
 * a gRPC, GraphQL, JWT, threat-intel or smuggling 403 rendered as
 * `[BLOCK] … 403` with no rule and no reason — the record carried neither.
 */
describe("Logs page access line", () => {
  const base = { ts: "2026-09-16T08:00:00Z", ip: "203.0.113.9", method: "POST", path: "/api/x", query: "",
    status: 403, protocol: "h1", latency: "5.50", waf_ms: "4.10", bytes: 0, site: "Juice Shop", ua: "curl/8.5.0", referer: "-" };

  it("shows the module reason on a block with no rule", () => {
    const line = fmt("access", { ...base, action: "BLOCK", rule: "", reason: "grpc: server reflection blocked" });
    expect(line).toContain("[BLOCK]");
    expect(line).toContain('reason="grpc: server reflection blocked"');
    expect(line).not.toContain("rule=");
  });

  it("shows the primary rule on a rule block", () => {
    const line = fmt("access", { ...base, action: "BLOCK", rule: "9900100", reason: "anomaly score 24 >= threshold 10" });
    expect(line).toContain("rule=9900100");
    expect(line).toContain('reason="anomaly score 24 >= threshold 10"');
  });

  it("renders a passed request and an older row exactly as before", () => {
    const passed = fmt("access", { ...base, status: 200, action: "PASS", rule: "", reason: "" });
    expect(passed).not.toContain("rule=");
    expect(passed).not.toContain("reason=");
    const old = fmt("access", { ...base, status: 200, action: "PASS" }); // predates the fields
    expect(old).toBe(passed);
  });

  it("verdict prefers the data plane's action over the HTTP status", () => {
    expect(verdict({ action: "PASS", status: 500 })).toBe("PASS");
    expect(verdict({ action: "BLOCK", status: 200 })).toBe("BLOCK");
    expect(verdict({ status: 403 })).toBe("BLOCK"); // fallback for rows with no action
  });
});

/**
 * A customer reads the Support ID off the block page; the operator must be able
 * to paste it into the Logs page search box. On 2026-09-24 that search found
 * nothing: the record carried request_id but no line printed it.
 */
describe("Logs page lines carry the Support ID, score and attack", () => {
  const id = "654954e0-65ef-478f-9b65-6b4e5ebca9fc";
  const blocked = { ts: "2026-09-24T08:52:26Z", ip: "10.212.134.61", method: "GET", path: "/rest/products/search",
    query: "q=%27))%20UNION", status: 403, protocol: "h1", latency: "13.70", waf_ms: "13.70", bytes: 1954,
    site: "Juice Shop", ua: "Mozilla/5.0", referer: "-", action: "BLOCK", rule: "9900100", score: 85,
    reason: "anomaly score 85 >= threshold 10", request_id: id };

  it("access line: id, score and — when joined — the attack name", () => {
    const plain = fmt("access", blocked);
    expect(plain).toContain(`id=${id}`);
    expect(plain).toContain("score=85");
    expect(plain).not.toContain("attack=");
    const joined = fmt("access", { ...blocked, attack: "SQL Injection via libinjection (all-placement)" });
    expect(joined).toContain('attack="SQL Injection via libinjection (all-placement)"');
  });

  it("waf line: id", () => {
    const line = fmt("waf", { ts: blocked.ts, action: "BLOCK", ip: blocked.ip, method: "GET", path: blocked.path,
      rule: "9900100", score: 85, sev: "CRITICAL", attack: "SQL Injection", request_id: id, site: "Juice Shop" });
    expect(line).toContain(`id=${id}`);
  });

  it("no id, no score and no attack on a row without them", () => {
    const line = fmt("access", { ...blocked, request_id: "", score: 0, action: "PASS", status: 200, rule: "", reason: "" });
    expect(line).not.toMatch(/ id=| score=| attack=/);
  });

  it("attackByRequest joins waf.log to access.log by request id", () => {
    const m = attackByRequest([
      { request_id: id, attack: "SQL Injection" },
      { request_id: "", attack: "ignored — no id" },
      { request_id: "other", attack: "" },
    ]);
    expect(m.get(id)).toBe("SQL Injection");
    expect(m.size).toBe(1);
  });
});

describe("Logs page counters count the lines on screen", () => {
  it("access: blocked by verdict, errors by 5xx — PASS lines are not threats", () => {
    // The 2026-09-24 screen: an access.log search showing two PASS lines read "2 threats".
    const rows = [
      { action: "PASS", status: 304, rule: "920350" },
      { action: "PASS", status: 200, rule: "920350" },
    ];
    expect(lineCounts("access", rows)).toEqual({ blocked: 0, errors: 0 });
    expect(lineCounts("access", [...rows, { action: "BLOCK", status: 403 }, { action: "PASS", status: 502 }]))
      .toEqual({ blocked: 1, errors: 1 });
  });

  it("waf: a learning-mode CRITICAL is red but not counted as blocked", () => {
    const detect = { action: "DETECT", sev: "CRITICAL" };
    expect(toneOf("waf", detect)).toBe("critical");
    expect(lineCounts("waf", [detect, { action: "BLOCK", sev: "CRITICAL" }])).toEqual({ blocked: 1, errors: 0 });
  });

  it("error: ERROR and FATAL", () => {
    expect(lineCounts("error", [{ lvl: "WARN" }, { lvl: "ERROR" }, { lvl: "FATAL" }])).toEqual({ blocked: 0, errors: 2 });
  });

  it("the page counts the filtered rows of the open file, not all of waf.log", () => {
    const page = readFileSync(join(__dirname, "../../app/(dashboard)/logs/page.tsx"), "utf8");
    expect(page).toMatch(/lineCounts\(kind, filtered\)/);
    expect(page).not.toMatch(/logs\.waf\.filter\(/);
  });
});

describe("waf.log line lists every contributing rule", () => {
  const base = { ts: "2026-09-25T10:00:00Z", action: "BLOCK", ip: "10.0.0.1", method: "GET", path: "/s",
    rule: "9900100", score: 85, sev: "CRITICAL", attack: "SQL Injection", site: "Juice Shop", request_id: "abc" };

  it("appends rules= with each rule's share when there are several", () => {
    const line = fmt("waf", { ...base, rules: [{ id: "9900100", score: 50 }, { id: "942190", score: 30 }, { id: "942100", score: 5 }] });
    expect(line).toContain("rules=9900100:50,942190:30,942100:5");
  });

  it("adds nothing for a single rule or an older record", () => {
    expect(fmt("waf", { ...base, rules: [{ id: "9900100", score: 85 }] })).not.toContain("rules=");
    expect(fmt("waf", base)).not.toContain("rules=");
  });
});
