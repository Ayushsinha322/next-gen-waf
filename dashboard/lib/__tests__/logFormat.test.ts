import { describe, it, expect } from "vitest";
import { fmt, verdict } from "../logFormat";

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
