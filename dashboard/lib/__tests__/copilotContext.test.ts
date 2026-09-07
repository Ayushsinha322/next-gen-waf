import { describe, it, expect } from "vitest";
import { buildCopilotMessage, explainAlertPrompt, draftExclusionPrompt } from "../copilotContext";

describe("copilot hand-off", () => {
  it("appends the record as fenced JSON after the question", () => {
    const m = buildCopilotMessage({ prompt: "Explain", context: { rule: "942100" } });
    expect(m.startsWith("Explain\n\nContext (JSON):\n```json\n")).toBe(true);
    expect(m).toContain('"rule": "942100"');
  });
  it("truncates oversized context so the server's text cap is not hit", () => {
    const m = buildCopilotMessage({ prompt: "x", context: { blob: "a".repeat(20000) } });
    expect(m.length).toBeLessThan(6000);
    expect(m).toContain("(truncated)");
  });
  it("titles say what was loaded", () => {
    expect(explainAlertPrompt({ kind: "attack_spike", severity: "high", summary: "Attack spike on juice" }).title).toContain("Attack spike on juice");
    expect(draftExclusionPrompt({ rule: "920350", path: "/api" }).title).toBe("Draft exclusion for rule 920350 on /api");
  });
});
