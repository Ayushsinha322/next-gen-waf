import { describe, it, expect } from "vitest";
import { niceStep } from "../../components/dashboard/ThreatTrend";

describe("Threat trend y-axis", () => {
  it("uses whole, distinct steps even for tiny counts", () => {
    for (const max of [1, 2, 3, 7, 13, 99, 1234]) {
      const step = niceStep(max / 4);
      const ticks = [0, 1, 2, 3, 4].map(k => k * step);
      expect(new Set(ticks).size, `max=${max}`).toBe(5);
      expect(ticks.every(Number.isInteger), `max=${max}`).toBe(true);
      expect(ticks[4]).toBeGreaterThanOrEqual(max);
    }
  });
});
