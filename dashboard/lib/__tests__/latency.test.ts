import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { formatP99 } from "../latency";

describe("formatP99", () => {
  it("reads no samples as no measurement, not as 0 ms", () => {
    // The Traffic page printed metrics.p99_latency_ms.toFixed(1) — "0.0 ms"
    // whenever the five-minute latency window was empty.
    expect(formatP99(0, 0)).toBe("—");
    expect(formatP99(12.3, 0)).toBe("—");
    expect(formatP99(undefined, undefined)).toBe("—");
    expect(formatP99(null, 5)).toBe("—");
    expect(formatP99(Number.NaN, 5)).toBe("—");
  });

  it("formats a measured value", () => {
    expect(formatP99(12.345, 40)).toBe("12.3 ms");
    expect(formatP99(12.345, 40, 2)).toBe("12.35 ms");
    expect(formatP99(0.04, 40)).toBe("<0.1 ms");
    // A cheap pass can measure 0 WAF time; with samples that is a reading.
    expect(formatP99(0, 40)).toBe("<0.1 ms");
  });

  it("an older control plane without a sample count still shows its value", () => {
    expect(formatP99(8.2, undefined)).toBe("8.2 ms");
    expect(formatP99(0, undefined)).toBe("—");
  });
});

describe("Traffic page p99 card", () => {
  it("goes through formatP99, not a raw toFixed", () => {
    const page = readFileSync(join(__dirname, "../../app/(dashboard)/traffic/page.tsx"), "utf8");
    expect(page).not.toMatch(/p99_latency_ms\.toFixed/);
    expect(page).toMatch(/formatP99\(metrics\?\.p99_latency_ms, metrics\?\.p99_samples\)/);
  });
});
