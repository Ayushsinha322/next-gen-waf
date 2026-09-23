import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { checkSiteLimits, LIMIT_CAPS } from "../siteConfig";

/**
 * The console's caps and the control plane's must be the same numbers. If they
 * drift, the console either lets through a value the server then rejects (a
 * confusing failure at Review) or refuses one the API happily accepts (the
 * console becomes the only thing enforcing a limit it thinks is global).
 */
describe("LIMIT_CAPS agree with the control plane", () => {
  const go = readFileSync(join(__dirname, "../../../control-plane/cmd/controllerd/site_validate.go"), "utf8");
  const constant = (name: string): number => {
    const m = go.match(new RegExp(`\\b${name}\\s*=\\s*([0-9*\\s]+?)\\s*(?://|\\n)`));
    if (!m) throw new Error(`${name} not found in site_validate.go`);
    return m[1].split("*").map(s => Number(s.trim())).reduce((a, b) => a * b, 1);
  };
  it("body", () => expect(constant("maxSiteBodyBytes")).toBe(LIMIT_CAPS.maxBodyMb * 1024 * 1024));
  it("uri", () => expect(constant("maxSiteURIBytes")).toBe(LIMIT_CAPS.maxUriBytes));
  it("headers", () => expect(constant("maxSiteHeaders")).toBe(LIMIT_CAPS.maxHeaders));
});

/**
 * The first real deployment stored these values, and nothing questioned them:
 * "Max Body (MB)" = 1000000 (a byte count for 1 MB, typed into a megabyte field —
 * 976 GB), "Max URI (bytes)" = 819200, and the Strict preset's paranoia 4 with
 * threshold 3. Each test below starts from a value an operator actually typed.
 */
const sane = {
  max_body_size_mb: 50,
  max_uri_length: 16384,
  max_header_count: 200,
  paranoia_level: 2,
  anomaly_threshold: 10,
  mode: "learning" as const,
};

const errors = (f: Partial<typeof sane>) =>
  checkSiteLimits({ ...sane, ...f }).filter(c => c.level === "error");
const warnings = (f: Partial<typeof sane>) =>
  checkSiteLimits({ ...sane, ...f }).filter(c => c.level === "warn");

describe("checkSiteLimits", () => {
  it("says nothing about a sane configuration", () => {
    expect(checkSiteLimits(sane)).toEqual([]);
  });

  it("refuses the 976 GB body limit from the UAT deployment, and names the likely mistake", () => {
    const e = errors({ max_body_size_mb: 1_000_000 });
    expect(e).toHaveLength(1);
    expect(e[0].field).toBe("max_body_size_mb");
    expect(e[0].message).toMatch(/megabytes/);
    expect(e[0].message).toMatch(/976\.6 GB|976 GB/);
    // 1,000,000 bytes is just under 1 MB — the hint says what to enter instead.
    expect(e[0].message).toMatch(/If you meant 1,000,000 bytes, enter 1\b/);
  });

  it("allows up to the cap, and warns on the memory cost of very large bodies", () => {
    expect(errors({ max_body_size_mb: LIMIT_CAPS.maxBodyMb })).toEqual([]);
    expect(errors({ max_body_size_mb: LIMIT_CAPS.maxBodyMb + 1 })).toHaveLength(1);
    expect(warnings({ max_body_size_mb: 4096 }).map(w => w.field)).toContain("max_body_size_mb");
  });

  it("warns that 0 means no body limit at all", () => {
    const w = warnings({ max_body_size_mb: 0 });
    expect(w).toHaveLength(1);
    expect(w[0].message).toMatch(/no limit/);
  });

  it("refuses the 819200-byte URI limit, and warns on one too small for real links", () => {
    const e = errors({ max_uri_length: 819_200 });
    expect(e).toHaveLength(1);
    expect(e[0].message).toMatch(/16384/);
    expect(warnings({ max_uri_length: 1024 }).map(w => w.field)).toContain("max_uri_length");
  });

  it("bounds header counts both ways", () => {
    expect(errors({ max_header_count: 5000 })).toHaveLength(1);
    expect(warnings({ max_header_count: 10 }).map(w => w.field)).toContain("max_header_count");
  });

  it("warns on the Strict preset's paranoia 4 / threshold 3, louder in blocking mode", () => {
    const learning = warnings({ paranoia_level: 4, anomaly_threshold: 3 });
    expect(learning).toHaveLength(1);
    expect(learning[0].field).toBe("anomaly_threshold");
    expect(learning[0].message).not.toMatch(/Blocking mode/);

    const blocking = warnings({ paranoia_level: 4, anomaly_threshold: 3, mode: "blocking" as never });
    expect(blocking[0].message).toMatch(/^This site is in Blocking mode/);
    // Strict but with a sane threshold is left alone.
    expect(warnings({ paranoia_level: 4, anomaly_threshold: 10 })).toEqual([]);
  });

  it("refuses impossible protection values", () => {
    expect(errors({ paranoia_level: 5 }).map(e => e.field)).toContain("paranoia_level");
    expect(errors({ paranoia_level: 0 }).map(e => e.field)).toContain("paranoia_level");
    expect(errors({ anomaly_threshold: 0 }).map(e => e.field)).toContain("anomaly_threshold");
  });

  it("refuses values a number input can produce but a limit cannot mean", () => {
    expect(errors({ max_body_size_mb: NaN }).map(e => e.field)).toContain("max_body_size_mb");
    expect(errors({ max_uri_length: -1 }).map(e => e.field)).toContain("max_uri_length");
    expect(errors({ paranoia_level: 2.5 }).map(e => e.field)).toContain("paranoia_level");
  });
});
