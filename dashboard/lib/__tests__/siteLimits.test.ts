import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { checkSiteLimits, LIMIT_CAPS, INSPECTION_LIMIT_RULES, INSPECTION_LIMIT_DEFAULTS, inspectionLimitOf } from "../siteConfig";

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
  it("inspection limits", () => {
    expect(constant("maxSiteInspectedArgs")).toBe(LIMIT_CAPS.maxInspectedArgs);
    expect(constant("maxSiteInspectedArgBytes")).toBe(LIMIT_CAPS.maxInspectedArgKib * 1024);
    expect(constant("maxSiteInspectionBudgetMs")).toBe(LIMIT_CAPS.maxInspectionBudgetMs);
    expect(constant("minSiteInspectionBudgetMs")).toBe(LIMIT_CAPS.minInspectionBudgetMs);
  });

  // The learning report offers "raise <setting>" instead of Disable for these
  // ids; the control plane refuses to exclude them. The two lists must be one.
  it("inspection-limit rule ids", () => {
    const m = go.match(/inspectionLimitRuleSettings = map\[int\]string\{([^}]*)\}/);
    if (!m) throw new Error("inspectionLimitRuleSettings not found in site_validate.go");
    const goMap = Object.fromEntries([...m[1].matchAll(/(\d+):\s*"(\w+)"/g)].map(e => [e[1], e[2]]));
    expect(Object.keys(goMap)).toHaveLength(3);
    const ours = Object.fromEntries(Object.entries(INSPECTION_LIMIT_RULES).map(([id, l]) => [id, l.setting]));
    expect(ours).toEqual(goMap);
  });
});

/** The defaults the form shows for an unset limit are the data plane's. */
describe("INSPECTION_LIMIT_DEFAULTS agree with the data plane", () => {
  const rust = readFileSync(join(__dirname, "../../../crates/sentinel-core/src/config/mod.rs"), "utf8");
  const constant = (name: string): number => {
    const m = rust.match(new RegExp(`pub const ${name}: u\\d+ = ([0-9_*\\s]+);`));
    if (!m) throw new Error(`${name} not found in config/mod.rs`);
    return m[1].split("*").map(s => Number(s.replace(/_/g, "").trim())).reduce((a, b) => a * b, 1);
  };
  it("args", () => expect(constant("DEFAULT_MAX_INSPECTED_ARGS")).toBe(INSPECTION_LIMIT_DEFAULTS.max_inspected_args));
  it("bytes", () => expect(constant("DEFAULT_MAX_INSPECTED_ARG_BYTES")).toBe(INSPECTION_LIMIT_DEFAULTS.max_inspected_arg_kib * 1024));
  it("time", () => expect(constant("DEFAULT_INSPECTION_TIME_BUDGET_MS")).toBe(INSPECTION_LIMIT_DEFAULTS.inspection_time_budget_ms));
});

describe("inspectionLimitOf", () => {
  it("names the setting for a refusal id, and nothing for a rule", () => {
    expect(inspectionLimitOf("9900402")?.setting).toBe("max_inspected_arg_bytes");
    expect(inspectionLimitOf(9900403)?.setting).toBe("inspection_time_budget_ms");
    expect(inspectionLimitOf("942100")).toBeUndefined();
  });
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

  it("says nothing about unset inspection limits, which take the data plane's defaults", () => {
    expect(checkSiteLimits({ ...sane, max_inspected_args: "", max_inspected_arg_kib: "", inspection_time_budget_ms: "" })).toEqual([]);
    expect(checkSiteLimits({ ...sane, max_inspected_args: 4096, max_inspected_arg_kib: 512, inspection_time_budget_ms: 10000 })).toEqual([]);
  });

  it("bounds the inspection limits as the control plane does", () => {
    const e = (f: object) => checkSiteLimits({ ...sane, ...f }).filter(c => c.level === "error").map(c => c.field);
    expect(e({ max_inspected_args: LIMIT_CAPS.maxInspectedArgs })).toEqual([]);
    expect(e({ max_inspected_args: LIMIT_CAPS.maxInspectedArgs + 1 })).toEqual(["max_inspected_args"]);
    expect(e({ max_inspected_args: 2.5 })).toEqual(["max_inspected_args"]);
    expect(e({ max_inspected_arg_kib: LIMIT_CAPS.maxInspectedArgKib + 1 })).toEqual(["max_inspected_arg_kib"]);
    expect(e({ max_inspected_arg_kib: -1 })).toEqual(["max_inspected_arg_kib"]);
    expect(e({ inspection_time_budget_ms: LIMIT_CAPS.maxInspectionBudgetMs + 1 })).toEqual(["inspection_time_budget_ms"]);
    // Seconds typed into the milliseconds field: refused, as the API refuses it.
    const tiny = checkSiteLimits({ ...sane, inspection_time_budget_ms: 10 }).filter(c => c.level === "error");
    expect(tiny.map(c => c.field)).toEqual(["inspection_time_budget_ms"]);
    expect(tiny[0].message).toMatch(/milliseconds/);
  });

  it("warns that 0 turns an inspection limit off, and that a small one refuses ordinary forms", () => {
    const w = (f: object) => checkSiteLimits({ ...sane, ...f }).filter(c => c.level === "warn").map(c => c.field);
    expect(w({ max_inspected_args: 0, max_inspected_arg_kib: 0, inspection_time_budget_ms: 0 }))
      .toEqual(["max_inspected_args", "max_inspected_arg_kib", "inspection_time_budget_ms"]);
    expect(w({ max_inspected_args: 200 })).toEqual(["max_inspected_args"]);
    expect(w({ max_inspected_arg_kib: 64 })).toEqual(["max_inspected_arg_kib"]);
  });

  it("refuses values a number input can produce but a limit cannot mean", () => {
    expect(errors({ max_body_size_mb: NaN }).map(e => e.field)).toContain("max_body_size_mb");
    expect(errors({ max_uri_length: -1 }).map(e => e.field)).toContain("max_uri_length");
    expect(errors({ paranoia_level: 2.5 }).map(e => e.field)).toContain("paranoia_level");
  });
});
