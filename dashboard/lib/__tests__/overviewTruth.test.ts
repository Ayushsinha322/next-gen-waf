import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const read = (p: string) => readFileSync(join(__dirname, "../../..", p), "utf8");

// Every category the control plane can put in attack_breakdown must have a row on
// the Overview page, or its blocks silently vanish from the chart — as 43 of 75
// did on the demo cluster (geoip, ratelimit, anomaly, ip_reputation, threat_intel).
describe("Overview attack breakdown covers every category the hub reports", () => {
  it("ATTACK_META ⊇ attackCategory() results", () => {
    const hub = read("control-plane/internal/logs/hub.go");
    const fn = hub.slice(hub.indexOf("func attackCategory("));
    const goCats = new Set([...fn.matchAll(/return "([a-z_]+)"/g)].map(m => m[1]));
    const page = read("dashboard/app/(dashboard)/overview/page.tsx");
    const meta = page.slice(page.indexOf("const ATTACK_META"), page.indexOf("};", page.indexOf("const ATTACK_META")));
    const tsCats = new Set([...meta.matchAll(/^\s*([a-z_]+):\s*\{ label/gm)].map(m => m[1]));
    expect(goCats.size).toBeGreaterThan(8);
    const missing = [...goCats].filter(c => !tsCats.has(c));
    expect(missing, `categories the hub reports but Overview drops: ${missing.join(", ")}`).toEqual([]);
  });
});

describe("Overview states only what it looked up", () => {
  const page = read("dashboard/app/(dashboard)/overview/page.tsx");
  it("counts ENABLED plugins, not installed ones", () => {
    expect(page).not.toMatch(/setPlugins\(\(p\.plugins \?\? \[\]\)\.length\)/);
    expect(page).not.toMatch(/WASM loaded/);
  });
  it("does not call bot defense on because the ML engine runs", () => {
    expect(page).not.toMatch(/crs\.on > 0 \|\| running/);
  });
});
