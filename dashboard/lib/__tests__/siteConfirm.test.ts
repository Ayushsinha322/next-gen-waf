import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { modeChangeConfirm, pauseConfirm, deleteConfirm, countryBlockConfirm } from "../siteConfirm";

describe("confirmation wording says the consequence", () => {
  it("Off warns that attacks go through uninspected", () => {
    const c = modeChangeConfirm("Juice Shop", "blocking", "off");
    expect(c.tone).toBe("danger");
    expect(c.body).toMatch(/without inspection/);
  });
  it("Blocking points at the learning report first", () => {
    expect(modeChangeConfirm("s", "learning", "blocking").body).toMatch(/learning report/);
  });
  it("leaving Blocking says attacks will reach the app", () => {
    const c = modeChangeConfirm("s", "blocking", "learning");
    expect(c.body).toMatch(/Attacks will reach/);
    expect(c.tone).toBe("danger");
  });
  it("Pause names the domains that will stop being served", () => {
    expect(pauseConfirm("s", ["a.example", "b.example"]).body).toMatch(/a\.example, b\.example/);
  });
  it("Delete says it cannot be undone; a map block says EVERY site", () => {
    expect(deleteConfirm("s", ["a.example"]).body).toMatch(/cannot be undone/);
    expect(countryBlockConfirm("China").title).toMatch(/every site/);
  });
});

// Each of these was a single click with no question. Pin that they now ask.
describe("the dangerous actions are wired to ask", () => {
  const src = (p: string) => readFileSync(join(__dirname, "../..", p), "utf8");
  it("site page: mode, pause, delete", () => {
    const s = src("app/(dashboard)/sites/[id]/page.tsx");
    expect(s).toMatch(/confirmAction\(modeChangeConfirm/);
    expect(s).toMatch(/confirmAction\(pauseConfirm/);
    expect(s).toMatch(/confirmAction\(deleteConfirm/);
  });
  it("sites list: pause, delete — no bare browser confirm()", () => {
    const s = src("app/(dashboard)/sites/page.tsx");
    expect(s).toMatch(/confirmAction\(pauseConfirm/);
    expect(s).toMatch(/confirmAction\(deleteConfirm/);
    expect(s).not.toMatch(/[^.\w]confirm\(`Delete/);
  });
  it("world map: blocking a country everywhere", () => {
    expect(src("components/dashboard/WorldMap.tsx")).toMatch(/confirmAction\(countryBlockConfirm/);
  });
  // The map closes its menu on any pointer-down. The menu's own pointer-down
  // must not reach it, or the button press closes the menu before the click
  // lands and "Block this country" silently does nothing (it never worked from
  // 2026-06-25 to 2026-10-18 for exactly this reason).
  it("world map: the menu's own press does not close the menu", () => {
    expect(src("components/dashboard/WorldMap.tsx")).toMatch(/onPointerDown=\{\(e\) => e\.stopPropagation\(\)\} onClick=\{\(e\) => e\.stopPropagation\(\)\}/);
  });
});

// Users could be created and never changed or removed from the console — a
// leaver kept access. Pin that the Users tab offers role, disable and remove,
// behind a confirmation, and reads the viewer in an effect.
describe("the Users tab can change and remove users", () => {
  const s = readFileSync(join(__dirname, "../..", "app/(dashboard)/settings/page.tsx"), "utf8");
  it("wires role change, disable and remove through confirmAction", () => {
    expect(s).toMatch(/api\.admin\.users\.update\(u\.id, \{ role \}\)/);
    expect(s).toMatch(/api\.admin\.users\.update\(u\.id, \{ status:/);
    expect(s).toMatch(/api\.admin\.users\.remove\(u\.id\)/);
    expect((s.match(/await confirmAction\(\{/g) ?? []).length).toBeGreaterThanOrEqual(3);
  });
  it("reads the signed-in user in an effect, not during render", () => {
    expect(s).toMatch(/useEffect\(\(\) => \{ setMe\(getUser\(\)\); \}, \[\]\)/);
  });
});

// Ten destructive actions (delete a rule, certificate, channel, plugin, report
// schedule or log profile; revoke an API key; revert the management certificate;
// remove an indicator; block an IP on every site) used the browser's native confirm() until 2026-10-19 — a system box that
// freezes the page, cannot state the consequence in the product's words, and
// can be suppressed for the session. Pin that no native confirm with a message
// comes back anywhere in the console.
describe("no native browser confirm() dialogs", () => {
  const { readdirSync, statSync } = require("node:fs") as typeof import("node:fs");
  const root = join(__dirname, "../..");
  const files: string[] = [];
  const walk = (d: string) => {
    for (const n of readdirSync(d)) {
      if (n === "node_modules" || n === ".next" || n === "__tests__") continue;
      const p = join(d, n);
      if (statSync(p).isDirectory()) walk(p);
      else if (/\.(tsx?|jsx?)$/.test(n)) files.push(p);
    }
  };
  walk(join(root, "app"));
  walk(join(root, "components"));
  it("scans a real tree", () => {
    expect(files.length).toBeGreaterThan(30);
  });
  it("calls confirm() with a message nowhere", () => {
    const offenders = files.filter(f =>
      /(^|[^.\w])(window\.)?confirm\(\s*[`"']/m.test(readFileSync(f, "utf8")));
    expect(offenders.map(f => f.slice(root.length + 1))).toEqual([]);
  });
  it("routes the ten former offenders through confirmAction", () => {
    const want: [string, RegExp][] = [
      ["app/(dashboard)/rules/page.tsx", /confirmAction\(ruleDeleteConfirm/],
      ["app/(dashboard)/alerts/page.tsx", /confirmAction\(ipBlockEverywhereConfirm/],
      ["app/(dashboard)/certificates/page.tsx", /confirmAction\(certDeleteConfirm/],
      ["app/(dashboard)/settings/page.tsx", /confirmAction\(apiKeyRevokeConfirm/],
      ["app/(dashboard)/settings/page.tsx", /confirmAction\(channelDeleteConfirm/],
      ["app/(dashboard)/settings/page.tsx", /confirmAction\(mgmtCertRevertConfirm/],
      ["app/(dashboard)/threat-intel/page.tsx", /confirmAction\(iocRemoveConfirm/],
      ["app/(dashboard)/plugins/page.tsx", /confirmAction\(pluginDeleteConfirm/],
      ["app/(dashboard)/reports/page.tsx", /confirmAction\(reportScheduleDeleteConfirm/],
      ["components/events/LogProfilePanel.tsx", /confirmAction\(logProfileDeleteConfirm/],
    ];
    for (const [f, re] of want) expect(readFileSync(join(root, f), "utf8")).toMatch(re);
  });
});
