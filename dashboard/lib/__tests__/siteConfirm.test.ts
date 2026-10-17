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
