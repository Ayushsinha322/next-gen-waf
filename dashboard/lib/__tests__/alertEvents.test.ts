import { describe, it, expect, vi, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { announceAlertsChanged, onAlertsChanged } from "../alertEvents";

describe("alert-count refresh", () => {
  // Node test environment: a bare EventTarget is all the module uses of window.
  beforeAll(() => { (globalThis as { window?: unknown }).window = new EventTarget(); });
  it("delivers an announcement to every subscriber, and stops after unsubscribe", () => {
    const a = vi.fn(), b = vi.fn();
    const offA = onAlertsChanged(a);
    onAlertsChanged(b);
    announceAlertsChanged();
    expect(a).toHaveBeenCalledTimes(1);
    expect(b).toHaveBeenCalledTimes(1);
    offA();
    announceAlertsChanged();
    expect(a).toHaveBeenCalledTimes(1);
    expect(b).toHaveBeenCalledTimes(2);
  });

  // The bug was a count fetched once and never again. Pin the three places that
  // must stay wired: the page that changes alerts announces, the bell and the
  // sidebar listen.
  const src = (p: string) => readFileSync(join(__dirname, "../..", p), "utf8");
  it("the Alerts page announces after acknowledging and closing", () => {
    const page = src("app/(dashboard)/alerts/page.tsx");
    expect(page.match(/announceAlertsChanged\(\)/g)?.length ?? 0).toBeGreaterThanOrEqual(5);
  });
  it("the bell and the sidebar badge listen and poll", () => {
    const top = src("components/layout/TopBar.tsx");
    expect(top).toMatch(/onAlertsChanged\(load\)/);
    expect(top).toMatch(/setInterval\(load, 15_000\)/);
    expect(src("components/layout/SideBar.tsx")).toMatch(/onAlertsChanged\(load\)/);
  });
});
