import { describe, it, expect } from "vitest";
import { translate, en, SUPPORTED_LOCALES } from "../i18n";

describe("i18n seed", () => {
  it("returns the English string and interpolates variables", () => {
    expect(translate("en", "cluster.online", { healthy: 3, total: 3 })).toBe("3/3 online");
  });
  it("falls back to the key for an unknown id, never to an empty string", () => {
    expect(translate("en", "nav.does-not-exist")).toBe("nav.does-not-exist");
  });
  it("leaves an unknown placeholder visible rather than dropping it", () => {
    expect(translate("en", "cluster.leader", {})).toBe("{id} · leader");
  });
  it("lists only locales that have a dictionary", () => {
    for (const l of SUPPORTED_LOCALES) expect(l.code === "en" ? en : undefined).toBeTruthy();
  });
});
