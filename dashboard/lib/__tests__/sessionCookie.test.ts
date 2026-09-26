import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { sessionCookieString, isSessionCookieValue, SESSION_MARKER, SESSION_COOKIE } from "../sessionCookie";

describe("the session cookie is a marker, never a credential", () => {
  it("holds the marker, and is Secure over HTTPS", () => {
    expect(sessionCookieString(true)).toBe(`${SESSION_COOKIE}=${SESSION_MARKER}; path=/; max-age=604800; SameSite=Lax; Secure`);
    expect(sessionCookieString(false)).not.toContain("Secure");
    expect(sessionCookieString(true)).not.toMatch(/eyJ/);
  });

  it("the navigation gate accepts the marker, and an older console's JWT until it is rewritten", () => {
    expect(isSessionCookieValue(SESSION_MARKER)).toBe(true);
    const jwtShaped = ["eyJhbGciOiJIUzI1NiJ9", btoa(JSON.stringify({ sub: "u" })), "sig"].join(".");
    expect(isSessionCookieValue(jwtShaped)).toBe(true);
    for (const bad of [undefined, "", "1", "a.b", "a.b.c", "x.eyJ9.y"]) {
      expect(isSessionCookieValue(bad), String(bad)).toBe(false);
    }
  });

  it("no source file writes a token into a cookie", () => {
    // 2026-09-26: four places set `sentinel_token=<access token>` from JS, so
    // the admin's token went to every site the WAF served on the same host.
    const root = join(__dirname, "../..");
    const files: string[] = [];
    const walk = (dir: string) => {
      for (const name of readdirSync(dir)) {
        if (name === "node_modules" || name === ".next" || name === "__tests__") continue;
        const p = join(dir, name);
        if (statSync(p).isDirectory()) walk(p);
        else if (/\.(ts|tsx)$/.test(name)) files.push(p);
      }
    };
    for (const d of ["app", "components", "lib"]) walk(join(root, d));
    // Top-level files (middleware.ts and friends) — not a second full walk.
    for (const name of readdirSync(root)) {
      if (/\.(ts|tsx)$/.test(name)) files.push(join(root, name));
    }
    const offenders = files.filter(f => /document\.cookie\s*=\s*`[^`]*=\$\{[^}]*(token|access)/i.test(readFileSync(f, "utf8")));
    expect(offenders).toEqual([]);
  });
});
