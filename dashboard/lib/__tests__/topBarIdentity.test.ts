import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * The top bar shows who is signed in, and it has to be right.
 *
 * It read a hardcoded "admin / OWNER" for every account. That is not a
 * harmless placeholder, because `owner` is the TOP of the RBAC table
 * (control-plane/internal/rbac/rbac.go) and the three accounts on the first
 * deployment are `admin`, `editor` and `auditor`. Every one of them was shown
 * OWNER — on the screen an access review reads, telling the reviewer that three
 * accounts hold the highest privilege in the product when none of them do.
 *
 * That is the same shape as several other defects here and the reason this file
 * exists rather than a comment: a value the console states with confidence,
 * which it never actually looked up. `last_login_at` read "Never" for everyone
 * because nothing wrote it; the 2FA column read a field the API never sent; a
 * disconnected Overview reported a WAF protecting zero sites. In each case the
 * screen was decisive and wrong, which is worse than blank.
 *
 * So: the identity must come from the session, and the elements that show it
 * must render expressions rather than literal text.
 */

const ROOT = join(__dirname, "..", "..");
const TOPBAR = join(ROOT, "components", "layout", "TopBar.tsx");

function src(): string {
  return readFileSync(TOPBAR, "utf8");
}

/**
 * Comments out. The component explains in prose WHY getUser() belongs in an
 * effect, and an earlier version of this test matched that sentence and
 * reported correct code as broken — the fourth time in this repo a rule has
 * failed on its own documentation. Strip first, match second, always.
 */
function code(): string {
  return src()
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/^\s*\/\/.*$/gm, "");
}

/**
 * Returns the text between an element opening with `className="<cls>"` and its
 * closing tag — i.e. what that element actually renders.
 */
function renderedBody(s: string, cls: string): string {
  const i = s.indexOf(`className="${cls}"`);
  if (i === -1) return "";
  const gt = s.indexOf(">", i);
  const close = s.indexOf("</", gt);
  return gt === -1 || close === -1 ? "" : s.slice(gt + 1, close);
}

describe("the top bar shows the account that is actually signed in", () => {
  it("reads the session rather than assuming one", () => {
    const s = code();
    expect(
      s.includes("getUser("),
      "TopBar does not call getUser() — whatever it shows is not the signed-in account",
    ).toBe(true);
  });

  /**
   * getUser() is backed by localStorage, which does not exist during server
   * rendering. Reading it inline makes the server and client markup disagree,
   * so it belongs in an effect.
   */
  it("reads it in an effect, not during render", () => {
    // Drop the import statements first: `import { getUser }` is a mention, not
    // a call, and an earlier version of this test matched it and then reported
    // correct code as broken.
    const body = code().replace(/^import .*$/gm, "");
    const calls = [...body.matchAll(/getUser\(\)/g)].map((m) => m.index!);
    expect(calls.length, "TopBar never calls getUser()").toBeGreaterThan(0);

    const effects = [...body.matchAll(/useEffect\(/g)].map((m) => {
      const start = m.index!;
      const end = body.indexOf("}, [", start);
      return end === -1 ? null : { start, end };
    });

    for (const at of calls) {
      const inside = effects.some((e) => e && at > e.start && at < e.end);
      expect(
        inside,
        "getUser() is called during render — localStorage does not exist on the " +
          "server, so the markup would hydrate differently than it rendered",
      ).toBe(true);
    }
  });

  // The three elements that make the claim. Each must render a value, not text.
  for (const cls of ["uav", "uname", "urole"]) {
    it(`.${cls} renders a value, not a hardcoded string`, () => {
      const body = renderedBody(src(), cls).trim();
      expect(body, `.${cls} was not found in TopBar.tsx`).not.toBe("");
      expect(
        body.startsWith("{"),
        `.${cls} renders the literal ${JSON.stringify(body)} — it will say that ` +
          "for every account that signs in, whoever they are",
      ).toBe(true);
    });
  }

  /**
   * Naming a specific role is the failure that actually happened, so check for
   * it directly: no RBAC role may appear as literal text anywhere in the file.
   * They are values that come back from the control plane, never decoration.
   */
  it("names no RBAC role as literal text", () => {
    const s = code();
    const roles = ["OWNER", "ADMIN", "EDITOR", "VIEWER", "AUDITOR"];
    const found = roles.filter((r) => new RegExp(`["'>]\\s*${r}\\s*["'<]`).test(s));
    expect(
      found,
      `a role is written into the markup: ${found.join(", ")}. Roles come from ` +
        "the session; stating one the account may not hold misreports privilege.",
    ).toEqual([]);
  });

  /**
   * When the session carries no profile the chip must say so rather than
   * inventing one. Blank is honest; "admin" is not.
   */
  it("has an explicit fallback for a session with no stored profile", () => {
    const s = code();
    expect(
      /meLoaded|\?\?\s*""|:\s*""/.test(s),
      "no fallback path — if getUser() returns null the chip should show that it " +
        "does not know, not a default identity",
    ).toBe(true);
  });
});
