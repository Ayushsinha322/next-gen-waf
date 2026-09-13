import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

/**
 * No JSX attribute may be swallowed into the string next to it.
 *
 * A misplaced quote or backtick turns the following attribute into part of the
 * preceding value. It still compiles, still type-checks, and still renders —
 * it just renders the markup as prose. The Site Wizard shipped this on the
 * origin-host field:
 *
 *   <Field label={`Host #${i + 1} hint="The origin as the WAF reaches it …"`}>
 *
 * so the reverse-proxy step displayed a label reading
 * `HOST #1 HINT="THE ORIGIN AS THE WAF REACHES IT — …"` in uppercase across
 * three lines, and the hint that was supposed to sit quietly under the input
 * never appeared. Its neighbours, Port and Weight, were written correctly, so
 * the page looked plainly broken next to them.
 *
 * It arrived in a commit that added hints to every field, which is exactly when
 * this happens: a bulk edit across many call sites, where one closing quote
 * lands on the wrong side and nothing downstream objects.
 *
 * This looks for an attribute-shaped fragment inside a string value. It is
 * deliberately narrow — it checks for the props this component set actually
 * uses, rather than anything containing an equals sign, because ordinary prose
 * does contain quotes.
 */

const ROOT = join(__dirname, "..", "..");
const SKIP = new Set(["node_modules", ".next", ".git", "dist", "coverage"]);

/** Props that take a plain string and sit beside other props on the same tag. */
const PROPS = [
  "hint",
  "label",
  "placeholder",
  "title",
  "desc",
  "sub",
  "blurb",
  "aria-label",
];

function sourceFiles(dir: string, acc: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (SKIP.has(entry)) continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) sourceFiles(full, acc);
    else if (/\.tsx?$/.test(entry)) acc.push(full);
  }
  return acc;
}

describe("JSX attributes are not swallowed into neighbouring strings", () => {
  const files = sourceFiles(ROOT).filter(f => !f.includes(`${join("lib", "__tests__")}`));

  it("finds source files to check", () => {
    expect(files.length).toBeGreaterThan(50);
  });

  for (const prop of PROPS) {
    it(`no string value contains a stray ${prop}= attribute`, () => {
      // Matches  label="… hint="…   and  label={`… hint="…
      // i.e. the named prop appearing INSIDE an already-open string or template.
      const inDoubleQuoted = new RegExp(`=\\s*"[^"\\n]*\\s${prop}=`, "g");
      const inTemplate = new RegExp("=\\s*\\{`[^`\\n]*\\s" + prop + "=", "g");

      const offenders: string[] = [];
      for (const file of files) {
        readFileSync(file, "utf8")
          .split("\n")
          .forEach((line, i) => {
            if (inDoubleQuoted.test(line) || inTemplate.test(line)) {
              offenders.push(
                `${file.slice(ROOT.length + 1)}:${i + 1}  ${line.trim().slice(0, 100)}`,
              );
            }
            inDoubleQuoted.lastIndex = 0;
            inTemplate.lastIndex = 0;
          });
      }

      expect(
        offenders,
        `A "${prop}" attribute is inside the previous string, so it renders as text ` +
          `instead of taking effect. Check the closing quote:\n${offenders.join("\n")}`,
      ).toEqual([]);
    });
  }
});
