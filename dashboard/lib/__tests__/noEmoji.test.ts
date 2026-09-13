import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

/**
 * The console renders no emoji.
 *
 * Not a style preference. Emoji were actively wrong here for four reasons:
 *
 *   - they are drawn by the operating system, so the product looked different
 *     on Windows, macOS and Linux, and screenshots in a customer's report never
 *     matched their screen;
 *   - they ignore the surrounding colour, so a toast could announce a failure
 *     under a green tick, and one did;
 *   - they do not scale with the type, so they sat at odd baselines and pushed
 *     table rows taller than their neighbours;
 *   - screen readers announce them by name, so the password field's visibility
 *     toggle was read out as "see-no-evil monkey".
 *
 * Use `components/ui/Icon.tsx` instead. Those are stroked paths that inherit
 * `currentColor`, scale with the type, and carry an accessible name only when
 * they stand alone.
 *
 * A few TEXT-presentation symbols are allowed, listed below. They are not
 * emoji: they render as glyphs in the page font, take the colour of the text
 * around them, and each is doing a job rather than decorating.
 */

/** Pictographs, transport, symbols, dingbats — the emoji blocks. */
const EMOJI =
  /[\u{1F300}-\u{1FAFF}\u{1F000}-\u{1F2FF}\u{2B00}-\u{2BFF}\u{2600}-\u{27BF}]/u;

/** Text-presentation symbols that are permitted, with why. */
const ALLOWED = new Set([
  "⚠", // warning sign, on inline error text
  "✓", // check, status
  "✔", // heavy check, status
  "✕", // multiplication x, close/remove control
  "✖", // heavy multiplication x
  "✗", // ballot x, status
  "✘", // heavy ballot x
  "○", // circle, the "off" half of a toggle pair
]);

/**
 * U+FE0F forces emoji presentation on a character that would otherwise be text,
 * so an allowed symbol followed by one is NOT allowed. This is how the warning
 * sign kept rendering as a colour emoji after the glyphs themselves were
 * removed.
 */
const VARIATION_SELECTOR = "️";

const ROOT = join(__dirname, "..", "..");
const SKIP = new Set(["node_modules", ".next", ".git", "dist", "coverage"]);

function sourceFiles(dir: string, acc: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (SKIP.has(entry)) continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) sourceFiles(full, acc);
    else if (/\.(ts|tsx|css)$/.test(entry)) acc.push(full);
  }
  return acc;
}

describe("the console renders no emoji", () => {
  const files = sourceFiles(ROOT);

  it("finds source files to check", () => {
    // Guards the guard: a broken walk would make every assertion below pass.
    expect(files.length).toBeGreaterThan(50);
  });

  it("contains no emoji", () => {
    const offenders: string[] = [];
    for (const file of files) {
      if (file.endsWith(join("lib", "__tests__", "noEmoji.test.ts"))) continue;
      const lines = readFileSync(file, "utf8").split("\n");
      lines.forEach((line, i) => {
        for (const ch of line) {
          if (EMOJI.test(ch) && !ALLOWED.has(ch)) {
            offenders.push(
              `${file.slice(ROOT.length + 1)}:${i + 1}  ${ch}  ${line.trim().slice(0, 70)}`,
            );
            break;
          }
        }
      });
    }
    expect(
      offenders,
      `Use components/ui/Icon.tsx instead of an emoji:\n${offenders.join("\n")}`,
    ).toEqual([]);
  });

  it("contains no variation selectors forcing emoji presentation", () => {
    const offenders: string[] = [];
    for (const file of files) {
      if (file.endsWith(join("lib", "__tests__", "noEmoji.test.ts"))) continue;
      const lines = readFileSync(file, "utf8").split("\n");
      lines.forEach((line, i) => {
        if (line.includes(VARIATION_SELECTOR)) {
          offenders.push(`${file.slice(ROOT.length + 1)}:${i + 1}  ${line.trim().slice(0, 70)}`);
        }
      });
    }
    expect(
      offenders,
      `U+FE0F makes a text symbol render as a colour emoji. Remove it:\n${offenders.join("\n")}`,
    ).toEqual([]);
  });

  it("toasts take no icon argument, so severity and icon cannot disagree", () => {
    const offenders: string[] = [];
    for (const file of files) {
      const src = readFileSync(file, "utf8");
      // showToast(msg, type) only. A third argument is the old per-call icon.
      const re = /showToast\((?:[^()"'`]|"[^"]*"|'[^']*'|`[^`]*`|\([^)]*\))*?,[^,()]*,/g;
      if (re.test(src) && !file.endsWith("noEmoji.test.ts")) {
        offenders.push(file.slice(ROOT.length + 1));
      }
    }
    expect(
      offenders,
      `showToast takes (message, severity). The icon follows the severity:\n${offenders.join("\n")}`,
    ).toEqual([]);
  });
});
