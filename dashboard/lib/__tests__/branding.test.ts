import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { PRODUCT_NAME } from "../version";

/**
 * The product has ONE name, written in ONE place.
 *
 * `sentinel` is the source codename — the cargo crates, the image tags, the
 * container names, the log targets, the env var prefix, the operator CLI. It is
 * not the product name and must never reach a screen a customer looks at.
 * lib/version.ts has said exactly that in a comment since the name was settled.
 * A comment is not a guard, and the comment lost: nine strings were still
 * shipping the codename to customers when this file was written, including the
 * copilot introducing itself as "Sentinel AI Copilot" on every visit and two
 * paragraphs of Settings prose.
 *
 * They survived because nothing checked. The emoji sweep got noEmoji.test.ts
 * and stayed clean; branding got a resolution, a constant, and no test, so it
 * went two-thirds applied and stopped. This is that missing half.
 *
 * WHAT IS ALLOWED, and why each is not branding:
 *
 *   - comments. Stripped before matching, so this file's own explanation and
 *     the history notes in lib/version.ts cannot fail the check they document.
 *     (A guard that matches its own documentation has happened twice here.)
 *   - HTTP header names like `X-Sentinel-Signature`. Those are wire protocol.
 *     A customer configures them on their webhook receiver and in their SIEM;
 *     renaming one breaks a live integration, and it is not a product name any
 *     more than `X-Forwarded-For` is a product name.
 *   - `SENTINEL_*` env vars and lowercase `sentinel-*` identifiers. Neither
 *     matches a capitalised standalone `Sentinel`, so neither needs an
 *     exception — noted here only so the next reader does not add one.
 */

const ROOT = join(__dirname, "..", "..");
const REPO = join(ROOT, "..");
const SKIP = new Set(["node_modules", ".next", ".git", "dist", "coverage", "target", "docs"]);

/** The codename, as a standalone capitalised word. */
const CODENAME = /\bSentinel\b/;

/** Names this product has been called before. None may reappear. */
const SUPERSEDED = [/Next-Gen ESDS ?WAF/, /\bESDSWAF\b/, /\bSentinel WAF\b/];

/** Remove block and line comments, so prose explaining a rule cannot break it. */
function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
}

/** Remove wire identifiers, which are protocol rather than branding. */
function stripWireNames(src: string): string {
  return src.replace(/\bX-Sentinel-[A-Za-z-]+/g, "");
}

function sourceFiles(dir: string, exts: RegExp, acc: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (SKIP.has(entry)) continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) sourceFiles(full, exts, acc);
    else if (exts.test(entry)) acc.push(full);
  }
  return acc;
}

const SELF = join("lib", "__tests__", "branding.test.ts");

describe("the console shows one product name", () => {
  const files = sourceFiles(ROOT, /\.(ts|tsx)$/).filter((f) => !f.endsWith(SELF));

  it("finds source files to check", () => {
    // Guards the guard: a broken walk makes every assertion below pass silently.
    expect(files.length).toBeGreaterThan(50);
  });

  it("names the product Swaraj Kavach", () => {
    expect(PRODUCT_NAME).toBe("Swaraj Kavach");
  });

  it("shows the source codename nowhere in the console", () => {
    const offenders: string[] = [];
    for (const file of files) {
      const src = stripWireNames(stripComments(readFileSync(file, "utf8")));
      src.split("\n").forEach((line, i) => {
        if (CODENAME.test(line)) {
          offenders.push(`${file.slice(ROOT.length + 1)}:${i + 1}  ${line.trim().slice(0, 80)}`);
        }
      });
    }
    expect(
      offenders,
      "`sentinel` is the source codename, not the product. Use PRODUCT_NAME " +
        `from lib/version.ts:\n${offenders.join("\n")}`,
    ).toEqual([]);
  });

  it("shows no name this product used to have", () => {
    const offenders: string[] = [];
    for (const file of files) {
      const src = stripComments(readFileSync(file, "utf8"));
      src.split("\n").forEach((line, i) => {
        if (SUPERSEDED.some((re) => re.test(line))) {
          offenders.push(`${file.slice(ROOT.length + 1)}:${i + 1}  ${line.trim().slice(0, 80)}`);
        }
      });
    }
    expect(
      offenders,
      `This name was replaced by ${PRODUCT_NAME}:\n${offenders.join("\n")}`,
    ).toEqual([]);
  });

  /**
   * The name must be written ONCE. A second literal is how the last drift
   * happened: five screens said one thing, the copilot prompt another, the
   * browser tab a third, and every one of them looked correct on its own.
   */
  it("writes the product name in exactly one place", () => {
    const offenders: string[] = [];
    for (const file of files) {
      if (file.endsWith(join("lib", "version.ts"))) continue;
      const src = stripComments(readFileSync(file, "utf8"));
      if (src.includes(PRODUCT_NAME)) {
        offenders.push(file.slice(ROOT.length + 1));
      }
    }
    expect(
      offenders,
      `Import PRODUCT_NAME instead of writing "${PRODUCT_NAME}" again:\n${offenders.join("\n")}`,
    ).toEqual([]);
  });
});

/**
 * The rest of the product.
 *
 * The console was never the whole problem. The data plane serves a
 * browser-check page and a CAPTCHA page to the PROTECTED SITE'S OWN VISITORS —
 * members of the public, who have never heard of either name — and both carried
 * the codename as their logo, as did the 429 body. The control plane put a name
 * in every password-reset email, in the Slack and webhook alert payloads, and in
 * the TOTP enrolment URI, which then sits in an administrator's authenticator
 * app for as long as the account exists. The mail templates were worse than
 * wrong: they still used the name this one replaced.
 *
 * All of it is fixed. Rust reads the name from `sentinel_core::product_name!()`
 * — a macro, because those pages are compile-time `const &str` and `concat!`
 * takes literals — and Go from `internal/version.Name`. So this is a GATE now,
 * not the inventory it started as: nothing outside the console may name the
 * product by hand either.
 *
 * Comments are exempt and stay that way. A crate's `//!` header calling itself
 * "sentinel-ml — ML engine for Sentinel WAF" is describing the source tree,
 * which is genuinely what `sentinel` names. The three `///` lines in
 * sentinel-cli that reach `--help` are deliberately left as well: they describe
 * a binary called `sentinel` reading `~/.config/sentinel/sentinel.yaml`, and
 * renaming the prose while the paths keep the codename reads worse, not better.
 */
describe("nothing outside the console names the product by hand", () => {
  const files = sourceFiles(REPO, /\.(go|rs)$/);

  it("finds source files to check", () => {
    expect(files.length).toBeGreaterThan(50);
  });

  /** The two files that DEFINE the name, mirroring lib/version.ts above. */
  const DEFINITIONS = [
    join("control-plane", "internal", "version", "version.go"),
    join("crates", "sentinel-core", "src", "lib.rs"),
  ];

  it("defines the name in both places, so the gate has something to point at", () => {
    // Guards the guard the other way: if a definition is renamed or moved, the
    // exemption below would silently start exempting nothing, and every call
    // site could go back to literals without this suite noticing.
    for (const d of DEFINITIONS) {
      const f = files.find((x) => x.endsWith(d));
      expect(f, `${d} not found — the exemption below is now pointing at nothing`).toBeTruthy();
      expect(readFileSync(f!, "utf8")).toContain(PRODUCT_NAME);
    }
  });

  it("uses the shared constant, not a literal", () => {
    const offenders: string[] = [];
    for (const file of files) {
      if (DEFINITIONS.some((d) => file.endsWith(d))) continue;
      // A test that asserts a name is ABSENT has to write that name down.
      // control-plane/internal/mailer/templates_branding_test.go is the guard
      // for the reset emails and lists every forbidden spelling; matching it
      // here would be the third time in this repo that a rule failed on its own
      // documentation. Rust `#[cfg(test)]` modules are inline and stay covered,
      // which is stricter and costs nothing now that the h3 fixtures are clean.
      if (file.endsWith("_test.go")) continue;
      const src = stripComments(readFileSync(file, "utf8"));
      src.split("\n").forEach((line, i) => {
        if (SUPERSEDED.some((re) => re.test(line)) || line.includes(PRODUCT_NAME)) {
          offenders.push(`${file.slice(REPO.length + 1)}:${i + 1}  ${line.trim().slice(0, 80)}`);
        }
      });
    }
    expect(
      offenders,
      "Rust: sentinel_core::product_name!() inside concat!, else PRODUCT_NAME. " +
        "Go: internal/version.Name.\n" +
        offenders.join("\n"),
    ).toEqual([]);
  });
});
