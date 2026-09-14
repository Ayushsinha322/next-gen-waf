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
 * The rest of the product, as a RATCHET rather than a gate.
 *
 * The console is not the only thing a customer reads. The data plane serves a
 * browser-check page and a CAPTCHA page to the protected site's own VISITORS —
 * members of the public, who have no idea what any of this is called — and both
 * carry a logo. The control plane puts a name in every password-reset email, in
 * the Slack and webhook alert payloads, and in the TOTP enrolment URI, which is
 * the label that then sits in an administrator's authenticator app for as long
 * as the account exists.
 *
 * Every one of those is wrong today, and the email templates are worse than
 * wrong: they still use the name that Swaraj Kavach replaced.
 *
 * Fixing them is a decision, not a rename — changing the TOTP issuer changes
 * what existing authenticator entries are called, and the alert payload fields
 * are consumed by whatever the customer wired them into. So this does not fail
 * on what is already there. It fails if the count GROWS, which stops the
 * problem spreading while the decision is pending, and it lists the sites so
 * they cannot be quietly forgotten the way the console's nine were.
 *
 * When one is fixed, lower its number here. When the last one goes, delete the
 * inventory and fold these paths into the gate above.
 */
const KNOWN_OUTSIDE_CONSOLE: Record<string, number> = {
  // Shown to the PROTECTED SITE'S VISITORS, not to an operator.
  "crates/sentinel-proxy/src/captcha.rs": 1, // the CAPTCHA page logo
  "crates/sentinel-proxy/src/challenge.rs": 1, // the browser-check page logo
  "crates/sentinel-proxy/src/lib.rs": 1, // the 429 rate-limit body
  // Shown to an ADMINISTRATOR, and durable once delivered.
  "control-plane/cmd/controllerd/handlers.go": 1, // TOTP issuer, lands in the authenticator app
  "control-plane/internal/mailer/templates.go": 14, // password-reset mail, SUPERSEDED name
  "control-plane/internal/mailer/mailer.go": 1, // mail From name, SUPERSEDED name
  "control-plane/internal/notify/senders.go": 2, // Slack/webhook alert title and footer
  "control-plane/cmd/controllerd/notify_handlers.go": 1, // test-alert summary
  // Operator-side tooling, where the codename is defensible.
  "control-plane/cmd/sentinelctl/main.go": 1, // the CLI is itself named for the codename
  "crates/sentinel-cli/src/main.rs": 2,
  "crates/sentinel-bin/src/main.rs": 1, // a startup log line, never a screen
  "crates/sentinel-proxy/src/http3.rs": 2, // test fixture payloads
};

describe("the product name outside the console does not spread further", () => {
  const files = sourceFiles(REPO, /\.(go|rs)$/);

  it("finds source files to check", () => {
    expect(files.length).toBeGreaterThan(50);
  });

  it("has no more occurrences than the inventory records", () => {
    const found: Record<string, number> = {};
    for (const file of files) {
      const rel = file.slice(REPO.length + 1);
      const src = stripComments(readFileSync(file, "utf8"));
      const n = src
        .split("\n")
        .filter((line) => SUPERSEDED.some((re) => re.test(line))).length;
      if (n > 0) found[rel] = n;
    }

    const grew: string[] = [];
    for (const [file, n] of Object.entries(found)) {
      const allowed = KNOWN_OUTSIDE_CONSOLE[file] ?? 0;
      if (n > allowed) {
        grew.push(`${file}: ${n} occurrence(s), inventory allows ${allowed}`);
      }
    }
    expect(
      grew,
      "A new product-name string appeared outside the console. Use the one " +
        "name, or add it to KNOWN_OUTSIDE_CONSOLE with a reason:\n" +
        grew.join("\n"),
    ).toEqual([]);

    // Ratchet the other way too: once a site is fixed, the number must come
    // down, or the inventory turns into a list of things that are no longer
    // true and nobody trusts it.
    const stale = Object.entries(KNOWN_OUTSIDE_CONSOLE)
      .filter(([file, n]) => (found[file] ?? 0) < n)
      .map(([file, n]) => `${file}: inventory says ${n}, found ${found[file] ?? 0}`);
    expect(
      stale,
      `Lower these numbers — the strings are gone:\n${stale.join("\n")}`,
    ).toEqual([]);
  });
});
