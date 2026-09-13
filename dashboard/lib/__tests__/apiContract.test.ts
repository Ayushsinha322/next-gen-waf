import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * The console must only read fields the control plane actually emits.
 *
 * This is the most repeated defect in the product and it is invisible by
 * construction: reading a field that does not exist yields `undefined`, React
 * renders `undefined` as nothing at all, and the column looks completely
 * plausible while being permanently wrong. Nothing throws, nothing logs, and
 * TypeScript is happy because the interface it checks against is the thing that
 * is wrong.
 *
 * Four instances found so far, all of them shipped:
 *
 *   - the 2FA column read `twofa`, a name that never existed, and showed
 *     "None" for every user
 *   - the Last Login column read `last_login` instead of `last_login_at`, so it
 *     read "Never" for everyone including the person signed in
 *   - the API-keys table read `scope` and `last_used` instead of `scopes` and
 *     `last_used_at`, so both columns were blank on every row and an unused key
 *     looked identical to one used a minute ago
 *   - the create-key response declared the secret INSIDE `api_key` when the
 *     handler returns it as a sibling, so the one-time reveal never rendered
 *     and the only copy of the key was discarded
 *
 * So this test reads the Go structs and asserts the TypeScript mirrors them.
 * It parses source text rather than importing anything, because the point is to
 * compare two files that have no build-time relationship at all.
 */

const REPO = join(__dirname, "..", "..", "..");

/** json tag names on a Go struct, e.g. `Scopes []string \`json:"scopes"\`` -> "scopes". */
function goStructFields(relPath: string, structName: string): Set<string> {
  const src = readFileSync(join(REPO, relPath), "utf8");
  const start = src.indexOf(`type ${structName} struct {`);
  if (start === -1) throw new Error(`Go struct ${structName} not found in ${relPath}`);
  const end = src.indexOf("\n}", start);
  const body = src.slice(start, end);

  const fields = new Set<string>();
  for (const line of body.split("\n")) {
    const m = line.match(/`json:"([^",]+)/);
    // `json:"-"` means deliberately not serialised.
    if (m && m[1] !== "-") fields.add(m[1]);
  }
  if (fields.size === 0) throw new Error(`no json tags parsed from ${structName}`);
  return fields;
}

/** Field names declared on an exported TS interface in lib/api.ts. */
function tsInterfaceFields(interfaceName: string): { name: string; optional: boolean }[] {
  const src = readFileSync(join(REPO, "dashboard", "lib", "api.ts"), "utf8");
  const start = src.indexOf(`export interface ${interfaceName} {`);
  if (start === -1) throw new Error(`TS interface ${interfaceName} not found`);
  const end = src.indexOf("\n}", start);
  const body = src.slice(start, end);

  const out: { name: string; optional: boolean }[] = [];
  let inBlockComment = false;
  for (const raw of body.split("\n").slice(1)) {
    const line = raw.trim();
    if (inBlockComment) {
      if (line.includes("*/")) inBlockComment = false;
      continue;
    }
    if (line.startsWith("/*")) {
      if (!line.includes("*/")) inBlockComment = true;
      continue;
    }
    if (line.startsWith("//") || line.startsWith("*") || line === "") continue;
    const m = line.match(/^([A-Za-z_][A-Za-z0-9_]*)(\??)\s*:/);
    if (m) out.push({ name: m[1], optional: m[2] === "?" });
  }
  if (out.length === 0) throw new Error(`no fields parsed from ${interfaceName}`);
  return out;
}

/** Remove block and line comments, so a search for a broken pattern cannot
 *  match the comment that documents why it was broken. */
function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
}

/** TS interface -> the Go struct it mirrors. */
const MIRRORS: { ts: string; goFile: string; goStruct: string }[] = [
  { ts: "UserRow", goFile: "control-plane/internal/db/user_store.go", goStruct: "UserRow" },
  { ts: "APIKeyRow", goFile: "control-plane/internal/db/apikey_store.go", goStruct: "APIKeyRow" },
];

describe("console field names match what the control plane emits", () => {
  for (const { ts, goFile, goStruct } of MIRRORS) {
    it(`${ts} only names fields present on Go ${goStruct}`, () => {
      const go = goStructFields(goFile, goStruct);
      const tsFields = tsInterfaceFields(ts);
      const unknown = tsFields.filter(f => !go.has(f.name)).map(f => f.name);

      expect(
        unknown,
        `these fields are read by the console but never emitted by the control plane, ` +
          `so they are permanently undefined and render as an empty cell: ` +
          `${unknown.join(", ")}. Go ${goStruct} emits: ${[...go].sort().join(", ")}`,
      ).toEqual([]);
    });

    it(`${ts} marks optional exactly what Go marks omitempty`, () => {
      const src = readFileSync(join(REPO, goFile), "utf8");
      const start = src.indexOf(`type ${goStruct} struct {`);
      const body = src.slice(start, src.indexOf("\n}", start));
      const omitempty = new Set<string>();
      for (const line of body.split("\n")) {
        const m = line.match(/`json:"([^",]+),omitempty"`/);
        if (m) omitempty.add(m[1]);
      }

      // A field Go may omit must be optional here, or the console will treat an
      // absent value as present and render "undefined" or crash on a method call.
      const shouldBeOptional = tsInterfaceFields(ts)
        .filter(f => omitempty.has(f.name) && !f.optional)
        .map(f => f.name);

      expect(
        shouldBeOptional,
        `Go marks these omitempty, so they are ABSENT rather than null when unset. ` +
          `Declare them optional in ${ts}: ${shouldBeOptional.join(", ")}`,
      ).toEqual([]);
    });
  }

  /**
   * The create-key response is not a row mirror, so it gets its own assertion.
   * This is the one that cost an operator the key itself.
   */
  it("the new API key is declared as a sibling of api_key, not a field on it", () => {
    // Comments are stripped before matching. The doc comment on the declaration
    // quotes the broken form in order to explain it, and an un-stripped search
    // found its own explanation and failed — the same way a lint rule that
    // matches its own documentation is useless.
    const api = stripComments(readFileSync(join(REPO, "dashboard", "lib", "api.ts"), "utf8"));
    const handlers = readFileSync(
      join(REPO, "control-plane", "cmd", "controllerd", "handlers.go"),
      "utf8",
    );

    // The handler returns {api_key: row, key: fullKey, warning: ...}.
    expect(handlers).toMatch(/"api_key":\s*row,/);
    expect(handlers).toMatch(/"key":\s*fullKey/);

    // So the declaration must not fold `key` into the row type.
    expect(
      api,
      "lib/api.ts declares the secret inside api_key. The handler returns it " +
        "alongside, so res.api_key.key is undefined and the one-time reveal " +
        "never renders.",
    ).not.toMatch(/api_key:\s*APIKeyRow\s*&\s*\{\s*key/);
    expect(api).toMatch(/api_key:\s*APIKeyRow;\s*key:\s*string/);
  });
});
