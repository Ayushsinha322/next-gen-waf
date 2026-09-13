/**
 * Geo helpers — turn an ISO 3166-1 alpha-2 country code into a flag emoji and a
 * human-readable name, with zero lookup tables and zero network calls.
 *
 *  • Flag: each ASCII letter maps to its Regional-Indicator Symbol codepoint;
 *    two of them render as the country's flag on every modern platform.
 *  • Name: Intl.DisplayNames (built into the JS runtime, incl. Node 18+ SSR).
 *
 * Everything degrades gracefully: an unknown / non-ISO value keeps its raw text
 * and shows a neutral globe, so the UI never renders a broken tofu box.
 */

const GLOBE = "\u{1F310}"; // 

// Intl.DisplayNames is constructed once (it is comparatively expensive) and
// reused. Guarded because very old runtimes / odd locales can throw.
let _regionNames: Intl.DisplayNames | null = null;
function regionNames(): Intl.DisplayNames | null {
  if (_regionNames) return _regionNames;
  try {
    _regionNames = new Intl.DisplayNames(["en"], { type: "region" });
  } catch {
    _regionNames = null;
  }
  return _regionNames;
}

/** True for a plausible ISO 3166-1 alpha-2 code (two ASCII letters). */
export function isCountryCode(cc: string | null | undefined): cc is string {
  return !!cc && /^[A-Za-z]{2}$/.test(cc);
}

/**
 * Flag emoji for a 2-letter country code. Returns for anything that is not a
 * clean alpha-2 code (empty, "XX", "unknown", a full name, an IP, …).
 */
export function countryFlag(cc: string | null | undefined): string {
  if (!isCountryCode(cc)) return GLOBE;
  const up = cc.toUpperCase();
  // Private-use / placeholder codes that have no real flag glyph.
  if (up === "XX" || up === "ZZ" || up === "T1") return GLOBE;
  const cp = [...up].map((c) => 0x1f1e6 + (c.charCodeAt(0) - 65));
  return String.fromCodePoint(...cp);
}

/**
 * English display name for a country code ("US" → "United States"). Falls back
 * to the raw value when it is not a resolvable code.
 */
export function countryName(cc: string | null | undefined): string {
  if (!cc) return "Unknown";
  if (!isCountryCode(cc)) return cc; // already a name or opaque token
  const up = cc.toUpperCase();
  if (up === "XX" || up === "ZZ") return "Unknown";
  const dn = regionNames();
  try {
    return dn?.of(up) ?? up;
  } catch {
    return up;
  }
}

/** Convenience: `{ flag, name }` for a code, computed once. */
export function country(cc: string | null | undefined): { flag: string; name: string } {
  return { flag: countryFlag(cc), name: countryName(cc) };
}
