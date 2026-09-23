/**
 * Validation for the site policy's network lists, mirroring the control plane
 * (control-plane/cmd/controllerd/net_validate.go), which is the authority.
 *
 * Both exist because the data plane silently skipped what it could not parse: a
 * block list reading "203.0.113.7" (a bare IP — the wizard's own placeholder) and a
 * country "USA" were saved, shown as applied, and blocked nothing.
 */

/** Every ISO 3166-1 alpha-2 code, plus XK (Kosovo, as DB-IP and MaxMind assign it). */
export const ISO_COUNTRY_CODES = `
AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL
BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV
CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD
GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM
IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK
LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW
MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR
PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS
ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY
UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW XK
`;

const ISO_SET = new Set(ISO_COUNTRY_CODES.split(/\s+/).filter(Boolean));

const COUNTRY_HINTS: Record<string, string> = {
  UK: "GB", USA: "US", GBR: "GB", IND: "IN", CHN: "CN", RUS: "RU",
  DEU: "DE", FRA: "FR", PAK: "PK", BGD: "BD", NPL: "NP", LKA: "LK",
  ARE: "AE", SAU: "SA", SGP: "SG", JPN: "JP", KOR: "KR", PRK: "KP",
  BRA: "BR", CAN: "CA", AUS: "AU", IRN: "IR", TUR: "TR", UKR: "UA",
};

export function isCountryCode(code: string): boolean {
  return ISO_SET.has(code.trim().toUpperCase());
}

/** What is wrong with a country entry, in words, or null when it is valid. */
export function countryCodeProblem(code: string): string | null {
  const c = code.trim().toUpperCase();
  if (ISO_SET.has(c)) return null;
  const hint = COUNTRY_HINTS[c];
  return hint
    ? `"${code}" is not a country code this WAF can match — did you mean "${hint}"?`
    : `"${code}" is not an ISO 3166-1 two-letter country code, so it can never match a request.`;
}

/** The country's English name, from the browser's own data; the code when unavailable. */
export function countryName(code: string): string {
  try {
    return new Intl.DisplayNames(["en"], { type: "region" }).of(code.toUpperCase()) ?? code;
  } catch {
    return code;
  }
}

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

function isIpv6(s: string): boolean {
  if (!/^[0-9a-fA-F:.]+$/.test(s) || !s.includes(":")) return false;
  if ((s.match(/::/g) ?? []).length > 1) return false;
  const tail = s.split(":").pop() ?? "";
  const hasV4Tail = tail.includes(".");
  if (hasV4Tail && !IPV4.test(tail)) return false;
  const groups = s.split(":").filter((g, i, a) => !(g === "" && (i === 0 || i === a.length - 1)));
  const words = groups.filter(g => g !== "").length + (hasV4Tail ? 1 : 0);
  if (groups.some(g => g !== "" && !g.includes(".") && !/^[0-9a-fA-F]{1,4}$/.test(g))) return false;
  return s.includes("::") ? words < 8 : words === 8;
}

/** A bare address (one host) or a CIDR range, IPv4 or IPv6 — what the data plane accepts. */
export function isIpOrCidr(entry: string): boolean {
  const e = entry.trim();
  const [addr, prefix, extra] = e.split("/");
  if (extra !== undefined || !addr) return false;
  const v4 = IPV4.test(addr);
  const v6 = !v4 && isIpv6(addr);
  if (!v4 && !v6) return false;
  if (prefix === undefined) return true;
  if (!/^\d{1,3}$/.test(prefix)) return false;
  return Number(prefix) <= (v4 ? 32 : 128);
}
