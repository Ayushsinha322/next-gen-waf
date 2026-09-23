import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ISO_COUNTRY_CODES, isCountryCode, countryCodeProblem, isIpOrCidr } from "../netValidate";

const codes = (s: string) => s.split(/\s+/).filter(Boolean).sort();

describe("the country list agrees with the control plane", () => {
  it("same codes as net_validate.go", () => {
    const go = readFileSync(join(__dirname, "../../../control-plane/cmd/controllerd/net_validate.go"), "utf8");
    const m = go.match(/const isoCountryCodes = `([^`]*)`/);
    expect(m, "isoCountryCodes not found in net_validate.go").toBeTruthy();
    expect(codes(ISO_COUNTRY_CODES)).toEqual(codes(m![1]));
    expect(codes(ISO_COUNTRY_CODES)).toHaveLength(250);
  });
});

describe("country codes", () => {
  it("accepts real codes in any case, and XK", () => {
    for (const c of ["IN", "us", "Gb", "XK", " NP "]) expect(isCountryCode(c), c).toBe(true);
  });
  it("refuses the code the audit stored, and says what was meant", () => {
    expect(isCountryCode("USA")).toBe(false);
    expect(countryCodeProblem("USA")).toMatch(/did you mean "US"/);
    expect(countryCodeProblem("UK")).toMatch(/did you mean "GB"/);
    expect(countryCodeProblem("Mars")).toMatch(/two-letter/);
    expect(countryCodeProblem("IN")).toBeNull();
  });
});

describe("IP / CIDR entries", () => {
  it("accepts what the data plane accepts — above all a bare address", () => {
    for (const e of ["203.0.113.7", "203.0.113.0/24", "10.0.0.0/8", "0.0.0.0/0", " 10.1.2.3 ",
                     "2001:db8::5", "2001:db8::/32", "::1", "::ffff:192.0.2.1", "fe80::1/64"]) {
      expect(isIpOrCidr(e), e).toBe(true);
    }
  });
  it("refuses what the data plane would silently skip", () => {
    for (const e of ["not-an-ip", "", "300.1.1.1", "10.0.0.0/33", "10.0.0.1/8x", "1.2.3", "1.2.3.4/",
                     "2001:db8::/129", "2001::db8::1", "gggg::1", "1.2.3.4/24/1"]) {
      expect(isIpOrCidr(e), e).toBe(false);
    }
  });
});
