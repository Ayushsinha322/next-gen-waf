import { describe, it, expect } from "vitest";
import { certStoreKeysFor, servingCertFor, certCoversHost } from "../siteConfig";

/**
 * These mirror `resolve_live` in crates/sentinel-proxy/src/tls/cert_store.rs.
 * If that function's matching ever changes, these tests must change with it —
 * the console's whole claim here is "this is what the WAF will actually serve",
 * and a console that confidently names the wrong certificate is worse than one
 * that says nothing.
 *
 * The case that prompted all of this: uat-console.swarajcloud.dev was being
 * served a GlobalSign wildcard from the shared store while the site form showed
 * an empty selector, which reads as "no certificate".
 */
describe("certStoreKeysFor — the keys the data plane tries, in order", () => {
  it("tries the exact name first, then the first label wildcarded", () => {
    expect(certStoreKeysFor("uat-console.swarajcloud.dev"))
      .toEqual(["uat-console.swarajcloud.dev", "*.swarajcloud.dev"]);
  });

  it("wildcards only one label deep, like the resolver", () => {
    expect(certStoreKeysFor("a.b.example.com")).toEqual(["a.b.example.com", "*.b.example.com"]);
  });

  it("offers no wildcard for an apex name — `*.` alone would match everything", () => {
    expect(certStoreKeysFor("example.com")).toEqual(["example.com", "*.com"]);
    expect(certStoreKeysFor("localhost")).toEqual(["localhost"]);
  });

  it("normalises case and a trailing dot", () => {
    expect(certStoreKeysFor("  UAT-Console.SwarajCloud.dev. "))
      .toEqual(["uat-console.swarajcloud.dev", "*.swarajcloud.dev"]);
  });

  it("returns nothing for an empty host", () => {
    expect(certStoreKeysFor("")).toEqual([]);
    expect(certStoreKeysFor("   ")).toEqual([]);
  });
});

describe("servingCertFor — which stored certificate the WAF would serve", () => {
  const exact = { domain: "uat-console.swarajcloud.dev", san: ["uat-console.swarajcloud.dev"] };
  const wildcard = { domain: "*.swarajcloud.dev", san: ["*.swarajcloud.dev"] };
  const other = { domain: "shop.example.com", san: ["shop.example.com"] };

  it("finds the certificate stored under the exact name", () => {
    expect(servingCertFor([other, exact], "uat-console.swarajcloud.dev")).toBe(exact);
  });

  it("falls back to a wildcard stored key", () => {
    expect(servingCertFor([other, wildcard], "uat-console.swarajcloud.dev")).toBe(wildcard);
  });

  it("prefers the exact key over the wildcard, as the resolver does", () => {
    expect(servingCertFor([wildcard, exact], "uat-console.swarajcloud.dev")).toBe(exact);
  });

  it("returns null when nothing matches — the WAF self-signs on demand", () => {
    expect(servingCertFor([other], "uat-console.swarajcloud.dev")).toBeNull();
    expect(servingCertFor([], "uat-console.swarajcloud.dev")).toBeNull();
  });

  it("never matches on SANs — the resolver does not read them", () => {
    // Stored under an unrelated key, but presenting the name. The data plane
    // would NOT serve this for uat-console, so neither may the console claim it.
    const sanOnly = { domain: "legacy-bundle", san: ["uat-console.swarajcloud.dev"] };
    expect(servingCertFor([sanOnly], "uat-console.swarajcloud.dev")).toBeNull();
  });

  it("does not let a wildcard reach two labels down", () => {
    expect(servingCertFor([wildcard], "a.b.swarajcloud.dev")).toBeNull();
  });
});

describe("certCoversHost — whether the served certificate presents the name", () => {
  it("is a separate question from which certificate is served", () => {
    // The real case: served by key *.swarajcloud.dev, and it does present it.
    expect(certCoversHost(["*.swarajcloud.dev"], "uat-console.swarajcloud.dev")).toBe(true);
    // A certificate can be served and still not present the name — browsers
    // then warn, which is what the amber line in the wizard says.
    expect(certCoversHost(["shop.example.com"], "uat-console.swarajcloud.dev")).toBe(false);
  });

  it("wildcards do not cover the apex", () => {
    expect(certCoversHost(["*.swarajcloud.dev"], "swarajcloud.dev")).toBe(false);
  });
});
