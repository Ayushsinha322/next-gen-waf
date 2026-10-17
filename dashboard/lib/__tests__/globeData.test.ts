import { describe, it, expect } from "vitest";
import { GLOBE_STEP, GLOBE_ROW_N, GLOBE_ROWS, GLOBE_CODES, GLOBE_LABELS } from "../globeData";
import { countryAt } from "@/components/dashboard/Globe";

// lib/globeData.ts is generated (dashboard/scripts/bake-globe.py). These pin the
// shape the globe's decoder relies on, and the borders a customer would notice.
describe("globe dataset", () => {
  it("has one band per step of latitude, each with a stored dot count", () => {
    expect(GLOBE_ROWS.length).toBe(Math.round(180 / GLOBE_STEP));
    expect(GLOBE_ROW_N.length).toBe(GLOBE_ROWS.length);
    GLOBE_ROW_N.forEach(n => expect(n).toBeGreaterThanOrEqual(1));
  });

  it("stores runs that stay inside their band, in order, with valid codes", () => {
    GLOBE_ROWS.forEach((r, i) => {
      expect(r.length % 3).toBe(0);
      let end = 0;
      for (let k = 0; k < r.length; k += 3) {
        expect(r[k]).toBeGreaterThanOrEqual(end);
        expect(r[k + 1]).toBeGreaterThan(0);
        end = r[k] + r[k + 1];
        expect(end).toBeLessThanOrEqual(GLOBE_ROW_N[i]);
        expect(r[k + 2]).toBeGreaterThanOrEqual(0);
        expect(r[k + 2]).toBeLessThan(GLOBE_CODES.length);
      }
    });
  });

  it("covers about as much of the sphere as the Earth's land does", () => {
    const cells = GLOBE_ROW_N.reduce((a, b) => a + b, 0);
    let land = 0;
    GLOBE_ROWS.forEach(r => { for (let k = 1; k < r.length; k += 3) land += r[k]; });
    expect(land / cells).toBeGreaterThan(0.27);
    expect(land / cells).toBeLessThan(0.31);
  });

  it("uses ISO alpha-2 codes, plus empty for land with no code", () => {
    GLOBE_CODES.forEach(c => expect(c === "" || /^[A-Z]{2}$/.test(c)).toBe(true));
    for (const [c, [lat, lon]] of Object.entries(GLOBE_LABELS)) {
      expect(c).toMatch(/^[A-Z]{2}$/);
      expect(Math.abs(lat)).toBeLessThanOrEqual(90);
      expect(Math.abs(lon)).toBeLessThanOrEqual(180);
    }
  });

  it("has a label point for small origins that have no dots of their own", () => {
    for (const c of ["SG", "HK", "MO", "BH", "MT"]) expect(GLOBE_LABELS[c]).toBeDefined();
  });

  it("puts places in the right country, with India's official boundaries", () => {
    expect(countryAt(35.2, 79.3)).toBe("IN");   // Aksai Chin
    expect(countryAt(35.9, 74.3)).toBe("IN");   // Gilgit
    expect(countryAt(28.0, 94.5)).toBe("IN");   // Arunachal Pradesh
    expect(countryAt(28.6, 77.2)).toBe("IN");   // Delhi
    expect(countryAt(31.5, 74.3)).toBe("PK");   // Lahore
    expect(countryAt(48.9, 2.35)).toBe("FR");
    expect(countryAt(-33.8, 150.5)).toBe("AU");
    expect(countryAt(31, -99)).toBe("US");
    expect(countryAt(30, -40)).toBeNull();      // mid-Atlantic
  });
});
