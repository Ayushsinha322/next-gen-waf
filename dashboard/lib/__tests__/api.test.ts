import { describe, it, expect } from "vitest";
import { eventQS } from "../api";

describe("eventQS", () => {
  it("drops undefined, null, and empty-string values", () => {
    expect(eventQS({ a: "x", b: undefined, c: "", d: 0, e: null as unknown as undefined })).toBe("a=x&d=0");
  });

  it("coerces numbers and URL-encodes values", () => {
    const qs = eventQS({ from: 1000, q: "a b&c" });
    expect(qs).toContain("from=1000");
    expect(qs).toContain("q=a+b%26c");
  });

  it("returns an empty string when every value is blank", () => {
    expect(eventQS({ a: undefined, b: "", c: null as unknown as undefined })).toBe("");
  });
});
