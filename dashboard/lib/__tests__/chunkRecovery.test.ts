import { describe, it, expect } from "vitest";
import { isChunkFailure } from "../chunkFailure";

describe("chunk-failure detection", () => {
  it("matches the ways a replaced build surfaces in a stale tab", () => {
    for (const m of [
      "ChunkLoadError: Loading chunk 493 failed.",
      "Loading chunk app/layout failed.",
      "Loading CSS chunk 12 failed",
      "TypeError: Failed to fetch dynamically imported module: https://host/_next/static/chunks/x.js",
      "Importing a module script failed. /_next/static/chunks/y.js",
    ]) {
      expect(isChunkFailure(m)).toBe(true);
    }
  });

  it("does NOT match ordinary application errors, which must stay visible", () => {
    for (const m of [
      "TypeError: Cannot read properties of undefined (reading 'map')",
      "API /sites: 500 internal error",
      "Failed to fetch",
      "Session expired — redirecting to login",
      "ResizeObserver loop completed with undelivered notifications",
      "Failed to fetch dynamically imported module: https://cdn.example.com/thing.js",
    ]) {
      expect(isChunkFailure(m)).toBe(false);
    }
  });
});
