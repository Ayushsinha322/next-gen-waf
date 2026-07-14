import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Pure-logic unit tests run in Node (no DOM needed).
    environment: "node",
    include: ["lib/**/*.test.ts", "components/**/*.test.{ts,tsx}"],
    // Exclude the app dir / node_modules from collection.
    exclude: ["node_modules", ".next"],
  },
});
