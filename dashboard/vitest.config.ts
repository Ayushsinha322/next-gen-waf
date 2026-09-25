import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  // `@/…` is the project's import alias, declared in tsconfig.json. Vitest does
  // NOT read tsconfig paths, so without this every test that reaches a module
  // importing `@/…` fails to load — not as an assertion failure but as a
  // collection error, which is easy to skim past in CI output.
  //
  // That is exactly what happened: a lib module began importing
  // `@/lib/version` on 2026-09-10, and the gating `npm run test` step has been
  // red on main ever since. Keep this in step with tsconfig.json's `paths`.
  resolve: {
    alias: {
      "@": fileURLToPath(new URL(".", import.meta.url)),
    },
  },
  test: {
    // Pure-logic unit tests run in Node (no DOM needed).
    environment: "node",
    include: ["lib/**/*.test.ts", "components/**/*.test.{ts,tsx}"],
    // Exclude the app dir / node_modules from collection.
    exclude: ["node_modules", ".next"],
  },
});
