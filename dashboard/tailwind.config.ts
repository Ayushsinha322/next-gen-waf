import type { Config } from "tailwindcss";

/**
 * The dashboard is styled almost entirely by hand-written CSS in app/globals.css,
 * which owns the design tokens (colour, type scale, terminal palette) as CSS
 * custom properties. Tailwind is kept for layout utilities only.
 *
 * This file previously carried a SECOND, competing design system: a `sentinel`
 * colour palette (#060912 / #C8001E / #00C8F0), an Orbitron display family, four
 * neon `*-glow` box-shadows and shimmer/glow/blink/border-glow keyframes. All of
 * it was dead — verified zero call sites across app/, components/ and lib/ — and
 * it disagreed with globals.css on every shared colour, so anything that started
 * using it would have split the UI across two palettes.
 *
 * Fonts resolve to the same variables globals.css defines, so `font-mono` as a
 * Tailwind class and `var(--font-mono)` in CSS are guaranteed to be the same
 * face. Do not reintroduce a literal family name here.
 */
const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./lib/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ["var(--font-sans)"],
        mono: ["var(--font-mono)"],
      },
    },
  },
  plugins: [],
};

export default config;
