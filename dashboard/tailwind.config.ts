import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./lib/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        orbitron: ["Orbitron", "sans-serif"],
        mono: ["Share Tech Mono", "monospace"],
        jetbrains: ["JetBrains Mono", "monospace"],
        inter: ["Inter", "sans-serif"],
      },
      colors: {
        sentinel: {
          bg:     "#060912",
          bg2:    "#0A0D1F",
          red:    "#C8001E",
          "red-b":"#FF1A44",
          cyan:   "#00C8F0",
          green:  "#00C87A",
          amber:  "#FFAA00",
          purple: "#7C2FBF",
          text:   "#E4E8F4",
          text2:  "#8896B8",
          text3:  "#424E6A",
        },
      },
      boxShadow: {
        "cyan-glow":    "0 0 18px rgba(0,200,240,.4)",
        "red-glow":     "0 0 18px rgba(200,0,30,.45)",
        "purple-glow":  "0 0 18px rgba(124,47,191,.5)",
        "green-glow":   "0 0 14px rgba(0,200,122,.35)",
        "glass":        "0 8px 32px rgba(0,0,0,.3)",
        "glass-hover":  "0 12px 40px rgba(0,0,0,.4), 0 0 0 1px rgba(0,212,255,.08)",
      },
      animation: {
        "pulse-slow":  "pulse 2.5s ease-in-out infinite",
        "spin-slow":   "spin 0.8s linear infinite",
        "shimmer":     "shimmer 2s linear infinite",
        "glow":        "glow 3.5s ease-in-out infinite",
        "blink":       "blink 2s ease-in-out infinite",
        "border-glow": "borderGlow 3s ease-in-out infinite",
      },
      keyframes: {
        shimmer: {
          "0%":   { transform: "translateX(-100%)" },
          "100%": { transform: "translateX(100%)" },
        },
        glow: {
          "0%,100%": { boxShadow: "0 0 10px rgba(0,200,240,.35)" },
          "50%":     { boxShadow: "0 0 28px rgba(0,200,240,.65)" },
        },
        blink: {
          "0%,100%": { opacity: "1" },
          "50%":     { opacity: ".35" },
        },
        borderGlow: {
          "0%,100%": { borderColor: "rgba(0,212,255,0.12)" },
          "50%":     { borderColor: "rgba(0,212,255,0.35)" },
        },
      },
      backdropBlur: {
        glass: "22px",
      },
    },
  },
  plugins: [],
};

export default config;