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
        "red-glow":    "0 0 18px rgba(200,0,30,.45)",
        "purple-glow": "0 0 18px rgba(124,47,191,.5)",
      },
      animation: {
        "pulse-slow": "pulse 2.5s ease-in-out infinite",
        "spin-slow":  "spin 0.8s linear infinite",
      },
    },
  },
  plugins: [],
};

export default config;
