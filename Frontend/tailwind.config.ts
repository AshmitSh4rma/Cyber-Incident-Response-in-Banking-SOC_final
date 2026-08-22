import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./hooks/**/*.{js,ts,jsx,tsx,mdx}",
    "./lib/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "sans-serif"],
        mono: ["JetBrains Mono", "monospace"],
      },
      colors: {
        background: "#060806",
        surface: "#0a0e0a",
        raised: "#111611",
        border: "#1a261a",
        textPrimary: "#e0e8e0",
        textMuted: "#7f937f",
        critical: "#d03b3b",
        high: "#ec835a",
        medium: "#fab219",
        low: "#3b9eff",
      },
    },
  },
};

export default config;