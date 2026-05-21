/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: "class",
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: {
          DEFAULT: "#07111f",
          secondary: "#0B1020",
        },
        surface: {
          DEFAULT: "#0f172a",
          elevated: "#1e293b",
        },
        accent: {
          cyan: "#00E5FF",
          "cyan-glow": "rgba(0, 229, 255, 0.15)",
        },
        danger: {
          DEFAULT: "#FF4D4D",
          glow: "rgba(255, 77, 77, 0.15)",
        },
        success: {
          DEFAULT: "#7CFF6B",
          glow: "rgba(124, 255, 107, 0.15)",
        },
        warning: {
          DEFAULT: "#FFB800",
          glow: "rgba(255, 184, 0, 0.15)",
        },
        muted: "#64748b",
        border: "rgba(148, 163, 184, 0.1)",
      },
      fontFamily: {
        mono: ["JetBrains Mono", "Fira Code", "monospace"],
        sans: ["Inter", "system-ui", "sans-serif"],
      },
      borderRadius: {
        xl: "16px",
        "2xl": "20px",
      },
      boxShadow: {
        glow: "0 0 40px rgba(0, 229, 255, 0.06)",
        "glow-danger": "0 0 40px rgba(255, 77, 77, 0.08)",
        "glow-success": "0 0 40px rgba(124, 255, 107, 0.08)",
      },
      backdropBlur: {
        xs: "2px",
      },
    },
  },
  plugins: [require("tailwindcss-animate")],
};