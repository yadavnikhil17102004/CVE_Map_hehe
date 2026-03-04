/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./*.html"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        primary: "#06b6d4",
        "primary-glow": "rgba(6,182,212,0.4)",
        "bg-dark": "#0f1115",
        "surface": "#161b22",
        "surface-2": "#1f2937",
        "border": "#30363d",
        "dim": "#8b949e",
        "success": "#2ea043",
        "warning": "#d29922",
        "danger": "#f85149",
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'monospace'],
        sans: ['Inter', 'sans-serif'],
      },
      animation: {
        pulse: "pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        ping: "ping 1s cubic-bezier(0, 0, 0.2, 1) infinite",
      }
    },
  },
  plugins: [
    require('@tailwindcss/typography'),
    require('@tailwindcss/forms'),
  ],
}
