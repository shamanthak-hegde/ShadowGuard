/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        sg: {
          bg: '#06060c',
          panel: 'rgba(10, 15, 30, 0.8)',
          cyan: '#00f0ff',
          red: '#ff0040',
          amber: '#ff8800',
          green: '#00ff88',
          purple: '#a855f7',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
    },
  },
  plugins: [],
}
