/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./app/templates/**/*.html",
    // Our own scripts that hand class names to Alpine (vehicle_live_view.js: the
    // bar gradients, the pill colours). Vendored libraries are excluded on purpose.
    "./app/static/js/vehicle_live_view.js",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        'neon-blue': '#00c6ff',
        'neon-blue-darker': '#0072ff',
        'neon-magenta': '#ff00ff',
        'neon-magenta-darker': '#cc00cc',
        'neon-green': '#39FF14',
        'neon-yellow': '#FFF01F',
        'neon-yellow-darker': '#E6D800',
        'dark-bg': '#0d1117',
        'card-bg': '#161b22',
        'border-color': '#30363d',
        'input-bg': '#0d1117',
        'text-primary': '#c9d1d9',
        'text-secondary': '#8b949e',
      },
      boxShadow: {
        'neon-blue': '0 0 5px #00c6ff, 0 0 10px #00c6ff, 0 0 15px #0072ff',
        'neon-magenta': '0 0 5px #ff00ff, 0 0 10px #ff00ff, 0 0 15px #cc00cc',
        'neon-glow-blue': '0 0 15px rgba(0, 198, 255, 0.5)',
        'neon-glow-magenta': '0 0 15px rgba(255, 0, 255, 0.5)',
        'neon-glow-yellow': '0 0 15px rgba(255, 240, 31, 0.5)',
      },
      fontFamily: {
        // 'sans' was ComicCodeLigatures, a commercial font ("Copyright (c) 2019 Toshi
        // Omagari. All rights reserved", licensed from ilovetypography.com) that cannot
        // be redistributed — which the GPL-3.0 release requires. Replaced with the
        // platform UI stack: no bytes shipped, no licence, and it stays proportional so
        // the font-mono class keeps marking code and logs apart from body text.
        sans: ['ui-sans-serif', 'system-ui', '-apple-system', 'Segoe UI', 'Roboto', 'Helvetica Neue', 'Arial', 'sans-serif'],
        mono: ['RobotoMono', 'ui-monospace', 'monospace'],
        mono_droid: ['DroidSansMono', 'ui-monospace', 'monospace'],
      },
    },
  },
  plugins: [],
}