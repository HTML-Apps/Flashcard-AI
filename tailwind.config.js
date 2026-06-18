/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./index.html",
    "./api/**/*.js",
    "./sw.js",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        slate: {
          50:  '#f8fafc',
          100: '#f1f5f9',
          200: '#e2e8f0',
          300: '#cbd5e1',
          400: '#94a3b8',
          500: '#64748b',
          600: '#475569',
          700: '#334155',
          800: '#1e293b',
          850: '#172033',
          900: '#000000',
          950: '#020617',
        }
      }
    }
  },
  plugins: [],
}