/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        background: 'hsl(222.2 84% 4.9%)',
        foreground: 'hsl(210 40% 98%)',
        card: 'hsl(222.2 47.4% 11.2%)',
        border: 'hsl(217.2 32.6% 17.5%)',
      },
    },
  },
  plugins: [],
}
