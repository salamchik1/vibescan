import type { Config } from 'tailwindcss';

const config: Config = {
  content: ['./app/**/*.{ts,tsx}', './components/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        ink: '#0B0B0B',
        panel: '#121212',
        primary: {
          DEFAULT: '#F3FE00',
          dark: '#E2EC07',
        },
      },
      fontFamily: {
        sans: ['Geologica', 'system-ui', 'sans-serif'],
        ui: ['"Plus Jakarta Sans"', 'system-ui', 'sans-serif'],
      },
    },
  },
  plugins: [],
};

export default config;
