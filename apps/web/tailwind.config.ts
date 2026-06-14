import type { Config } from 'tailwindcss';

const config: Config = {
  content: ['./app/**/*.{ts,tsx}', './components/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Twenty-style light palette
        paper: '#F4F4F4', // page background (muted)
        card: '#FFFFFF', // surfaces / cards
        panel: '#FFFFFF',
        ink: '#16161A', // near-black foreground + primary accent surface
        // Black CTA accent (Twenty buttons are black, not coloured).
        primary: {
          DEFAULT: '#16161A',
          dark: '#000000',
        },
        // Object/category accents lifted straight from Twenty's app UI.
        accent: {
          blue: '#3A5CCC',
          red: '#DC3D43',
          teal: '#0E9888',
          orange: '#ED5F00',
          yellow: '#FEF2A4',
        },
      },
      fontFamily: {
        sans: ['"Host Grotesk"', 'system-ui', 'sans-serif'],
        ui: ['"Host Grotesk"', 'system-ui', 'sans-serif'],
        serif: ['Aleo', 'Georgia', 'serif'],
        mono: ['"Azeret Mono"', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      boxShadow: {
        // Soft Twenty card shadows.
        card: '0 4px 16px 0 rgba(0, 0, 0, 0.06)',
        float: '0 10px 64px 0 rgba(0, 0, 0, 0.18)',
      },
    },
  },
  plugins: [],
};

export default config;
