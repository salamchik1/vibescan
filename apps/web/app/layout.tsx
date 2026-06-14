import type { Metadata, Viewport } from 'next';
import { headers } from 'next/headers';
import './globals.css';

export const metadata: Metadata = {
  title: 'VibeScan — Is your vibe-coded app secure?',
  description:
    'Free security scan for apps built on Lovable, Bolt, Base44 and Supabase. Find leaked API keys, open databases and missing auth in 60 seconds — in plain English.',
};

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  themeColor: '#0B0B0E',
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  // Touch the request headers so every route renders per request (dynamically).
  // The CSP set in middleware.ts carries a fresh per-request nonce, and Next can
  // only stamp that nonce onto the <script> tags it injects during a per-request
  // render — a build-time static render would bake in an absent/stale nonce and
  // the browser would block hydration under our nonce-based script-src.
  await headers();

  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
