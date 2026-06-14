import type { Metadata, Viewport } from 'next';
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

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
