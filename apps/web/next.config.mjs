import { config as loadEnv } from 'dotenv';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

// Load the repo-root .env so a single file configures both web and scanner.
const here = dirname(fileURLToPath(import.meta.url));
loadEnv({ path: resolve(here, '../../.env') });

// Static security headers applied to every response. The Content-Security-Policy
// is intentionally NOT set here — it carries a fresh per-request nonce, which a
// static header can't express, so it's built in middleware.ts instead. Keep the
// two files in sync if framing/transport policy changes.
const securityHeaders = [
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  // Only honored over HTTPS, so harmless on localhost.
  { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains' },
];

/** @type {import('next').NextConfig} */
const nextConfig = {
  // The shared findings package ships TypeScript source; Next must transpile it.
  transpilePackages: ['@vibescan/findings'],
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }];
  },
};

export default nextConfig;
