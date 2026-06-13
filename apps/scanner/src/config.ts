import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import dotenv from 'dotenv';

// Load the repo-root .env (apps/scanner/src -> ../../../ = repo root).
const here = dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: resolve(here, '../../../.env') });
// Also load a local override if present.
dotenv.config();

function num(name: string, fallback: number): number {
  const v = process.env[name];
  const n = v ? Number(v) : NaN;
  return Number.isFinite(n) ? n : fallback;
}

export const config = {
  // Render/Railway inject PORT and route external traffic to it. Honor it first,
  // fall back to SCANNER_PORT for local dev, then the default.
  port: num('PORT', num('SCANNER_PORT', 8787)),
  sharedSecret: process.env.SCANNER_SHARED_SECRET ?? '',
  allowedOrigins: (process.env.SCANNER_ALLOWED_ORIGINS ?? 'http://localhost:3000')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean),
  rateMax: num('SCANNER_RATE_MAX', 5),
  rateWindowMs: num('SCANNER_RATE_WINDOW_MS', 60_000),
  timeoutMs: num('SCANNER_TIMEOUT_MS', 75_000),
  useGitleaks: process.env.SCANNER_USE_GITLEAKS === '1',
  // Read-only liveness checks on detected secrets. On by default; set SCANNER_VERIFY_SECRETS=0 to disable.
  verifySecrets: process.env.SCANNER_VERIFY_SECRETS !== '0',
};

export const SCANNER_VERSION = '0.3.0';

/** Identifies our bot to scanned sites (transparency + abuse tracing). */
export const USER_AGENT =
  'VibeScanBot/0.1 (+https://vibescan.app/bot; security scanner, scans only on user request)';
