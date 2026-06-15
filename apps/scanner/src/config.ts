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

  // --- Repository (source-code) scanning ---------------------------------
  // Master gate for the async repo-scan pipeline (clone + Semgrep + OSV +
  // gitleaks-history). Off by default so a slim deploy without git/semgrep is
  // still valid. Requires git (always) and, for SAST, semgrep on PATH.
  useRepoScan: process.env.SCANNER_USE_REPO_SCAN === '1',
  // Run Semgrep SAST during a repo scan. Independent of useRepoScan so an
  // operator can ship repo scanning with only OSV + gitleaks if semgrep is absent.
  useSemgrep: process.env.SCANNER_USE_SEMGREP === '1',
  // Hard budget for `git clone` alone (ms).
  repoCloneTimeoutMs: num('SCANNER_REPO_CLONE_TIMEOUT_MS', 120_000),
  // Hard budget for the whole repo scan (clone + all engines), separate from the
  // synchronous URL/code timeoutMs above.
  repoScanTimeoutMs: num('SCANNER_REPO_SCAN_TIMEOUT_MS', 240_000),
  // Abort + clean up if the cloned working tree exceeds these caps.
  repoMaxSizeMb: num('SCANNER_REPO_MAX_SIZE_MB', 200),
  repoMaxFiles: num('SCANNER_REPO_MAX_FILES', 20_000),
  // Skip individual files larger than this when handing paths to SAST/OSV.
  repoMaxFileBytes: num('SCANNER_REPO_MAX_FILE_BYTES', 2_000_000),
  // Pinned Semgrep ruleset. A registry pack (e.g. p/owasp-top-ten, p/default)
  // is reproducible; `auto` is not. Override with SCANNER_SEMGREP_CONFIG.
  semgrepConfig: process.env.SCANNER_SEMGREP_CONFIG?.trim() || 'p/owasp-top-ten',
};

export const SCANNER_VERSION = '0.3.0';

/** Identifies our bot to scanned sites (transparency + abuse tracing). */
export const USER_AGENT =
  'VibeScanBot/0.1 (+https://vibescan.app/bot; security scanner, scans only on user request)';
