import { summarize, type Finding, type ScanResult, type ScanMode, type Severity } from '@vibescan/findings';
import { assertSafeUrl } from './ssrfGuard';
import { collect, type CollectResult } from './collector';
import { detectSecrets } from './detectors/secrets';
import { detectSupabase } from './detectors/supabase';
import { detectFirebase } from './detectors/firebase';
import { detectAuth } from './detectors/auth';
import { detectOwasp, detectSourceMaps } from './detectors/owasp';
import { detectFiles } from './detectors/files';
import { detectGraphql } from './detectors/graphql';
import { detectIdor } from './detectors/idor';
import { runGitleaks } from './detectors/gitleaks';
import { config, SCANNER_VERSION } from './config';

export class TimeoutError extends Error {
  constructor() {
    super('Scan timed out.');
    this.name = 'TimeoutError';
  }
}

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return Promise.race([
    p,
    new Promise<T>((_, reject) => setTimeout(() => reject(new TimeoutError()), ms)),
  ]);
}

function dedupe(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const f of findings) {
    const key = `${f.type}::${f.summary}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
}

/** Run one detector, capturing failures as notes instead of aborting the whole scan. */
export async function safe<T extends Finding[]>(
  name: string,
  fn: () => Promise<T> | T,
  notes: string[]
): Promise<Finding[]> {
  try {
    return await fn();
  } catch (err) {
    notes.push(`${name} check failed: ${(err as Error).message}`);
    return [];
  }
}

/** Assemble the final ScanResult from raw findings (dedupe + score + grade). */
export function buildResult(
  label: string,
  mode: ScanMode,
  findings: Finding[],
  notes: string[],
  start: number
): ScanResult {
  const deduped = dedupe(findings);
  const { score, verdict, counts, categoryGrades } = summarize(deduped);
  return {
    url: label,
    mode,
    scannedAt: new Date().toISOString(),
    score,
    verdict,
    counts,
    categoryGrades,
    findings: deduped,
    durationMs: Date.now() - start,
    notes: notes.length ? notes : undefined,
    scannerVersion: SCANNER_VERSION,
  };
}

export async function runScan(rawUrl: string): Promise<ScanResult> {
  const start = Date.now();
  const { url } = await assertSafeUrl(rawUrl); // throws SsrfError on unsafe targets

  return withTimeout(
    (async (): Promise<ScanResult> => {
      const notes: string[] = [];
      const collected = await collect(url.toString());
      notes.push(...collected.notes);

      // Detectors are independent and each is failure-isolated by safe(); run
      // them concurrently so a slow host bounds the scan by the slowest single
      // detector, not the sum of all of them.
      const groups = await Promise.all([
        safe('Secrets', () => detectSecrets(collected, { verify: config.verifySecrets }), notes),
        safe('Gitleaks', () => runGitleaks(collected), notes),
        safe('Supabase', () => detectSupabase(collected), notes),
        safe('Firebase', () => detectFirebase(collected), notes),
        safe('Auth', () => detectAuth(collected), notes),
        safe('IDOR/BOLA', () => detectIdor(collected), notes),
        safe('OWASP', () => detectOwasp(collected), notes),
        safe('Exposed files', () => detectFiles(collected), notes),
        safe('GraphQL', () => detectGraphql(collected), notes),
      ]);
      const findings: Finding[] = groups.flat();

      return buildResult(rawUrl, 'url', findings, notes, start);
    })(),
    config.timeoutMs
  );
}

/** Build a synthetic CollectResult so the text-based detectors can run over pasted code. */
function collectedFromCode(code: string): CollectResult {
  return {
    finalUrl: 'pasted-code',
    origin: '', // no live origin -> network-only checks (CORS, header probes) are skipped
    status: 0,
    responseHeaders: {},
    setCookies: [],
    html: code,
    scripts: [{ url: 'pasted-code', content: code }],
    jsCombined: code,
    requestedHosts: [],
    notes: [],
  };
}

/**
 * Scan pasted source code instead of a live URL. Runs the detectors that work
 * purely from text/JS (leaked secrets, exposed DB credentials, hard-coded
 * Supabase/Firebase config, source maps). Checks that need a live server —
 * security headers, CORS, unprotected routes, IDOR — cannot run here and are
 * surfaced as a note so the result isn't read as "all clear".
 */
export async function runCodeScan(code: string): Promise<ScanResult> {
  const start = Date.now();

  return withTimeout(
    (async (): Promise<ScanResult> => {
      const notes: string[] = [
        'Code-paste scan: checked for leaked secrets, exposed database credentials, and hard-coded Supabase/Firebase config. Live-server checks (security headers, CORS, unprotected routes, IDOR) need a URL — scan your deployed app to include those.',
      ];
      const collected = collectedFromCode(code);

      const findings: Finding[] = [];
      findings.push(...(await safe('Secrets', () => detectSecrets(collected, { verify: config.verifySecrets }), notes)));
      findings.push(...(await safe('Gitleaks', () => runGitleaks(collected), notes)));
      findings.push(...(await safe('Supabase', () => detectSupabase(collected), notes)));
      findings.push(...(await safe('Firebase', () => detectFirebase(collected), notes)));
      // Source maps are the one OWASP signal derivable from code alone; the
      // header/CORS/cookie checks are skipped here (they'd be false positives
      // against empty headers — see the note above).
      findings.push(...(await safe('Source maps', () => detectSourceMaps(collected), notes)));

      return buildResult('Pasted code', 'code', findings, notes, start);
    })(),
    config.timeoutMs
  );
}
