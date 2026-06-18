import type { Finding, ScanResult } from '@vibescan/findings';
import { buildResult, safe, withTimeout } from '../scan';
import { config } from '../config';
import { cloneRepo } from './clone';
import { detectSemgrepRepo } from './detectors/semgrep';
import { detectVulnerableDeps } from './detectors/osv';
import { detectIacMisconfig } from './detectors/iac';
import { runGitleaksRepo } from '../detectors/gitleaks';

/**
 * Scan a public Git repository end-to-end: clone (full history, big blobs
 * filtered) then run the three engines over the working tree. The temp clone is
 * always cleaned up. The whole thing is bounded by repoScanTimeoutMs, separate
 * from the synchronous URL/code timeout. Reuses buildResult/safe/withTimeout so
 * scoring, dedupe and failure isolation match the rest of the scanner.
 *
 * Note: validation (assertSafeGitUrl) happens inside cloneRepo and throws
 * SsrfError on a bad URL — the caller (job runner) turns that into a failed job.
 */
export async function runRepoScan(
  repoUrl: string,
  onPhase?: (phase: 'cloning' | 'scanning') => void
): Promise<ScanResult> {
  const start = Date.now();

  return withTimeout(
    (async (): Promise<ScanResult> => {
      const notes: string[] = [];
      onPhase?.('cloning');
      const { ctx, cleanup } = await cloneRepo(repoUrl);
      onPhase?.('scanning');
      try {
        const findings: Finding[] = [];

        // Cheap engines (network + file reads) run together; Semgrep runs alone
        // afterwards so peak memory stays low on small hosts.
        const cheap = await Promise.all([
          safe('Dependencies (OSV)', () => detectVulnerableDeps(ctx), notes),
          safe('Secrets (git history)', () => runGitleaksRepo(ctx), notes),
          safe('IaC / container misconfig', () => detectIacMisconfig(ctx), notes),
        ]);
        findings.push(...cheap.flat());

        findings.push(...(await safe('Semgrep (SAST)', () => detectSemgrepRepo(ctx), notes)));

        if (!config.useSemgrep) {
          notes.push(
            'Code analysis (Semgrep) was not run on this server. Enable SCANNER_USE_SEMGREP=1 to include SAST findings.'
          );
        }
        if (!config.useGitleaks) {
          notes.push(
            'Git-history secret scan (gitleaks) was not run on this server. Enable SCANNER_USE_GITLEAKS=1 to include it.'
          );
        }

        return buildResult(ctx.repoUrl, 'repo', findings, notes, start);
      } finally {
        await cleanup();
      }
    })(),
    config.repoScanTimeoutMs
  );
}
