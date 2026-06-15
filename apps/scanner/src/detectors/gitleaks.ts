import { execFile } from 'node:child_process';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import type { Finding } from '@vibescan/findings';
import type { CollectResult } from '../collector';
import type { RepoContext } from '../repo/types';
import { config } from '../config';

const execFileAsync = promisify(execFile);

interface GitleaksHit {
  RuleID?: string;
  Description?: string;
  Match?: string;
  Secret?: string;
  File?: string;
  Commit?: string;
}

/**
 * gitleaks rule IDs whose matches are low-confidence by construction: they fire
 * on a secret-ish *keyword* sitting near a high-entropy string, not on a known
 * provider key format. They are the dominant source of false positives —
 * tripping on placeholders, .env examples, test fixtures (including our own),
 * build hashes and other non-secret tokens. We still surface them (a real leak
 * can hide here) but as a `low`, minor finding instead of a screaming critical,
 * and tag them `unverified` so the report card carries the caveat. Provider-
 * format rules (Stripe, AWS, GitHub, Slack, private keys, JWTs, …) are precise,
 * so they keep their critical severity — important because on repo scans
 * gitleaks is the ONLY secrets engine (the provider-aware detectSecrets runs on
 * URL/code scans only), so a real service_role/AWS leak must not be demoted. */
const LOW_CONFIDENCE_RULES: ReadonlySet<string> = new Set(['generic-api-key']);

const LOW_CONFIDENCE_DETAIL =
  'Low-confidence match: flagged by a generic keyword + high-entropy rule, not a known provider key ' +
  "format. It's often a placeholder, example, or test value. Confirm it's a real, live credential " +
  'before rotating anything.';

/** Turn a list of gitleaks hits into deduped `secret_exposed` findings. */
function hitsToFindings(hits: GitleaksHit[], withLocation: boolean): Finding[] {
  const seen = new Set<string>();
  const findings: Finding[] = [];
  for (const hit of hits) {
    const provider = hit.RuleID ?? hit.Description ?? 'secret';
    const masked = hit.Secret || hit.Match || '(redacted)';
    const key = `${provider}::${masked}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const params: Record<string, string> = { provider };
    if (withLocation && hit.File) params.file = hit.File;
    if (withLocation && hit.Commit) params.commit = hit.Commit.slice(0, 10);
    const lowConfidence = LOW_CONFIDENCE_RULES.has(hit.RuleID ?? '');
    const finding: Finding = {
      type: 'secret_exposed',
      severity: lowConfidence ? 'low' : 'critical',
      category: 'secrets',
      summary: `${provider} (${masked})`,
      evidence: masked,
      params,
    };
    if (lowConfidence) {
      finding.verification = { status: 'unverified', detail: LOW_CONFIDENCE_DETAIL };
    }
    findings.push(finding);
  }
  return findings;
}

/**
 * Optional deep secret scan via the gitleaks binary (150+ rules). Off unless
 * SCANNER_USE_GITLEAKS=1 and the binary is on PATH (Docker/CI). Never throws —
 * returns [] (plus a note via the caller) on any problem.
 */
export async function runGitleaks(collected: CollectResult): Promise<Finding[]> {
  if (!config.useGitleaks) return [];

  let dir: string | null = null;
  try {
    dir = await mkdtemp(join(tmpdir(), 'vibescan-'));
    // Write each script to its own file so gitleaks can scan them.
    await Promise.all(
      collected.scripts.map((s, i) => writeFile(join(dir!, `script-${i}.js`), s.content, 'utf8'))
    );
    const report = join(dir, 'report.json');
    await execFileAsync(
      'gitleaks',
      ['detect', '--no-git', '-s', dir, '-f', 'json', '-r', report, '--redact', '--exit-code', '0'],
      { timeout: 20_000, maxBuffer: 16 * 1024 * 1024 }
    );

    const raw = await readFile(report, 'utf8').catch(() => '[]');
    const hits = JSON.parse(raw) as GitleaksHit[];
    return hitsToFindings(hits, false);
  } catch {
    return [];
  } finally {
    if (dir) await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

/**
 * Full-history secret scan of a cloned repository. Unlike runGitleaks (which
 * scans loose script files with --no-git), this scans the git history, so it
 * catches secrets that were committed and later "removed" but still live in old
 * commits. Gated by SCANNER_USE_GITLEAKS; never throws.
 */
export async function runGitleaksRepo(ctx: RepoContext): Promise<Finding[]> {
  if (!config.useGitleaks || !ctx.hasGitHistory) return [];

  let report: string | null = null;
  let dir: string | null = null;
  try {
    dir = await mkdtemp(join(tmpdir(), 'vibescan-glr-'));
    report = join(dir, 'report.json');
    // No --no-git: scan the commit history of the cloned working tree.
    await execFileAsync(
      'gitleaks',
      ['detect', '-s', ctx.dir, '-f', 'json', '-r', report, '--redact', '--exit-code', '0'],
      { timeout: 60_000, maxBuffer: 32 * 1024 * 1024 }
    );

    const raw = await readFile(report, 'utf8').catch(() => '[]');
    const hits = JSON.parse(raw) as GitleaksHit[];
    return hitsToFindings(hits, true);
  } catch {
    return [];
  } finally {
    if (dir) await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}
