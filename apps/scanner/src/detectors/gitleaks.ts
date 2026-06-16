import { execFile } from 'node:child_process';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import type { Finding } from '@vibescan/findings';
import type { CollectResult } from '../collector';
import type { RepoContext } from '../repo/types';
import { config } from '../config';
import { maskSecret } from '../util/mask';
import { extractJwts, jwtRole } from '../util/jwt';

const execFileAsync = promisify(execFile);

export interface GitleaksHit {
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

const ROLELESS_JWT_DETAIL =
  "Low-confidence match: a JWT with no Supabase role claim. It's usually a session token, a test " +
  'fixture, or a demo/example token (such as the well-known jwt.io sample). A Supabase admin key would ' +
  "decode to role:service_role and stay critical. Confirm it's a real, live credential before rotating.";

/**
 * If a hit's secret is a Supabase JWT, return its `role` claim (anon |
 * authenticated | service_role | …). Lets us tell a public-by-design anon key
 * apart from the admin service_role key — gitleaks' broad `jwt` rule cannot.
 */
function supabaseJwtRole(...sources: Array<string | undefined>): string | null {
  for (const src of sources) {
    if (!src) continue;
    for (const jwt of extractJwts(src)) {
      const role = jwtRole(jwt);
      if (role) return role;
    }
  }
  return null;
}

/**
 * Turn a list of gitleaks hits into deduped secret findings. `withLocation` is
 * true only for the git-history scan: those carry file/commit and are reported
 * as `secret_committed` (a secret baked into the repo's history), whereas the
 * loose-script scan reports `secret_exposed` (a key shipped in the page's JS).
 */
export function hitsToFindings(hits: GitleaksHit[], withLocation: boolean): Finding[] {
  const seen = new Set<string>();
  const findings: Finding[] = [];
  for (const hit of hits) {
    const raw = hit.Secret || hit.Match || '';
    const role = supabaseJwtRole(hit.Secret, hit.Match);

    // Supabase anon / authenticated keys are JWTs that are PUBLIC by design:
    // they ship to the browser and are gated by Row Level Security, not by
    // secrecy. gitleaks' generic `jwt` rule flags them as a critical leak — a
    // false positive. detectSecrets already omits them; do the same here so we
    // don't scream about a key that is meant to be exposed. (service_role, the
    // admin key, is the dangerous one and stays critical below.)
    if (role === 'anon' || role === 'authenticated') continue;

    const isServiceRole = role === 'service_role';
    // A `jwt`-rule hit with no decodable Supabase role is low-signal: it's a
    // session token, a demo/example token (e.g. the jwt.io sample shipped by our
    // own JWT decoder tool), or a test fixture — not a known dangerous key. A real
    // admin key always decodes to role:service_role above, so demoting these never
    // hides a genuine leak. (anon/authenticated were already dropped just above.)
    const rolelessJwt = !role && hit.RuleID === 'jwt';
    const lowConfidence =
      !isServiceRole && (LOW_CONFIDENCE_RULES.has(hit.RuleID ?? '') || rolelessJwt);
    const provider = isServiceRole
      ? 'Supabase service_role'
      : hit.RuleID ?? hit.Description ?? 'secret';
    const masked = /PRIVATE KEY/.test(raw)
      ? '(private key block)'
      : raw
        ? maskSecret(raw)
        : '(redacted)';

    const key = `${provider}::${masked}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const params: Record<string, string> = { provider };
    if (withLocation) {
      // Always fill both placeholders so the explanation never renders a literal
      // {{file}}/{{commit}} on the rare hit that lacks them.
      params.file = hit.File || 'your source';
      params.commit = hit.Commit ? hit.Commit.slice(0, 10) : 'an earlier commit';
    }

    const finding: Finding = {
      type: withLocation ? 'secret_committed' : 'secret_exposed',
      // service_role is a full-admin key: always critical, never demoted.
      severity: isServiceRole ? 'critical' : lowConfidence ? 'low' : 'critical',
      category: 'secrets',
      summary: isServiceRole
        ? `Supabase service_role key (${masked}) — full admin access`
        : `${provider} (${masked})`,
      evidence: masked,
      params,
    };
    if (lowConfidence) {
      finding.verification = {
        status: 'unverified',
        detail: rolelessJwt ? ROLELESS_JWT_DETAIL : LOW_CONFIDENCE_DETAIL,
      };
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
    // No --redact: we need the raw match to tell a Supabase anon key (public by
    // design) from a service_role key. We mask every secret ourselves in
    // hitsToFindings, so no raw value ever reaches a Finding; the report file
    // that briefly holds them is deleted in `finally`.
    await execFileAsync(
      'gitleaks',
      ['detect', '--no-git', '-s', dir, '-f', 'json', '-r', report, '--exit-code', '0'],
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
    // No --redact either — see runGitleaks: we mask in hitsToFindings so we can
    // first decode JWT roles and drop public-by-design anon keys.
    await execFileAsync(
      'gitleaks',
      ['detect', '-s', ctx.dir, '-f', 'json', '-r', report, '--exit-code', '0'],
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
