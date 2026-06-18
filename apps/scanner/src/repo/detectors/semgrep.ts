import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { Finding, Severity } from '@vibescan/findings';
import { config } from '../../config';
import type { RepoContext } from '../types';

const execFileAsync = promisify(execFile);

/** Max grouped rules surfaced per scan — keeps the report (and the score) sane. */
const MAX_SAST_FINDINGS = 20;
/** Max length of a rule message echoed as evidence. */
const MAX_EVIDENCE = 240;

interface SemgrepResult {
  check_id?: string;
  path?: string;
  start?: { line?: number };
  extra?: {
    message?: string;
    severity?: string; // 'ERROR' | 'WARNING' | 'INFO'
    metadata?: Record<string, unknown>;
  };
}

interface SemgrepOutput {
  results?: SemgrepResult[];
}

/**
 * Map Semgrep severity to ours conservatively. Semgrep cannot confirm
 * exploitability the way the live URL checks do, so we never auto-promote to
 * critical, and only the highest-confidence ERRORs reach `high` — this stops a
 * noisy repo from dominating the score (see scoring notes in the plan).
 */
function mapSeverity(extra: SemgrepResult['extra']): Severity {
  const sev = (extra?.severity ?? '').toUpperCase();
  const md = extra?.metadata ?? {};
  const confidence = String(md.confidence ?? '').toUpperCase();
  const impact = String(md.impact ?? '').toUpperCase();
  if (sev === 'ERROR') {
    return confidence === 'HIGH' && impact === 'HIGH' ? 'high' : 'medium';
  }
  return 'low'; // WARNING / INFO / anything else
}

const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/** Last dotted segment of a Semgrep check_id, e.g. "…audit.sqli.sqli" -> "sqli". */
function shortRule(checkId: string): string {
  const segs = checkId.split('.').filter(Boolean);
  return segs[segs.length - 1] || checkId;
}

/**
 * Run Semgrep SAST over the cloned tree. Findings are grouped by rule (one
 * Finding per rule, with an occurrence count) and capped, so a repo with
 * hundreds of hits produces a readable report and a meaningful score rather than
 * a wall of items that floors the grade. Never throws on findings; only a
 * genuine failure (semgrep missing / crash) propagates to the caller's safe().
 */
export async function detectSemgrepRepo(ctx: RepoContext): Promise<Finding[]> {
  if (!config.useSemgrep) return [];

  // Each comma-separated pack becomes its own `--config` flag.
  const configFlags = config.semgrepConfig
    .split(',')
    .map((c) => c.trim())
    .filter(Boolean)
    .flatMap((c) => ['--config', c]);

  const args = [
    'scan',
    ...configFlags,
    '--json',
    '--quiet',
    '--no-git-ignore', // we control the tree; scan what we cloned
    '--timeout',
    '20', // per-rule-per-file seconds
    '--max-target-bytes',
    String(config.repoMaxFileBytes),
    '--jobs',
    '1', // bound memory on small hosts
    '--disable-version-check',
    '--metrics=off',
    ctx.dir,
  ];

  let stdout = '';
  try {
    const res = await execFileAsync('semgrep', args, {
      timeout: config.repoScanTimeoutMs,
      maxBuffer: 64 * 1024 * 1024,
      env: { ...process.env, SEMGREP_SEND_METRICS: 'off' },
    });
    stdout = res.stdout;
  } catch (err) {
    // Semgrep exits non-zero in some modes even when it merely *found* issues;
    // if it still produced JSON, use it. Otherwise it's a real failure.
    const e = err as { stdout?: string };
    if (e.stdout && e.stdout.trim().startsWith('{')) stdout = e.stdout;
    else throw err;
  }

  let parsed: SemgrepOutput;
  try {
    parsed = JSON.parse(stdout) as SemgrepOutput;
  } catch {
    return [];
  }
  const results = parsed.results ?? [];

  // Group by rule: one Finding per check_id, keeping the first location, the
  // worst severity, and an occurrence count.
  interface Group {
    rule: string;
    short: string;
    file: string;
    line: number;
    message: string;
    severity: Severity;
    count: number;
  }
  const groups = new Map<string, Group>();

  for (const r of results) {
    const checkId = r.check_id ?? 'semgrep.rule';
    const severity = mapSeverity(r.extra);
    const file = r.path ?? '(unknown)';
    const line = r.start?.line ?? 0;
    const message = (r.extra?.message ?? '').replace(/\s+/g, ' ').trim().slice(0, MAX_EVIDENCE);

    const existing = groups.get(checkId);
    if (existing) {
      existing.count += 1;
      if (SEVERITY_RANK[severity] < SEVERITY_RANK[existing.severity]) existing.severity = severity;
    } else {
      groups.set(checkId, {
        rule: checkId,
        short: shortRule(checkId),
        file,
        line,
        message,
        severity,
        count: 1,
      });
    }
  }

  const ranked = [...groups.values()].sort(
    (a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || b.count - a.count
  );

  return ranked.slice(0, MAX_SAST_FINDINGS).map((g) => {
    const where = g.line ? `${g.file}:${g.line}` : g.file;
    const countSuffix = g.count > 1 ? ` — ${g.count} occurrences` : '';
    return {
      type: 'sast_finding',
      severity: g.severity,
      category: 'code',
      summary: `${g.short} (${where})${countSuffix}`,
      evidence: g.message || undefined,
      params: {
        rule: g.rule,
        file: g.file,
        line: String(g.line),
        count: String(g.count),
        countSuffix,
      },
    };
  });
}
