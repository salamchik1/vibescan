import type {
  Category,
  CategoryGrade,
  Finding,
  Grade,
  ScanResult,
  SeverityCounts,
  Severity,
  Verdict,
} from './types';

/** All categories, in the order we present them on the report. */
export const ALL_CATEGORIES: Category[] = [
  'secrets',
  'database',
  'auth',
  'owasp',
  'infra',
  'code',
  'dependencies',
];

/**
 * Points subtracted from a perfect 100 per finding, by severity. Tune on real scans.
 * `low` is deliberately tiny and `info` is free: a low-confidence, often-unverified
 * hardening note (a dev-only dep advisory, a placeholder that matched a secret rule)
 * should shave at most a point, never alarm a client. Real exposure lives in the
 * major tier (medium and up), which keeps its full weight.
 */
export const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 25,
  high: 15,
  medium: 7,
  low: 1,
  info: 0,
};

/**
 * Low/info findings are "nice to know" hardening gaps, not real exposure, so we
 * cap their *combined* hit to the score. The cap is set below a single `medium`'s
 * weight, which gives two guarantees: a pile of minor items can never outweigh even
 * one genuine major finding, and the minor tier on its own can never knock a site
 * below an A / out of the green band (100 − 6 = 94). That keeps a report full of
 * unverified, low-confidence noise from scaring a client whose app is actually fine.
 */
export const MINOR_DEDUCTION_CAP = 6;

/** Severities treated as "minor" (their deduction is capped, see above). */
const MINOR_SEVERITIES: ReadonlySet<Severity> = new Set<Severity>(['low', 'info']);

/** Verdict bands by score. */
export const VERDICT_BANDS = {
  redBelow: 50, // score < 50  -> red
  greenFrom: 80, // score >= 80 -> green; otherwise yellow
} as const;

/**
 * Total points to subtract from 100: major severities (critical/high/medium)
 * count in full and linearly; the minor tier (low/info) is summed and then
 * capped at MINOR_DEDUCTION_CAP. Shared by the overall and per-category scores.
 */
function deductionFromFindings(findings: Finding[]): number {
  let major = 0;
  let minor = 0;
  for (const f of findings) {
    if (MINOR_SEVERITIES.has(f.severity)) minor += SEVERITY_WEIGHTS[f.severity];
    else major += SEVERITY_WEIGHTS[f.severity];
  }
  return major + Math.min(minor, MINOR_DEDUCTION_CAP);
}

export function emptyCounts(): SeverityCounts {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

export function countBySeverity(findings: Finding[]): SeverityCounts {
  const counts = emptyCounts();
  for (const f of findings) counts[f.severity] += 1;
  return counts;
}

export function scoreFromFindings(findings: Finding[]): number {
  return Math.max(0, Math.min(100, 100 - deductionFromFindings(findings)));
}

export function verdictFromScore(score: number): Verdict {
  if (score < VERDICT_BANDS.redBelow) return 'red';
  if (score >= VERDICT_BANDS.greenFrom) return 'green';
  return 'yellow';
}

/** Map a 0..100 score to an A–F letter grade. Shared by the overall and per-category grades. */
export function gradeFromScore(score: number): Grade {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 45) return 'D';
  return 'F';
}

/**
 * Per-category A–F breakdown. Each category starts at 100 and loses the same
 * (minor-capped) deductions as the overall score, so a single critical leak
 * tanks that category to an F while leaving untouched categories at A.
 */
export function categoryGrades(findings: Finding[]): CategoryGrade[] {
  return ALL_CATEGORIES.map((category) => {
    const inCategory = findings.filter((f) => f.category === category);
    const score = Math.max(0, Math.min(100, 100 - deductionFromFindings(inCategory)));
    return { category, score, grade: gradeFromScore(score), findings: inCategory.length };
  });
}

/** Build the score/verdict/counts/grades portion of a ScanResult from findings. */
export function summarize(
  findings: Finding[]
): Pick<ScanResult, 'score' | 'verdict' | 'counts' | 'categoryGrades'> {
  const score = scoreFromFindings(findings);
  return {
    score,
    verdict: verdictFromScore(score),
    counts: countBySeverity(findings),
    categoryGrades: categoryGrades(findings),
  };
}
