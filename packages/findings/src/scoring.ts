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
export const ALL_CATEGORIES: Category[] = ['secrets', 'database', 'auth', 'owasp'];

/** Points subtracted from a perfect 100 per finding, by severity. Tune on real scans. */
export const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 25,
  high: 15,
  medium: 7,
  low: 3,
  info: 0,
};

/** Verdict bands by score. */
export const VERDICT_BANDS = {
  redBelow: 50, // score < 50  -> red
  greenFrom: 80, // score >= 80 -> green; otherwise yellow
} as const;

export function emptyCounts(): SeverityCounts {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

export function countBySeverity(findings: Finding[]): SeverityCounts {
  const counts = emptyCounts();
  for (const f of findings) counts[f.severity] += 1;
  return counts;
}

export function scoreFromFindings(findings: Finding[]): number {
  let score = 100;
  for (const f of findings) score -= SEVERITY_WEIGHTS[f.severity];
  return Math.max(0, Math.min(100, score));
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
 * severity weights as the overall score, so a single critical leak tanks that
 * category to an F while leaving untouched categories at A.
 */
export function categoryGrades(findings: Finding[]): CategoryGrade[] {
  return ALL_CATEGORIES.map((category) => {
    const inCategory = findings.filter((f) => f.category === category);
    let score = 100;
    for (const f of inCategory) score -= SEVERITY_WEIGHTS[f.severity];
    score = Math.max(0, Math.min(100, score));
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
