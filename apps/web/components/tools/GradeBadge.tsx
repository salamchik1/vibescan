'use client';

export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';

const GRADE_COLOR: Record<Grade, string> = {
  A: '#34d399',
  B: '#a3e635',
  C: '#fbbf24',
  D: '#fb923c',
  F: '#f87171',
};

/** Large A–F grade card with a title and summary line — shared by the graded tools. */
export function GradeBadge({
  grade,
  title,
  summary,
  meta,
}: {
  grade: Grade;
  title: string;
  summary: string;
  meta?: string;
}) {
  const color = GRADE_COLOR[grade];
  return (
    <div className="flex items-center gap-5 rounded-2xl border border-ink/10 bg-white p-5">
      <div
        className="flex h-20 w-20 shrink-0 items-center justify-center rounded-2xl border-2 text-4xl font-bold"
        style={{ color, borderColor: color }}
      >
        {grade}
      </div>
      <div className="min-w-0">
        <div className="text-sm text-ink/50">{title}</div>
        <div className="text-lg font-semibold text-ink">{summary}</div>
        {meta && <p className="mt-1 text-sm text-ink/60">{meta}</p>}
      </div>
    </div>
  );
}
