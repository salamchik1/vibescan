'use client';

export type Tone = 'good' | 'info' | 'low' | 'warn' | 'bad';

const TONE_META: Record<Tone, { cls: string; icon: string }> = {
  good: { cls: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200', icon: '✓' },
  info: { cls: 'border-sky-500/30 bg-sky-500/10 text-sky-700', icon: 'i' },
  low: { cls: 'border-sky-500/30 bg-sky-500/10 text-sky-700', icon: '!' },
  warn: { cls: 'border-amber-500/30 bg-amber-500/10 text-amber-700', icon: '!' },
  bad: { cls: 'border-red-500/30 bg-red-500/10 text-red-700', icon: '✕' },
};

/** Map a finding severity to a banner tone. */
export function severityTone(severity: 'critical' | 'high' | 'medium' | 'low' | 'none'): Tone {
  if (severity === 'critical' || severity === 'high') return 'bad';
  if (severity === 'medium') return 'warn';
  if (severity === 'low') return 'low';
  return 'good';
}

/** Headline result banner: a tone-coloured box with a title and one-line summary. */
export function VerdictBanner({
  tone,
  title,
  summary,
}: {
  tone: Tone;
  title: string;
  summary: string;
}) {
  const m = TONE_META[tone];
  return (
    <div className={`flex items-start gap-3 rounded-2xl border p-4 ${m.cls}`}>
      <span className="mt-0.5 text-lg font-bold" aria-hidden>
        {m.icon}
      </span>
      <div className="min-w-0">
        <p className="font-ui font-semibold">{title}</p>
        <p className="mt-0.5 text-sm opacity-90">{summary}</p>
      </div>
    </div>
  );
}
