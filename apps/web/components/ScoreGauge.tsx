import type { Verdict } from '@vibescan/findings';
import { VERDICT_META } from '../lib/ui';

const COLORS: Record<Verdict, string> = {
  red: '#f87171',
  yellow: '#fbbf24',
  green: '#34d399',
};

export function ScoreGauge({ score, verdict }: { score: number; verdict: Verdict }) {
  const r = 52;
  const circ = 2 * Math.PI * r;
  const dash = (score / 100) * circ;
  const color = COLORS[verdict];

  return (
    <div className="relative h-24 w-24 shrink-0 sm:h-32 sm:w-32">
      <svg viewBox="0 0 120 120" className="h-full w-full -rotate-90">
        <circle cx="60" cy="60" r={r} fill="none" stroke="#E6E6E6" strokeWidth="10" />
        <circle
          cx="60"
          cy="60"
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={`${dash} ${circ}`}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-2xl font-bold sm:text-3xl" style={{ color }}>
          {score}
        </span>
        <span className="text-xs text-ink/40">/ 100</span>
      </div>
      <span className="sr-only">{VERDICT_META[verdict].label}</span>
    </div>
  );
}
