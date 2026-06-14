'use client';

export type CheckStatus = 'pass' | 'warn' | 'fail' | 'info';

export interface Check {
  id: string;
  label: string;
  status: CheckStatus;
  detail: string;
}

const STATUS_META: Record<CheckStatus, { icon: string; cls: string }> = {
  pass: { icon: '✓', cls: 'text-emerald-600' },
  warn: { icon: '!', cls: 'text-amber-400' },
  fail: { icon: '✕', cls: 'text-red-600' },
  info: { icon: 'i', cls: 'text-sky-400' },
};

/** A single pass/warn/fail check row — shared by the SSL, email, DNS and security.txt tools. */
export function CheckRow({ check }: { check: Check }) {
  const m = STATUS_META[check.status];
  return (
    <div className="rounded-xl border border-ink/10 bg-white p-3">
      <div className="flex items-start gap-2.5">
        <span className={`mt-0.5 font-bold ${m.cls}`} aria-hidden>
          {m.icon}
        </span>
        <div className="min-w-0">
          <p className="text-sm font-medium text-ink">{check.label}</p>
          <p className="mt-0.5 break-words text-sm leading-relaxed text-ink/60">{check.detail}</p>
        </div>
      </div>
    </div>
  );
}

/** Render a list of checks. */
export function CheckList({ checks }: { checks: Check[] }) {
  return (
    <section className="space-y-2">
      {checks.map((c) => (
        <CheckRow key={c.id} check={c} />
      ))}
    </section>
  );
}
