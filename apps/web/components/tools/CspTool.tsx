'use client';

import { useMemo, useState } from 'react';
import { evaluateCsp, type CheckStatus, type Grade } from '../../lib/tools/csp';

const GRADE_COLOR: Record<Grade, string> = {
  A: '#34d399',
  B: '#a3e635',
  C: '#fbbf24',
  D: '#fb923c',
  F: '#f87171',
};

const STATUS_META: Record<CheckStatus, { icon: string; cls: string }> = {
  pass: { icon: '✓', cls: 'text-emerald-400' },
  warn: { icon: '!', cls: 'text-amber-400' },
  fail: { icon: '✕', cls: 'text-red-400' },
};

const SAMPLE =
  "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.com; style-src 'self' 'unsafe-inline'; img-src *";

export function CspTool() {
  const [csp, setCsp] = useState('');
  const report = useMemo(() => evaluateCsp(csp), [csp]);
  const color = report.valid ? GRADE_COLOR[report.grade] : '#6b7280';

  return (
    <div className="space-y-5">
      <div>
        <div className="mb-1.5 flex items-center justify-between">
          <label className="text-xs uppercase tracking-wide text-white/40">
            Content-Security-Policy
          </label>
          <button
            onClick={() => setCsp(SAMPLE)}
            className="text-xs text-white/50 underline hover:text-white/80"
          >
            Load sample
          </button>
        </div>
        <textarea
          value={csp}
          onChange={(e) => setCsp(e.target.value)}
          spellCheck={false}
          rows={4}
          placeholder="default-src 'self'; script-src 'self' …"
          className="w-full resize-y rounded-xl border border-white/10 bg-white/5 p-3 font-mono text-sm text-white placeholder:text-white/30 outline-none focus:border-primary focus:ring-2 focus:ring-primary/30"
        />
        <p className="mt-1.5 text-xs text-white/40">
          Paste the value of your <span className="font-mono">Content-Security-Policy</span> header.
        </p>
      </div>

      {report.valid && (
        <>
          {/* Grade */}
          <div className="flex items-center gap-5 rounded-2xl border border-white/10 bg-white/5 p-5">
            <div
              className="flex h-20 w-20 shrink-0 items-center justify-center rounded-2xl border-2 text-4xl font-bold"
              style={{ color, borderColor: color }}
            >
              {report.grade}
            </div>
            <div>
              <div className="text-sm text-white/50">CSP grade</div>
              <div className="text-2xl font-bold text-white">{report.score}/100</div>
              <p className="mt-1 text-sm text-white/60">
                {report.checks.filter((c) => c.status === 'pass').length}/{report.checks.length}{' '}
                checks passed
              </p>
            </div>
          </div>

          {/* Checks */}
          <section className="space-y-2">
            {report.checks.map((c) => {
              const m = STATUS_META[c.status];
              return (
                <div key={c.id} className="rounded-xl border border-white/10 bg-white/5 p-3">
                  <div className="flex items-start gap-2.5">
                    <span className={`mt-0.5 font-bold ${m.cls}`} aria-hidden>
                      {m.icon}
                    </span>
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-white">{c.label}</p>
                      <p className="mt-0.5 text-sm leading-relaxed text-white/60">{c.detail}</p>
                    </div>
                  </div>
                </div>
              );
            })}
          </section>

          {/* Parsed directives */}
          {report.directives.length > 0 && (
            <details className="rounded-xl border border-white/10 bg-white/5 p-4 text-sm">
              <summary className="cursor-pointer text-white/60">
                Parsed directives ({report.directives.length})
              </summary>
              <ul className="mt-3 space-y-1.5 font-mono text-xs">
                {report.directives.map((d) => (
                  <li key={d.name} className="flex flex-wrap gap-x-2">
                    <span className="text-primary">{d.name}</span>
                    <span className="text-white/60">{d.value || '(empty)'}</span>
                  </li>
                ))}
              </ul>
            </details>
          )}
        </>
      )}
    </div>
  );
}
