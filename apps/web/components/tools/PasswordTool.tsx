'use client';

import { useMemo, useState } from 'react';
import { checkPassword } from '../../lib/tools/password';

const BAR_COLORS = ['#f87171', '#fb923c', '#fbbf24', '#a3e635', '#34d399'];

export function PasswordTool() {
  const [pw, setPw] = useState('');
  const [show, setShow] = useState(false);
  const result = useMemo(() => checkPassword(pw), [pw]);
  const color = BAR_COLORS[result.score];

  return (
    <div className="space-y-5">
      <div>
        <label className="mb-1.5 block text-xs uppercase tracking-wide text-white/40">Password</label>
        <div className="relative">
          <input
            type={show ? 'text' : 'password'}
            value={pw}
            onChange={(e) => setPw(e.target.value)}
            autoComplete="off"
            spellCheck={false}
            placeholder="Type a password to test…"
            className="w-full rounded-xl border border-white/10 bg-white/5 px-3 py-2.5 pr-16 font-mono text-sm text-white placeholder:text-white/30 outline-none focus:border-primary focus:ring-2 focus:ring-primary/30"
          />
          <button
            onClick={() => setShow((s) => !s)}
            className="absolute right-2 top-1/2 -translate-y-1/2 rounded-md px-2 py-1 text-xs text-white/50 hover:text-white"
          >
            {show ? 'Hide' : 'Show'}
          </button>
        </div>
        <p className="mt-1.5 text-xs text-white/40">
          Tested locally in your browser — this password is never transmitted.
        </p>
      </div>

      {/* Strength meter */}
      <div>
        <div className="flex gap-1.5">
          {[0, 1, 2, 3, 4].map((i) => (
            <div
              key={i}
              className="h-2 flex-1 rounded-full transition-colors"
              style={{ background: pw && i <= result.score ? color : 'rgba(255,255,255,0.08)' }}
            />
          ))}
        </div>
        <div className="mt-2 flex flex-wrap items-baseline justify-between gap-2 text-sm">
          <span className="font-ui font-semibold" style={{ color: pw ? color : undefined }}>
            {pw ? result.label : '—'}
          </span>
          {pw && (
            <span className="text-white/50">
              {result.entropyBits} bits · cracks in {result.crackTime}
            </span>
          )}
        </div>
      </div>

      {result.warnings.length > 0 && (
        <ul className="space-y-1.5 rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 text-sm text-amber-200">
          {result.warnings.map((w, i) => (
            <li key={i} className="flex gap-2">
              <span aria-hidden>⚠️</span> {w}
            </li>
          ))}
        </ul>
      )}

      {result.suggestions.length > 0 && (
        <ul className="space-y-1.5 rounded-xl border border-white/10 bg-white/5 p-4 text-sm text-white/70">
          {result.suggestions.map((s, i) => (
            <li key={i} className="flex gap-2">
              <span className="text-primary" aria-hidden>
                →
              </span>{' '}
              {s}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
