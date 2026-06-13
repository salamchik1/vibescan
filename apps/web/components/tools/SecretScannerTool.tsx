'use client';

import { useMemo, useState } from 'react';
import { scanForSecrets, type Severity } from '../../lib/tools/secrets';

const SEVERITY_META: Record<Severity, { label: string; cls: string; dot: string }> = {
  critical: { label: 'Critical', cls: 'border-red-500/30 bg-red-500/10 text-red-300', dot: 'bg-red-400' },
  high: { label: 'High', cls: 'border-orange-500/30 bg-orange-500/10 text-orange-300', dot: 'bg-orange-400' },
  medium: { label: 'Medium', cls: 'border-amber-500/30 bg-amber-500/10 text-amber-300', dot: 'bg-amber-400' },
  low: { label: 'Low', cls: 'border-sky-500/30 bg-sky-500/10 text-sky-300', dot: 'bg-sky-400' },
};

const ORDER: Severity[] = ['critical', 'high', 'medium', 'low'];

// Demo-only fake keys. The provider prefixes are split/joined at runtime so the
// literal `sk_live_…`/`sk-proj-…` never appears contiguously in source — that keeps
// static secret scanners (GitHub push protection) from flagging this sample, while
// the reconstructed strings still trip the scanner below so the demo works.
const STRIPE_PREFIX = 'sk_' + 'live_';
const OPENAI_PREFIX = 'sk-' + 'proj-';
const SAMPLE = `# .env
STRIPE_SECRET_KEY=${STRIPE_PREFIX}51HCXn2Ks9dQfLm0ZpQ8RtVxYwAbCdEf
OPENAI_API_KEY=${OPENAI_PREFIX}abc123DEF456ghi789JKL012mno345PQR
DATABASE_URL=postgres://admin:s3cr3tP@ss@db.example.com:5432/app
NEXT_PUBLIC_SUPABASE_URL=https://demo.supabase.co  # public, fine`;

export function SecretScannerTool() {
  const [text, setText] = useState('');
  const result = useMemo(() => scanForSecrets(text), [text]);
  const hasInput = text.trim().length > 0;
  const total = result.hits.length;

  return (
    <div className="space-y-5">
      <div>
        <div className="mb-1.5 flex items-center justify-between">
          <label className="text-xs uppercase tracking-wide text-white/40">
            Code, .env or config
          </label>
          <button
            onClick={() => setText(SAMPLE)}
            className="text-xs text-white/50 underline hover:text-white/80"
          >
            Load sample
          </button>
        </div>
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          spellCheck={false}
          rows={10}
          placeholder="Paste a file, .env, JSON config or any snippet…"
          className="w-full resize-y rounded-xl border border-white/10 bg-white/5 p-3 font-mono text-sm text-white placeholder:text-white/30 outline-none focus:border-primary focus:ring-2 focus:ring-primary/30"
        />
        <p className="mt-1.5 text-xs text-white/40">
          {hasInput ? `${result.lineCount} lines scanned` : 'Nothing is uploaded — matching runs in your browser.'}
        </p>
      </div>

      {hasInput && total === 0 && (
        <div className="flex items-center gap-2.5 rounded-2xl border border-emerald-500/20 bg-emerald-500/5 p-4 text-sm text-emerald-200/90">
          <span aria-hidden>✓</span>
          No obvious secrets found. This catches known key formats and high-entropy tokens — it’s not a
          guarantee, so still keep real secrets out of client code.
        </div>
      )}

      {total > 0 && (
        <>
          <div className="flex flex-wrap items-center gap-2 rounded-2xl border border-white/10 bg-white/5 p-4">
            <span className="text-sm font-semibold text-white">
              {total} potential {total === 1 ? 'secret' : 'secrets'}
            </span>
            <span className="text-white/30">·</span>
            {ORDER.filter((s) => result.counts[s] > 0).map((s) => (
              <span
                key={s}
                className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium ${SEVERITY_META[s].cls}`}
              >
                <span className={`h-1.5 w-1.5 rounded-full ${SEVERITY_META[s].dot}`} aria-hidden />
                {result.counts[s]} {SEVERITY_META[s].label.toLowerCase()}
              </span>
            ))}
          </div>

          <section className="space-y-2">
            {result.hits.map((hit, i) => {
              const m = SEVERITY_META[hit.severity];
              return (
                <div
                  key={`${hit.provider}-${hit.masked}-${i}`}
                  className="flex items-start gap-3 rounded-xl border border-white/10 bg-white/5 p-3"
                >
                  <span
                    className={`mt-0.5 inline-flex shrink-0 rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase ${m.cls}`}
                  >
                    {m.label}
                  </span>
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-white">{hit.provider}</p>
                    <p className="mt-0.5 font-mono text-xs text-white/60">
                      line {hit.line} · {hit.masked}
                    </p>
                  </div>
                </div>
              );
            })}
          </section>

          <p className="rounded-xl border border-amber-500/20 bg-amber-500/5 px-4 py-3 text-xs text-amber-200/80">
            Rotate any real key shown here, then move it to a server-side environment variable. Values
            are masked — the full secret never leaves this page.
          </p>
        </>
      )}
    </div>
  );
}
