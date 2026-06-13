'use client';

import { useMemo, useState } from 'react';
import { analyzeJwt, type IssueLevel } from '../../lib/tools/jwt';
import { CopyButton } from './CopyButton';

const LEVEL_STYLE: Record<IssueLevel, { badge: string; icon: string }> = {
  critical: { badge: 'border-red-500/40 bg-red-500/10 text-red-300', icon: '🔴' },
  warning: { badge: 'border-amber-500/40 bg-amber-500/10 text-amber-300', icon: '🟡' },
  info: { badge: 'border-white/15 bg-white/5 text-white/70', icon: '⚪' },
};

const SAMPLE =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

function pretty(obj: Record<string, unknown> | null): string {
  return obj ? JSON.stringify(obj, null, 2) : '';
}

export function JwtTool() {
  const [token, setToken] = useState('');
  const analysis = useMemo(() => analyzeJwt(token), [token]);

  return (
    <div className="space-y-5">
      <div>
        <div className="mb-1.5 flex items-center justify-between">
          <label className="text-xs uppercase tracking-wide text-white/40">JWT</label>
          <button
            onClick={() => setToken(SAMPLE)}
            className="text-xs text-white/50 underline hover:text-white/80"
          >
            Load sample
          </button>
        </div>
        <textarea
          value={token}
          onChange={(e) => setToken(e.target.value)}
          spellCheck={false}
          rows={4}
          placeholder="Paste a JWT (eyJ…)…"
          className="w-full resize-y break-all rounded-xl border border-white/10 bg-white/5 p-3 font-mono text-sm text-white placeholder:text-white/30 outline-none focus:border-primary focus:ring-2 focus:ring-primary/30"
        />
      </div>

      {token.trim() && analysis.error && (
        <p className="rounded-xl border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300">
          {analysis.error}
        </p>
      )}

      {analysis.valid && (
        <>
          {/* Security checks */}
          <section>
            <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-white/50">
              Security checks
            </h2>
            <div className="space-y-2">
              {analysis.issues.map((issue, i) => {
                const s = LEVEL_STYLE[issue.level];
                return (
                  <div key={i} className={`rounded-xl border p-3 ${s.badge}`}>
                    <div className="flex items-center gap-2 font-medium">
                      <span aria-hidden>{s.icon}</span>
                      {issue.title}
                    </div>
                    <p className="mt-1 text-sm leading-relaxed text-white/70">{issue.detail}</p>
                  </div>
                );
              })}
            </div>
          </section>

          {/* Timeline */}
          {analysis.timeline.length > 0 && (
            <section className="rounded-xl border border-white/10 bg-white/5 p-4">
              <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-white/50">
                Validity
              </h2>
              <ul className="space-y-1.5 text-sm">
                {analysis.timeline.map((t) => (
                  <li key={t.claim} className="flex flex-wrap gap-x-2 text-white/70">
                    <span className="w-24 shrink-0 text-white/50">{t.label}</span>
                    <span className="font-mono text-xs">{t.value}</span>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {/* Decoded segments */}
          <div className="grid gap-4 sm:grid-cols-2">
            <Segment title="Header" json={pretty(analysis.header)} />
            <Segment title="Payload" json={pretty(analysis.payload)} />
          </div>

          <div className="rounded-xl border border-white/10 bg-white/5 p-3">
            <span className="text-xs uppercase tracking-wide text-white/40">Signature</span>
            <p className="mt-1 break-all font-mono text-xs text-white/60">
              {analysis.signature || '(none)'}
            </p>
            <p className="mt-2 text-xs text-white/40">
              The signature is not verified here — that needs the secret or public key on your server.
            </p>
          </div>
        </>
      )}
    </div>
  );
}

function Segment({ title, json }: { title: string; json: string }) {
  return (
    <div className="rounded-xl border border-white/10 bg-black/40 p-3">
      <div className="mb-1.5 flex items-center justify-between">
        <span className="text-xs uppercase tracking-wide text-white/40">{title}</span>
        <CopyButton value={json} />
      </div>
      <pre className="overflow-x-auto whitespace-pre-wrap break-words text-xs text-white/90">
        {json}
      </pre>
    </div>
  );
}
