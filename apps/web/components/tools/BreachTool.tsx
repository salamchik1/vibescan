'use client';

import { useToolRequest } from './useToolRequest';
import { TargetForm } from './TargetForm';
import { VerdictBanner } from './VerdictBanner';
import type { BreachResult } from '../../lib/tools/breach';

function stripHtml(s: string): string {
  return s.replace(/<[^>]+>/g, '');
}

export function BreachTool() {
  const { loading, error, data, run } = useToolRequest<BreachResult>('/api/tools/breach');

  return (
    <div className="space-y-5">
      <TargetForm
        label="Email address"
        placeholder="you@example.com"
        buttonLabel="Check breaches"
        inputType="email"
        loading={loading}
        error={error}
        hint="We query Have I Been Pwned for breaches containing this address. We don’t store it."
        onSubmit={(email) => run({ email })}
      />

      {data && !data.pwned && (
        <VerdictBanner
          tone="good"
          title="No breaches found"
          summary={`${data.email} doesn’t appear in any breach known to Have I Been Pwned. Keep using a password manager and unique passwords.`}
        />
      )}

      {data && data.pwned && (
        <>
          <VerdictBanner
            tone="bad"
            title={`Found in ${data.breachCount} breach${data.breachCount === 1 ? '' : 'es'}`}
            summary={`${data.email} appeared in the breaches below. Change reused passwords and enable two-factor authentication where you can.`}
          />

          <section className="space-y-3">
            {data.breaches.map((b) => (
              <div key={b.name} className="rounded-xl border border-white/10 bg-white/5 p-4">
                <div className="flex flex-wrap items-center gap-2">
                  <h3 className="font-ui font-semibold text-white">{b.name}</h3>
                  {b.isSensitive && (
                    <span className="rounded-full border border-red-500/30 bg-red-500/10 px-2 py-0.5 text-[10px] font-medium text-red-300">
                      sensitive
                    </span>
                  )}
                  {!b.isVerified && (
                    <span className="rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[10px] font-medium text-amber-300">
                      unverified
                    </span>
                  )}
                  <span className="ml-auto text-xs text-white/40">{b.breachDate}</span>
                </div>
                <p className="mt-1 text-xs text-white/50">
                  {b.domain || 'unknown domain'} · {b.pwnCount.toLocaleString()} accounts
                </p>
                {b.dataClasses.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {b.dataClasses.map((d) => (
                      <span
                        key={d}
                        className="rounded-md border border-white/10 bg-black/30 px-2 py-0.5 text-[11px] text-white/70"
                      >
                        {d}
                      </span>
                    ))}
                  </div>
                )}
                <p className="mt-2.5 text-sm leading-relaxed text-white/60">{stripHtml(b.description)}</p>
              </div>
            ))}
          </section>
        </>
      )}
    </div>
  );
}
