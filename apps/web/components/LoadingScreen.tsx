'use client';

import { useEffect, useState } from 'react';

const STEPS = [
  'Loading your app in a real browser…',
  'Reading the JavaScript for leaked keys…',
  'Checking if your database is open…',
  'Testing pages that should need a login…',
  'Looking at security headers and exposed files…',
  'Writing your report…',
];

export function LoadingScreen({ url, status }: { url: string; status?: string }) {
  const [step, setStep] = useState(0);

  useEffect(() => {
    if (status) return; // repo scans report their own live status, no fake stepper
    const id = setInterval(() => setStep((s) => Math.min(s + 1, STEPS.length - 1)), 2500);
    return () => clearInterval(id);
  }, [status]);

  return (
    <div className="flex w-full flex-col items-center gap-6 py-16 text-center">
      <div className="h-12 w-12 animate-spin rounded-full border-4 border-ink/10 border-t-primary" />
      <div className="max-w-full">
        <p className="text-sm text-ink/40">Scanning</p>
        <p className="max-w-full break-all font-mono text-primary">{url}</p>
      </div>

      {status ? (
        <>
          <p className="text-sm text-ink/80">{status}</p>
          <p className="max-w-sm text-xs text-ink/40">
            We clone the repo, then run code analysis (Semgrep), dependency CVE checks, and a
            full git-history secret scan. This can take a minute or two — keep this tab open.
          </p>
        </>
      ) : (
        <>
          <ul className="space-y-2 text-left">
            {STEPS.map((s, i) => (
              <li
                key={s}
                className={`flex items-center gap-2 text-sm transition ${
                  i <= step ? 'text-ink/80' : 'text-ink/30'
                }`}
              >
                <span className={i < step ? 'text-emerald-600' : 'text-ink/30'}>
                  {i < step ? '✓' : i === step ? '…' : '○'}
                </span>
                {s}
              </li>
            ))}
          </ul>
          <p className="max-w-sm text-xs text-ink/40">
            This usually takes 30–90 seconds. We load your site, inspect it, and gently probe a few
            endpoints — read-only.
          </p>
        </>
      )}
    </div>
  );
}
