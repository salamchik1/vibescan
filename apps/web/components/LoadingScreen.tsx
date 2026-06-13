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

export function LoadingScreen({ url }: { url: string }) {
  const [step, setStep] = useState(0);

  useEffect(() => {
    const id = setInterval(() => setStep((s) => Math.min(s + 1, STEPS.length - 1)), 2500);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="flex flex-col items-center gap-6 py-16 text-center">
      <div className="h-12 w-12 animate-spin rounded-full border-4 border-white/10 border-t-primary" />
      <div>
        <p className="text-sm text-white/40">Scanning</p>
        <p className="font-mono text-primary">{url}</p>
      </div>
      <ul className="space-y-2 text-left">
        {STEPS.map((s, i) => (
          <li
            key={s}
            className={`flex items-center gap-2 text-sm transition ${
              i <= step ? 'text-white/80' : 'text-white/30'
            }`}
          >
            <span className={i < step ? 'text-emerald-400' : 'text-white/30'}>
              {i < step ? '✓' : i === step ? '…' : '○'}
            </span>
            {s}
          </li>
        ))}
      </ul>
      <p className="max-w-sm text-xs text-white/40">
        This usually takes 30–90 seconds. We load your site, inspect it, and gently probe a few
        endpoints — read-only.
      </p>
    </div>
  );
}
