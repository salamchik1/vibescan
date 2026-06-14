'use client';

import { useCallback, useState } from 'react';
import type { ScanResult } from '@vibescan/findings';
import { ScanForm, type ScanInput } from '../components/ScanForm';
import { LoadingScreen } from '../components/LoadingScreen';
import { Report } from '../components/Report';
import { SiteHeader } from '../components/SiteHeader';

type State =
  | { phase: 'idle' }
  | { phase: 'loading'; label: string; mode: 'url' | 'code' }
  | { phase: 'done'; result: ScanResult; lastInput: ScanInput; id?: string }
  | { phase: 'error'; message: string };

export default function Home() {
  const [state, setState] = useState<State>({ phase: 'idle' });

  const runScan = useCallback(async (input: ScanInput) => {
    const isCode = 'code' in input;
    setState({
      phase: 'loading',
      mode: isCode ? 'code' : 'url',
      label: isCode ? 'your pasted code' : input.url,
    });
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(input),
      });
      const data = await res.json();
      if (!res.ok) {
        setState({ phase: 'error', message: data?.error ?? 'Something went wrong. Please try again.' });
        return;
      }
      const { id, ...result } = data as ScanResult & { id?: string };
      setState({ phase: 'done', result: result as ScanResult, lastInput: input, id });
    } catch {
      setState({ phase: 'error', message: 'Network error. Please try again.' });
    }
  }, []);

  const rescan = useCallback(() => {
    if (state.phase === 'done') runScan(state.lastInput);
  }, [state, runScan]);

  const busy = state.phase === 'loading';

  return (
    <main className="mx-auto flex min-h-screen max-w-3xl flex-col items-center px-5 py-12 sm:py-16">
      <SiteHeader active="scan" />

      {state.phase !== 'done' && (
        <section className="mt-16 flex w-full flex-col items-center text-center sm:mt-20">
          <span className="mb-5 inline-flex items-center gap-2 rounded-full border border-ink/10 bg-card px-3 py-1 text-xs font-medium text-ink/70 shadow-card">
            <span aria-hidden>🛡️</span> Security scanner for vibe-coded apps
          </span>
          <h1 className="max-w-3xl text-4xl leading-[1.1] tracking-tight text-ink sm:text-5xl">
            <span className="block font-serif font-light">Is your vibe-coded app</span>
            <span className="block font-sans font-semibold">leaking secrets?</span>
          </h1>
          <p className="mt-5 max-w-xl text-base text-ink/60">
            Paste your app&apos;s URL. In about a minute we check for leaked API keys, open databases,
            and missing logins — and tell you, in plain English, exactly how to fix each one.
          </p>
          <div className="mt-9 flex w-full flex-col items-center">
            <ScanForm onScan={runScan} disabled={busy} />
          </div>
          <div className="mt-6 flex flex-wrap justify-center gap-x-6 gap-y-2 text-xs text-ink/40">
            <span>✓ No signup</span>
            <span>✓ No access to your code</span>
            <span>✓ We don&apos;t store your keys</span>
          </div>
        </section>
      )}

      {state.phase === 'loading' && <LoadingScreen url={state.label} />}

      {state.phase === 'error' && (
        <p className="mt-8 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-600">
          {state.message}
        </p>
      )}

      {state.phase === 'done' && (
        <section className="mt-10 flex w-full flex-col items-center">
          <Report
            result={state.result}
            onRescan={rescan}
            shareUrl={state.id ? `/r/${state.id}` : undefined}
          />
          {state.id && (
            <p className="mt-4 text-center text-xs text-ink/40">
              This report is saved.{' '}
              <a href={`/r/${state.id}`} className="underline hover:text-ink/70">
                Open its permanent link →
              </a>
            </p>
          )}
          <button
            onClick={() => setState({ phase: 'idle' })}
            className="mt-8 text-sm text-ink/40 hover:text-ink/70"
          >
            ← Scan another app
          </button>
        </section>
      )}

      <footer className="mt-auto w-full pt-16 text-center text-xs text-ink/40">
        VibeScan checks the most common, high-impact issues in vibe-coded apps. It is not a full
        security audit.{' '}
        <a href="/terms" className="underline hover:text-ink/70">
          Terms
        </a>{' '}
        ·{' '}
        <a href="/privacy" className="underline hover:text-ink/70">
          Privacy
        </a>
      </footer>
    </main>
  );
}
