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
  | { phase: 'done'; result: ScanResult; lastInput: ScanInput }
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
      setState({ phase: 'done', result: data as ScanResult, lastInput: input });
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
        <section className="mt-12 flex w-full flex-col items-center text-center">
          <h1 className="max-w-2xl text-3xl font-bold leading-tight text-white sm:text-4xl">
            Is your vibe-coded app leaking secrets?
          </h1>
          <p className="mt-4 max-w-xl text-white/60">
            Paste your app&apos;s URL. In about a minute we check for leaked API keys, open databases,
            and missing logins — and tell you, in plain English, exactly how to fix each one.
          </p>
          <div className="mt-8 flex w-full flex-col items-center">
            <ScanForm onScan={runScan} disabled={busy} />
          </div>
          <div className="mt-6 flex flex-wrap justify-center gap-x-6 gap-y-2 text-xs text-white/40">
            <span>✓ No signup</span>
            <span>✓ No access to your code</span>
            <span>✓ We don&apos;t store your keys</span>
          </div>
        </section>
      )}

      {state.phase === 'loading' && <LoadingScreen url={state.label} />}

      {state.phase === 'error' && (
        <p className="mt-8 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
          {state.message}
        </p>
      )}

      {state.phase === 'done' && (
        <section className="mt-10 flex w-full flex-col items-center">
          <Report result={state.result} onRescan={rescan} />
          <button
            onClick={() => setState({ phase: 'idle' })}
            className="mt-8 text-sm text-white/40 hover:text-white/70"
          >
            ← Scan another app
          </button>
        </section>
      )}

      <footer className="mt-auto w-full pt-16 text-center text-xs text-white/40">
        VibeScan checks the most common, high-impact issues in vibe-coded apps. It is not a full
        security audit.{' '}
        <a href="/terms" className="underline hover:text-white/70">
          Terms
        </a>{' '}
        ·{' '}
        <a href="/privacy" className="underline hover:text-white/70">
          Privacy
        </a>
      </footer>
    </main>
  );
}
