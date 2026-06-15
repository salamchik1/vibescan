'use client';

import { useCallback, useState } from 'react';
import { useRouter } from 'next/navigation';
import type { ScanResult } from '@vibescan/findings';
import { ScanForm, type ScanInput } from '../components/ScanForm';
import { LoadingScreen } from '../components/LoadingScreen';
import { Report } from '../components/Report';
import { SiteHeader } from '../components/SiteHeader';

type State =
  | { phase: 'idle' }
  | { phase: 'loading'; label: string; mode: 'url' | 'code' }
  | { phase: 'polling'; label: string; status: string }
  | { phase: 'done'; result: ScanResult; lastInput: ScanInput; id?: string }
  | { phase: 'error'; message: string };

// Live status copy per repo-job state.
const REPO_STATUS_TEXT: Record<string, string> = {
  queued: 'Queued…',
  cloning: 'Cloning the repository…',
  scanning: 'Analysing the code…',
};

export default function Home() {
  const [state, setState] = useState<State>({ phase: 'idle' });
  const router = useRouter();

  // Repo scans are async: enqueue a job, then poll Supabase (via our route)
  // until it's done, then jump to the saved report at /r/{id}.
  const pollRepoJob = useCallback(
    async (jobId: string, label: string) => {
      const MAX_ATTEMPTS = 80; // ~4 min at 3s intervals
      for (let i = 0; i < MAX_ATTEMPTS; i += 1) {
        await new Promise((r) => setTimeout(r, 3000));
        let data: { status?: string; scanId?: string | null; error?: string };
        try {
          const res = await fetch(`/api/scan/repo/${jobId}`);
          data = await res.json();
          if (!res.ok) {
            setState({ phase: 'error', message: data?.error ?? 'Lost track of the scan.' });
            return;
          }
        } catch {
          continue; // transient hiccup — keep polling
        }
        if (data.status === 'done') {
          if (data.scanId) router.push(`/r/${data.scanId}`);
          else setState({ phase: 'error', message: 'The scan finished but the report could not be saved.' });
          return;
        }
        if (data.status === 'failed') {
          setState({ phase: 'error', message: data.error || 'The repository scan failed.' });
          return;
        }
        setState({ phase: 'polling', label, status: REPO_STATUS_TEXT[data.status ?? ''] ?? 'Scanning…' });
      }
      setState({ phase: 'error', message: 'The scan is taking longer than expected. Please try again later.' });
    },
    [router]
  );

  const runScan = useCallback(
    async (input: ScanInput) => {
      if ('repoUrl' in input) {
        setState({ phase: 'polling', label: input.repoUrl, status: 'Starting…' });
        try {
          const res = await fetch('/api/scan/repo', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ repoUrl: input.repoUrl }),
          });
          const data = await res.json();
          if (!res.ok || !data?.jobId) {
            setState({ phase: 'error', message: data?.error ?? 'Could not start the scan.' });
            return;
          }
          await pollRepoJob(data.jobId, input.repoUrl);
        } catch {
          setState({ phase: 'error', message: 'Network error. Please try again.' });
        }
        return;
      }

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
    },
    [pollRepoJob]
  );

  const rescan = useCallback(() => {
    if (state.phase === 'done') runScan(state.lastInput);
  }, [state, runScan]);

  const busy = state.phase === 'loading' || state.phase === 'polling';

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

      {state.phase === 'polling' && <LoadingScreen url={state.label} status={state.status} />}

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
