'use client';

import { useState } from 'react';

export type ScanInput = { url: string } | { code: string };

type Mode = 'url' | 'code';

export function ScanForm({
  onScan,
  disabled,
}: {
  onScan: (input: ScanInput) => void;
  disabled?: boolean;
}) {
  const [mode, setMode] = useState<Mode>('url');
  const [url, setUrl] = useState('');
  const [code, setCode] = useState('');
  const [agreed, setAgreed] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (mode === 'code') {
      if (!code.trim()) {
        setError('Paste some code to scan (your bundled JS, config, or source files).');
        return;
      }
      onScan({ code });
      return;
    }

    if (!url.trim()) {
      setError('Enter the URL of your app.');
      return;
    }
    if (!agreed) {
      setError('Please confirm you are allowed to scan this site.');
      return;
    }
    onScan({ url: url.trim() });
  }

  return (
    <form onSubmit={submit} className="w-full max-w-xl">
      {/* Mode tabs */}
      <div className="mb-4 inline-flex rounded-lg border border-ink/10 bg-white p-1 text-sm shadow-card">
        {(
          [
            { id: 'url', label: 'Scan a URL' },
            { id: 'code', label: 'Paste code' },
          ] as { id: Mode; label: string }[]
        ).map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => {
              setMode(t.id);
              setError(null);
            }}
            disabled={disabled}
            className={`rounded-md px-4 py-1.5 transition ${
              mode === t.id ? 'bg-ink font-semibold text-white' : 'text-ink/60 hover:text-ink'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {mode === 'url' ? (
        <>
          <div className="flex flex-col gap-3 sm:flex-row">
            <input
              type="text"
              inputMode="url"
              autoComplete="off"
              placeholder="https://my-app.lovable.app"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              disabled={disabled}
              className="flex-1 rounded-lg border border-ink/10 bg-white px-5 py-3 text-base text-ink shadow-card placeholder:text-ink/40 outline-none focus:border-ink/40 focus:ring-2 focus:ring-ink/10 disabled:opacity-60"
            />
            <button
              type="submit"
              disabled={disabled}
              className="btn-primary px-6 py-3 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {disabled ? 'Scanning…' : 'Scan for free'}
            </button>
          </div>

          <label className="mt-3 flex items-start gap-2 text-sm text-ink/60">
            <input
              type="checkbox"
              checked={agreed}
              onChange={(e) => setAgreed(e.target.checked)}
              disabled={disabled}
              className="mt-0.5 h-4 w-4 rounded border-ink/20 bg-black/5 accent-primary"
            />
            <span>I own this site or have permission to scan it.</span>
          </label>

          {error && <p className="mt-2 text-sm text-red-600">{error}</p>}
          <p className="mt-2 text-xs text-ink/40">
            We scan only the public page. We never ask for your code or store your keys.
          </p>
        </>
      ) : (
        <>
          <textarea
            value={code}
            onChange={(e) => setCode(e.target.value)}
            disabled={disabled}
            rows={10}
            placeholder={'Paste your bundled JS, .env, supabase config, or any source file here…'}
            className="w-full resize-y rounded-lg border border-ink/10 bg-white px-4 py-3 font-mono text-sm text-ink shadow-card placeholder:text-ink/40 outline-none focus:border-ink/40 focus:ring-2 focus:ring-ink/10 disabled:opacity-60"
          />
          <button
            type="submit"
            disabled={disabled}
            className="btn-primary mt-3 w-full px-6 py-3 disabled:cursor-not-allowed disabled:opacity-60 sm:w-auto"
          >
            {disabled ? 'Scanning…' : 'Scan this code'}
          </button>

          {error && <p className="mt-2 text-sm text-red-600">{error}</p>}
          <p className="mt-2 text-xs text-ink/40">
            Code scans run fully in our scanner — we find leaked keys, exposed database credentials,
            and hard-coded Supabase/Firebase config. Live-server checks (headers, CORS, unprotected
            routes) need a URL.
          </p>
        </>
      )}
    </form>
  );
}
