'use client';

import { useState } from 'react';
import { SRI_ALGOS, sriHash, sriTag, type SriAlgo, type SriKind } from '../../lib/tools/sri';
import { CopyButton } from './CopyButton';

export function SriTool() {
  const [kind, setKind] = useState<SriKind>('script');
  const [algo, setAlgo] = useState<SriAlgo>('sha384');
  const [url, setUrl] = useState('');
  const [content, setContent] = useState('');
  const [integrity, setIntegrity] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function fromContent() {
    setError(null);
    if (!content) {
      setError('Paste the file contents first, or fetch by URL.');
      return;
    }
    setIntegrity(await sriHash(content, algo));
  }

  async function fromUrl() {
    setError(null);
    setIntegrity('');
    const target = url.trim();
    if (!target) {
      setError('Enter a URL to fetch.');
      return;
    }
    setBusy(true);
    try {
      const res = await fetch(target, { mode: 'cors' });
      if (!res.ok) throw new Error(String(res.status));
      const buf = await res.arrayBuffer();
      setIntegrity(await sriHash(buf, algo));
    } catch {
      setError(
        'Could not fetch that URL (likely blocked by CORS). Open the file, copy its contents, and paste them below instead.'
      );
    } finally {
      setBusy(false);
    }
  }

  const tag = integrity ? sriTag(kind, url, integrity) : '';

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-2">
        {(['script', 'style'] as SriKind[]).map((k) => (
          <button
            key={k}
            onClick={() => setKind(k)}
            className={`rounded-full border px-4 py-1.5 text-sm transition ${
              kind === k
                ? 'border-primary bg-primary/15 text-primary'
                : 'border-ink/10 text-ink/60 hover:border-ink/30'
            }`}
          >
            {k === 'script' ? '<script>' : '<link> stylesheet'}
          </button>
        ))}
        <div className="ml-auto flex items-center gap-1 text-sm">
          {SRI_ALGOS.map((a) => (
            <button
              key={a}
              onClick={() => setAlgo(a)}
              className={`rounded-full px-3 py-1 transition ${
                algo === a ? 'bg-black/5 text-ink' : 'text-ink/50 hover:text-ink'
              }`}
            >
              {a}
            </button>
          ))}
        </div>
      </div>

      <div>
        <label className="mb-1.5 block text-xs uppercase tracking-wide text-ink/40">
          Resource URL
        </label>
        <div className="flex flex-col gap-2 sm:flex-row">
          <input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://cdn.example.com/app.js"
            spellCheck={false}
            className="flex-1 rounded-lg border border-ink/10 bg-white px-3 py-2.5 font-mono text-sm text-ink shadow-card placeholder:text-ink/40 outline-none focus:border-ink/40 focus:ring-2 focus:ring-ink/10"
          />
          <button
            onClick={fromUrl}
            disabled={busy}
            className="btn-primary px-4 py-2.5 disabled:opacity-60"
          >
            {busy ? 'Fetching…' : 'Fetch & hash'}
          </button>
        </div>
        <p className="mt-1.5 text-xs text-ink/40">
          The URL is also used as the tag&apos;s <span className="font-mono">src/href</span>.
        </p>
      </div>

      <div>
        <label className="mb-1.5 block text-xs uppercase tracking-wide text-ink/40">
          …or paste file contents
        </label>
        <textarea
          value={content}
          onChange={(e) => setContent(e.target.value)}
          spellCheck={false}
          rows={4}
          placeholder="Paste the exact JS/CSS file contents…"
          className="w-full resize-y rounded-xl border border-ink/10 bg-white p-3 font-mono text-sm text-ink placeholder:text-ink/30 outline-none focus:border-primary focus:ring-2 focus:ring-primary/30"
        />
        <button
          onClick={fromContent}
          className="mt-2 rounded-full border border-ink/10 px-4 py-1.5 text-sm text-ink/70 transition hover:border-ink/30"
        >
          Hash pasted contents
        </button>
      </div>

      {error && (
        <p className="rounded-xl border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-600">
          {error}
        </p>
      )}

      {integrity && (
        <div className="space-y-3">
          <div>
            <div className="mb-1.5 flex items-center justify-between">
              <label className="text-xs uppercase tracking-wide text-ink/40">Integrity value</label>
              <CopyButton value={integrity} />
            </div>
            <p className="break-all rounded-xl border border-ink/10 bg-black/5 p-3 font-mono text-xs text-primary">
              {integrity}
            </p>
          </div>
          <div>
            <div className="mb-1.5 flex items-center justify-between">
              <label className="text-xs uppercase tracking-wide text-ink/40">Ready-to-paste tag</label>
              <CopyButton value={tag} />
            </div>
            <pre className="overflow-x-auto rounded-xl border border-ink/10 bg-black/5 p-3 text-xs text-ink/90">
              {tag}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
