'use client';

import { useMemo, useState } from 'react';
import { encodeBase64, decodeBase64 } from '../../lib/tools/base64';
import { CopyButton } from './CopyButton';

type Mode = 'encode' | 'decode';

export function Base64Tool() {
  const [mode, setMode] = useState<Mode>('encode');
  const [urlSafe, setUrlSafe] = useState(false);
  const [input, setInput] = useState('');

  const result = useMemo(
    () => (mode === 'encode' ? encodeBase64(input, urlSafe) : decodeBase64(input)),
    [mode, urlSafe, input]
  );

  function swap() {
    if (result.ok && result.output) setInput(result.output);
    setMode((m) => (m === 'encode' ? 'decode' : 'encode'));
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        {(['encode', 'decode'] as Mode[]).map((m) => (
          <button
            key={m}
            onClick={() => setMode(m)}
            className={`rounded-full border px-4 py-1.5 text-sm capitalize transition ${
              mode === m
                ? 'border-primary bg-primary/15 text-primary'
                : 'border-white/10 text-white/60 hover:border-white/30'
            }`}
          >
            {m}
          </button>
        ))}
        {mode === 'encode' && (
          <label className="ml-2 flex items-center gap-2 text-sm text-white/60">
            <input
              type="checkbox"
              checked={urlSafe}
              onChange={(e) => setUrlSafe(e.target.checked)}
              className="h-4 w-4 rounded border-white/20 bg-white/10 accent-primary"
            />
            URL-safe
          </label>
        )}
      </div>

      <div>
        <label className="mb-1.5 block text-xs uppercase tracking-wide text-white/40">
          {mode === 'encode' ? 'Plain text' : 'Base64'}
        </label>
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          spellCheck={false}
          rows={5}
          placeholder={mode === 'encode' ? 'Type or paste text…' : 'Paste base64…'}
          className="w-full resize-y rounded-xl border border-white/10 bg-white/5 p-3 font-mono text-sm text-white placeholder:text-white/30 outline-none focus:border-primary focus:ring-2 focus:ring-primary/30"
        />
      </div>

      <div className="flex justify-center">
        <button
          onClick={swap}
          className="rounded-full border border-white/10 px-4 py-1.5 text-sm text-white/70 transition hover:border-white/30"
        >
          ⇅ Swap
        </button>
      </div>

      <div>
        <div className="mb-1.5 flex items-center justify-between">
          <label className="text-xs uppercase tracking-wide text-white/40">
            {mode === 'encode' ? 'Base64' : 'Plain text'}
          </label>
          <CopyButton value={result.ok ? result.output : ''} />
        </div>
        {result.ok ? (
          <textarea
            value={result.output}
            readOnly
            rows={5}
            spellCheck={false}
            className="w-full resize-y rounded-xl border border-white/10 bg-black/40 p-3 font-mono text-sm text-white/90 outline-none"
          />
        ) : (
          <p className="rounded-xl border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300">
            {result.error}
          </p>
        )}
      </div>
    </div>
  );
}
