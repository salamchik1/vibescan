'use client';

import { useEffect, useState } from 'react';
import { HASH_ALGOS, hashAll, type HashAlgo } from '../../lib/tools/hash';
import { CopyButton } from './CopyButton';

const LEGACY: Record<string, string> = {
  MD5: 'Broken — checksums only, never for security.',
  'SHA-1': 'Deprecated — avoid for signatures or integrity.',
};

export function HashTool() {
  const [input, setInput] = useState('');
  const [hashes, setHashes] = useState<Record<HashAlgo, string> | null>(null);

  useEffect(() => {
    let cancelled = false;
    if (!input) {
      setHashes(null);
      return;
    }
    hashAll(input).then((h) => {
      if (!cancelled) setHashes(h);
    });
    return () => {
      cancelled = true;
    };
  }, [input]);

  return (
    <div className="space-y-4">
      <div>
        <label className="mb-1.5 block text-xs uppercase tracking-wide text-white/40">Text</label>
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          spellCheck={false}
          rows={4}
          placeholder="Type or paste text to hash…"
          className="w-full resize-y rounded-xl border border-white/10 bg-white/5 p-3 font-mono text-sm text-white placeholder:text-white/30 outline-none focus:border-primary focus:ring-2 focus:ring-primary/30"
        />
      </div>

      <div className="space-y-2.5">
        {HASH_ALGOS.map((algo) => (
          <div key={algo} className="rounded-xl border border-white/10 bg-white/5 p-3">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <span className="font-ui text-sm font-semibold text-white">{algo}</span>
                {LEGACY[algo] && (
                  <span className="rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[10px] font-medium text-amber-300">
                    legacy
                  </span>
                )}
              </div>
              <CopyButton value={hashes?.[algo] ?? ''} />
            </div>
            <p className="mt-2 break-all font-mono text-xs text-white/80">
              {hashes?.[algo] ?? <span className="text-white/30">—</span>}
            </p>
            {LEGACY[algo] && (
              <p className="mt-1.5 text-[11px] text-amber-300/70">{LEGACY[algo]}</p>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
