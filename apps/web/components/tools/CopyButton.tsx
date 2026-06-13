'use client';

import { useState } from 'react';

/** Small copy-to-clipboard button with a transient "Copied" state. */
export function CopyButton({
  value,
  label = 'Copy',
  className = '',
  disabled,
}: {
  value: string;
  label?: string;
  className?: string;
  disabled?: boolean;
}) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      /* clipboard unavailable */
    }
  }

  return (
    <button
      type="button"
      onClick={copy}
      disabled={disabled || !value}
      className={`rounded-md bg-white/10 px-2.5 py-1 text-xs font-medium text-white transition hover:bg-white/20 disabled:cursor-not-allowed disabled:opacity-40 ${className}`}
    >
      {copied ? 'Copied ✓' : label}
    </button>
  );
}
