'use client';

import { useState } from 'react';

/** Shared single-field form for the network tools: input + run button + error. */
export function TargetForm({
  label,
  placeholder,
  buttonLabel = 'Check',
  inputType = 'text',
  loading,
  error,
  sample,
  hint,
  onSubmit,
}: {
  label: string;
  placeholder: string;
  buttonLabel?: string;
  inputType?: 'text' | 'email';
  loading: boolean;
  error: string | null;
  /** Optional one-click sample value. */
  sample?: string;
  hint?: string;
  onSubmit: (value: string) => void;
}) {
  const [value, setValue] = useState('');

  function submit(e: React.FormEvent) {
    e.preventDefault();
    const v = value.trim();
    if (v && !loading) onSubmit(v);
  }

  return (
    <form onSubmit={submit} className="space-y-2.5">
      <div className="flex items-center justify-between">
        <label className="text-xs uppercase tracking-wide text-ink/40">{label}</label>
        {sample && (
          <button
            type="button"
            onClick={() => setValue(sample)}
            className="text-xs text-ink/50 underline hover:text-ink/80"
          >
            Use sample
          </button>
        )}
      </div>
      <div className="flex flex-col gap-2 sm:flex-row">
        <input
          type={inputType}
          value={value}
          onChange={(e) => setValue(e.target.value)}
          spellCheck={false}
          autoCapitalize="none"
          autoCorrect="off"
          placeholder={placeholder}
          className="min-w-0 flex-1 rounded-lg border border-ink/10 bg-white px-3.5 py-2.5 font-mono text-sm text-ink shadow-card placeholder:text-ink/40 outline-none focus:border-ink/40 focus:ring-2 focus:ring-ink/10"
        />
        <button
          type="submit"
          disabled={loading || !value.trim()}
          className="btn-primary shrink-0 px-5 py-2.5 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {loading ? 'Checking…' : buttonLabel}
        </button>
      </div>
      {hint && <p className="text-xs text-ink/40">{hint}</p>}
      {error && (
        <p className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-600">
          {error}
        </p>
      )}
    </form>
  );
}
