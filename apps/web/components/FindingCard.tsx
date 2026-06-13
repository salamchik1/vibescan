'use client';

import { useState } from 'react';
import {
  CATALOG,
  renderCodeExamples,
  renderFix,
  renderMeaning,
  type Finding,
  type Platform,
} from '@vibescan/findings';
import { SEVERITY_META, VERIFICATION_META } from '../lib/ui';

export function FindingCard({ finding, platform }: { finding: Finding; platform: Platform }) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const [codeCopied, setCodeCopied] = useState(false);
  const [activeExample, setActiveExample] = useState(0);

  const entry = CATALOG[finding.type];
  const sev = SEVERITY_META[finding.severity];
  const meaning = renderMeaning(finding.type, finding.params);
  const fix = renderFix(finding.type, platform, finding.params);
  const examples = renderCodeExamples(finding.type, finding.params);
  const example = examples[activeExample];
  const verification = finding.verification;
  const verMeta = verification ? VERIFICATION_META[verification.status] : null;

  async function copyText(text: string, mark: (v: boolean) => void) {
    try {
      await navigator.clipboard.writeText(text);
      mark(true);
      setTimeout(() => mark(false), 1800);
    } catch {
      /* clipboard unavailable */
    }
  }

  return (
    <div className="rounded-xl border border-white/10 bg-white/5 p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h4 className="font-semibold text-white">{entry.title}</h4>
          <p className="mt-0.5 text-sm text-white/60">{finding.summary}</p>
        </div>
        <span
          className={`shrink-0 rounded-full border px-2.5 py-0.5 text-xs font-medium ${sev.badge}`}
        >
          {sev.label}
        </span>
      </div>

      {verMeta && (
        <div className="mt-3 rounded-lg border border-white/10 bg-black/30 p-2.5">
          <span
            className={`inline-block rounded-full border px-2.5 py-0.5 text-xs font-medium ${verMeta.badge}`}
          >
            {verMeta.label}
          </span>
          <p className="mt-1.5 text-xs leading-relaxed text-white/60">
            {verification?.detail ?? verMeta.note}
          </p>
          {verification?.checkedEndpoint && (
            <p className="mt-1 font-mono text-[11px] text-white/35">
              Read-only check: {verification.checkedEndpoint}
            </p>
          )}
        </div>
      )}

      <p className="mt-3 text-sm leading-relaxed text-white/70">{meaning}</p>

      {finding.evidence && (
        <p className="mt-2 font-mono text-xs text-white/40">Evidence: {finding.evidence}</p>
      )}

      <button
        onClick={() => setOpen((o) => !o)}
        className="mt-3 text-sm font-medium text-primary hover:text-primary-dark print:hidden"
      >
        {open ? 'Hide fix' : 'How to fix →'}
      </button>

      {/* Rendered always so the PDF export includes every fix; hidden on screen until toggled. */}
      <div className={open ? '' : 'hidden print:block'}>
          {/* Copy-paste prompt for the selected builder */}
          <div className="mt-3 rounded-lg border border-white/10 bg-black/60 p-3">
            <div className="mb-2 flex items-center justify-between">
              <span className="text-xs uppercase tracking-wide text-white/40">
                Copy &amp; paste this
              </span>
              <button
                onClick={() => copyText(fix, setCopied)}
                className="rounded-md bg-white/10 px-2.5 py-1 text-xs font-medium text-white hover:bg-white/20 print:hidden"
              >
                {copied ? 'Copied ✓' : 'Copy'}
              </button>
            </div>
            <pre className="whitespace-pre-wrap break-words text-sm text-white/90">{fix}</pre>
          </div>

          {/* Real code examples per stack */}
          {examples.length > 0 && example && (
            <div className="mt-3 rounded-lg border border-white/10 bg-black/60 p-3">
              <div className="mb-2 flex flex-wrap items-center gap-2">
                <span className="mr-1 text-xs uppercase tracking-wide text-white/40">
                  Example code
                </span>
                {examples.map((ex, i) => (
                  <button
                    key={ex.stack}
                    onClick={() => setActiveExample(i)}
                    className={`rounded-full border px-2.5 py-0.5 text-xs transition ${
                      i === activeExample
                        ? 'border-primary bg-primary/15 text-primary'
                        : 'border-white/10 text-white/50 hover:border-white/30'
                    }`}
                  >
                    {ex.stack}
                  </button>
                ))}
                <button
                  onClick={() => copyText(example.code, setCodeCopied)}
                  className="ml-auto rounded-md bg-white/10 px-2.5 py-1 text-xs font-medium text-white hover:bg-white/20 print:hidden"
                >
                  {codeCopied ? 'Copied ✓' : 'Copy code'}
                </button>
              </div>
              {example.note && (
                <p className="mb-2 text-xs leading-relaxed text-white/50">{example.note}</p>
              )}
              <pre className="overflow-x-auto rounded-md bg-black/50 p-3 text-[13px] leading-relaxed text-white/90">
                <code>{example.code}</code>
              </pre>
            </div>
          )}
      </div>
    </div>
  );
}
