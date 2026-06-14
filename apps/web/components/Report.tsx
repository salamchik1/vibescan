'use client';

import { useMemo, useState } from 'react';
import type { Category, Platform, ScanResult } from '@vibescan/findings';
import {
  CATEGORY_LABEL,
  CATEGORY_OK,
  GRADE_COLOR,
  PLATFORMS,
  VERDICT_META,
  detectPlatform,
} from '../lib/ui';
import { ScoreGauge } from './ScoreGauge';
import { FindingCard } from './FindingCard';

const ALL_CATEGORIES: Category[] = ['secrets', 'database', 'auth', 'owasp'];

export function Report({
  result,
  onRescan,
  shareUrl,
}: {
  result: ScanResult;
  /** When provided, shows a Re-scan button. Omitted on the read-only /r/{id} page. */
  onRescan?: () => void;
  /** Permanent link to this saved report. Shows a "Copy link" button when set. */
  shareUrl?: string;
}) {
  const [platform, setPlatform] = useState<Platform>(detectPlatform(result.url));
  const verdict = VERDICT_META[result.verdict];

  const { redFindings, yellowFindings, okCategories, liveKeys } = useMemo(() => {
    const red = result.findings.filter((f) => f.severity === 'critical' || f.severity === 'high');
    const yellow = result.findings.filter(
      (f) => f.severity === 'medium' || f.severity === 'low' || f.severity === 'info'
    );
    const present = new Set(result.findings.map((f) => f.category));
    const ok = ALL_CATEGORIES.filter((c) => !present.has(c));
    const live = result.findings.filter((f) => f.verification?.status === 'active').length;
    return { redFindings: red, yellowFindings: yellow, okCategories: ok, liveKeys: live };
  }, [result]);

  return (
    <div id="vibescan-report" className="w-full max-w-2xl">
      {/* Verdict banner */}
      <div
        className={`flex items-center gap-4 rounded-2xl border border-ink/10 bg-white p-4 ring-1 sm:gap-5 sm:p-5 ${verdict.ring}`}
      >
        <ScoreGauge score={result.score} verdict={result.verdict} />
        <div className="min-w-0">
          <div className={`text-2xl font-bold ${verdict.text}`}>
            {verdict.emoji} {verdict.label}
          </div>
          <p className="mt-1 text-sm text-ink/70">{verdict.blurb}</p>
          <p className="mt-2 truncate font-mono text-xs text-ink/40">{result.url}</p>
          <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-ink/60">
            <span>🔴 {result.counts.critical + result.counts.high} critical/high</span>
            <span>🟡 {result.counts.medium + result.counts.low} medium/low</span>
            <span>⚪ {result.counts.info} info</span>
            {liveKeys > 0 && (
              <span className="font-semibold text-red-600">
                ✅ {liveKeys} live key{liveKeys === 1 ? '' : 's'} confirmed
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Per-category grades (A–F), like the overall verdict but broken down */}
      {result.categoryGrades && result.categoryGrades.length > 0 && (
        <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
          {result.categoryGrades.map((cg) => (
            <div
              key={cg.category}
              className="flex items-center gap-3 rounded-xl border border-ink/10 bg-white px-3 py-2.5"
            >
              <span
                className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg text-lg font-bold text-black"
                style={{ backgroundColor: GRADE_COLOR[cg.grade] }}
              >
                {cg.grade}
              </span>
              <div className="min-w-0 leading-tight">
                <div className="text-sm text-ink/80">{CATEGORY_LABEL[cg.category]}</div>
                <div className="text-xs text-ink/40">
                  {cg.findings === 0
                    ? 'no issues'
                    : `${cg.findings} issue${cg.findings === 1 ? '' : 's'}`}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Platform selector */}
      <div className="mt-5 flex flex-wrap items-center gap-2 print:hidden">
        <span className="text-sm text-ink/60">Show fix instructions for:</span>
        {PLATFORMS.map((p) => (
          <button
            key={p.id}
            onClick={() => setPlatform(p.id)}
            className={`rounded-full border px-3 py-1 text-sm transition ${
              platform === p.id
                ? 'border-primary bg-primary/15 text-primary'
                : 'border-ink/10 text-ink/60 hover:border-ink/30'
            }`}
          >
            {p.label}
          </button>
        ))}
      </div>

      {/* Red zone */}
      {redFindings.length > 0 && (
        <section className="mt-6">
          <h3 className="mb-3 text-sm font-semibold uppercase tracking-wide text-red-600">
            🔴 Fix now ({redFindings.length})
          </h3>
          <div className="space-y-3">
            {redFindings.map((f, i) => (
              <FindingCard key={`r${i}`} finding={f} platform={platform} />
            ))}
          </div>
        </section>
      )}

      {/* Yellow zone */}
      {yellowFindings.length > 0 && (
        <section className="mt-6">
          <h3 className="mb-3 text-sm font-semibold uppercase tracking-wide text-amber-600">
            🟡 Worth fixing ({yellowFindings.length})
          </h3>
          <div className="space-y-3">
            {yellowFindings.map((f, i) => (
              <FindingCard key={`y${i}`} finding={f} platform={platform} />
            ))}
          </div>
        </section>
      )}

      {/* Green zone */}
      {okCategories.length > 0 && (
        <section className="mt-6">
          <h3 className="mb-3 text-sm font-semibold uppercase tracking-wide text-emerald-600">
            🟢 Looks OK
          </h3>
          <ul className="space-y-1.5 rounded-xl border border-ink/10 bg-white p-4 text-sm text-ink/70">
            {okCategories.map((c) => (
              <li key={c} className="flex items-center gap-2">
                <span className="text-emerald-600">✓</span> {CATEGORY_OK[c]}
              </li>
            ))}
          </ul>
        </section>
      )}

      {result.findings.length === 0 && (
        <p className="mt-6 rounded-xl border border-ink/10 bg-white p-4 text-sm text-ink/70">
          We did not find any of the issues we check for. That is a good sign — but no scan catches
          everything. Keep an eye on it as you add features.
        </p>
      )}

      {/* CTAs — monitoring/verification land in later stages */}
      <div className="mt-8 flex flex-wrap gap-3 print:hidden">
        {onRescan && (
          <button onClick={onRescan} className="btn-primary px-5 py-2.5">
            Re-scan
          </button>
        )}
        {shareUrl && <CopyLinkButton url={shareUrl} />}
        <button
          onClick={() => window.print()}
          title="Save the full report as a PDF"
          className="btn-secondary px-5 py-2.5"
        >
          Download PDF
        </button>
        <button
          disabled
          title="Coming soon"
          className="btn-secondary cursor-not-allowed px-5 py-2.5 text-ink/40"
        >
          Monitor 24/7 (soon)
        </button>
      </div>

      {result.notes && result.notes.length > 0 && (
        <details className="mt-6 text-xs text-ink/40">
          <summary className="cursor-pointer">Scan notes</summary>
          <ul className="mt-2 list-disc space-y-1 pl-5">
            {result.notes.map((n, i) => (
              <li key={i}>{n}</li>
            ))}
          </ul>
        </details>
      )}

      <p className="mt-6 text-xs text-ink/40">
        Scanned {new Date(result.scannedAt).toLocaleString()} · scanner v{result.scannerVersion} ·{' '}
        {(result.durationMs / 1000).toFixed(1)}s. This is a lightweight check of the most common,
        high-impact issues — not a full penetration test.
      </p>
    </div>
  );
}

/** "Copy link" button for a saved report's permanent URL. */
function CopyLinkButton({ url }: { url: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={async () => {
        try {
          const absolute = new URL(url, window.location.origin).href;
          await navigator.clipboard.writeText(absolute);
          setCopied(true);
          setTimeout(() => setCopied(false), 2000);
        } catch {
          /* clipboard blocked — ignore */
        }
      }}
      title="Copy a permanent link to this report"
      className="btn-secondary px-5 py-2.5"
    >
      {copied ? '✓ Link copied' : '🔗 Copy link'}
    </button>
  );
}
