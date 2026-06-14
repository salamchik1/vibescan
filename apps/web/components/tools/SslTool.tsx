'use client';

import { useToolRequest } from './useToolRequest';
import { TargetForm } from './TargetForm';
import { CheckList } from './CheckRow';
import { GradeBadge } from './GradeBadge';
import type { SslResult } from '../../lib/tools/ssl';

export function SslTool() {
  const { loading, error, data, run } = useToolRequest<SslResult>('/api/tools/ssl');

  return (
    <div className="space-y-5">
      <TargetForm
        label="Domain"
        placeholder="example.com"
        buttonLabel="Check SSL"
        loading={loading}
        error={error}
        sample="example.com"
        hint="We open a TLS connection on port 443 and inspect the certificate the server presents."
        onSubmit={(host) => run({ host })}
      />

      {data && (
        <>
          <GradeBadge
            grade={data.grade}
            title={data.host}
            summary={data.summary}
            meta={`${
              data.daysRemaining >= 0
                ? `${data.daysRemaining} day(s) until expiry`
                : `Expired ${Math.abs(data.daysRemaining)} day(s) ago`
            }${data.protocol ? ` · ${data.protocol}` : ''}`}
          />

          <CheckList checks={data.checks} />

          <details className="rounded-xl border border-ink/10 bg-white p-4 text-sm">
            <summary className="cursor-pointer text-ink/60">Certificate details</summary>
            <dl className="mt-3 grid grid-cols-[auto,1fr] gap-x-4 gap-y-1.5 font-mono text-xs">
              <dt className="text-ink/40">Subject</dt>
              <dd className="break-all text-ink/80">{data.subject}</dd>
              <dt className="text-ink/40">Issuer</dt>
              <dd className="break-all text-ink/80">{data.issuer}</dd>
              <dt className="text-ink/40">Valid from</dt>
              <dd className="text-ink/80">{new Date(data.validFrom).toUTCString()}</dd>
              <dt className="text-ink/40">Valid to</dt>
              <dd className="text-ink/80">{new Date(data.validTo).toUTCString()}</dd>
              {data.cipher && (
                <>
                  <dt className="text-ink/40">Cipher</dt>
                  <dd className="break-all text-ink/80">{data.cipher}</dd>
                </>
              )}
            </dl>
            {data.altNames.length > 0 && (
              <div className="mt-3">
                <p className="text-ink/40">Subject Alternative Names ({data.altNames.length})</p>
                <p className="mt-1 break-all font-mono text-xs text-ink/70">
                  {data.altNames.join(', ')}
                </p>
              </div>
            )}
          </details>
        </>
      )}
    </div>
  );
}
