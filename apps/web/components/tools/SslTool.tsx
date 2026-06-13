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

          <details className="rounded-xl border border-white/10 bg-white/5 p-4 text-sm">
            <summary className="cursor-pointer text-white/60">Certificate details</summary>
            <dl className="mt-3 grid grid-cols-[auto,1fr] gap-x-4 gap-y-1.5 font-mono text-xs">
              <dt className="text-white/40">Subject</dt>
              <dd className="break-all text-white/80">{data.subject}</dd>
              <dt className="text-white/40">Issuer</dt>
              <dd className="break-all text-white/80">{data.issuer}</dd>
              <dt className="text-white/40">Valid from</dt>
              <dd className="text-white/80">{new Date(data.validFrom).toUTCString()}</dd>
              <dt className="text-white/40">Valid to</dt>
              <dd className="text-white/80">{new Date(data.validTo).toUTCString()}</dd>
              {data.cipher && (
                <>
                  <dt className="text-white/40">Cipher</dt>
                  <dd className="break-all text-white/80">{data.cipher}</dd>
                </>
              )}
            </dl>
            {data.altNames.length > 0 && (
              <div className="mt-3">
                <p className="text-white/40">Subject Alternative Names ({data.altNames.length})</p>
                <p className="mt-1 break-all font-mono text-xs text-white/70">
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
