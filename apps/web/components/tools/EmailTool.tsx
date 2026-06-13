'use client';

import { useToolRequest } from './useToolRequest';
import { TargetForm } from './TargetForm';
import { CheckList } from './CheckRow';
import { GradeBadge } from './GradeBadge';
import type { EmailResult } from '../../lib/tools/email';

export function EmailTool() {
  const { loading, error, data, run } = useToolRequest<EmailResult>('/api/tools/email');

  return (
    <div className="space-y-5">
      <TargetForm
        label="Domain"
        placeholder="example.com"
        buttonLabel="Check email"
        loading={loading}
        error={error}
        sample="github.com"
        hint="We look up the domain’s SPF and DMARC TXT records and its MX records over DNS."
        onSubmit={(domain) => run({ domain })}
      />

      {data && (
        <>
          <GradeBadge grade={data.grade} title={data.domain} summary={data.summary} />

          <CheckList checks={data.checks} />

          <details className="rounded-xl border border-white/10 bg-white/5 p-4 text-sm">
            <summary className="cursor-pointer text-white/60">Raw records</summary>
            <dl className="mt-3 space-y-2 font-mono text-xs">
              <div>
                <dt className="text-white/40">SPF</dt>
                <dd className="mt-0.5 break-all text-white/80">{data.spf ?? '(none)'}</dd>
              </div>
              <div>
                <dt className="text-white/40">DMARC</dt>
                <dd className="mt-0.5 break-all text-white/80">{data.dmarc ?? '(none)'}</dd>
              </div>
              <div>
                <dt className="text-white/40">MX</dt>
                <dd className="mt-0.5 break-all text-white/80">
                  {data.mx.length ? data.mx.join(', ') : '(none)'}
                </dd>
              </div>
            </dl>
          </details>
        </>
      )}
    </div>
  );
}
