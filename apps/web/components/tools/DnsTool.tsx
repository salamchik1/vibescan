'use client';

import { useToolRequest } from './useToolRequest';
import { TargetForm } from './TargetForm';
import { CheckList } from './CheckRow';
import { GradeBadge } from './GradeBadge';
import type { DnsResult } from '../../lib/tools/dns';

export function DnsTool() {
  const { loading, error, data, run } = useToolRequest<DnsResult>('/api/tools/dns');

  return (
    <div className="space-y-5">
      <TargetForm
        label="Domain"
        placeholder="example.com"
        buttonLabel="Check DNS"
        loading={loading}
        error={error}
        sample="cloudflare.com"
        hint="We query DNSSEC (DS + validation flag) and CAA records over DNS-over-HTTPS."
        onSubmit={(domain) => run({ domain })}
      />

      {data && (
        <>
          <GradeBadge grade={data.grade} title={data.domain} summary={data.summary} />

          <CheckList checks={data.checks} />

          {data.caa.length > 0 && (
            <details className="rounded-xl border border-white/10 bg-white/5 p-4 text-sm">
              <summary className="cursor-pointer text-white/60">CAA records ({data.caa.length})</summary>
              <ul className="mt-3 space-y-1 font-mono text-xs text-white/80">
                {data.caa.map((r, i) => (
                  <li key={i} className="break-all">
                    {r}
                  </li>
                ))}
              </ul>
            </details>
          )}
        </>
      )}
    </div>
  );
}
