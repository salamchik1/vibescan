'use client';

import { useToolRequest } from './useToolRequest';
import { TargetForm } from './TargetForm';
import { CheckList } from './CheckRow';
import { GradeBadge } from './GradeBadge';
import type { SecurityTxtResult } from '../../lib/tools/securityTxt';

export function SecurityTxtTool() {
  const { loading, error, data, run } = useToolRequest<SecurityTxtResult>('/api/tools/security-txt');

  return (
    <div className="space-y-5">
      <TargetForm
        label="Domain"
        placeholder="example.com"
        buttonLabel="Validate"
        loading={loading}
        error={error}
        sample="google.com"
        hint="We fetch /.well-known/security.txt (then /security.txt) and validate it against RFC 9116."
        onSubmit={(domain) => run({ domain })}
      />

      {data && (
        <>
          <GradeBadge
            grade={data.grade}
            title={data.url}
            summary={data.summary}
            meta={`${data.fields.length} field(s)${data.signed ? ' · signed' : ''}`}
          />

          <CheckList checks={data.checks} />

          {data.fields.length > 0 && (
            <details className="rounded-xl border border-ink/10 bg-white p-4 text-sm">
              <summary className="cursor-pointer text-ink/60">Parsed fields ({data.fields.length})</summary>
              <ul className="mt-3 space-y-1.5 font-mono text-xs">
                {data.fields.map((f, i) => (
                  <li key={i} className="flex flex-wrap gap-x-2">
                    <span className="text-primary">{f.name}:</span>
                    <span className="break-all text-ink/70">{f.value}</span>
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
