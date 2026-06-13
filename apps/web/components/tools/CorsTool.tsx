'use client';

import { useToolRequest } from './useToolRequest';
import { TargetForm } from './TargetForm';
import { CheckList } from './CheckRow';
import { VerdictBanner, severityTone } from './VerdictBanner';
import type { CorsResult } from '../../lib/tools/cors';

const VERDICT_TITLE: Record<CorsResult['verdict'], string> = {
  vulnerable: 'Vulnerable',
  risky: 'Risky configuration',
  permissive: 'Permissive (wildcard)',
  restricted: 'Looks safe',
};

export function CorsTool() {
  const { loading, error, data, run } = useToolRequest<CorsResult>('/api/tools/cors');

  return (
    <div className="space-y-5">
      <TargetForm
        label="API or page URL"
        placeholder="https://api.example.com/me"
        buttonLabel="Test CORS"
        loading={loading}
        error={error}
        sample="https://example.com"
        hint="We send a request with a forged Origin header and inspect the CORS response headers."
        onSubmit={(url) => run({ url })}
      />

      {data && (
        <>
          <VerdictBanner
            tone={severityTone(data.severity)}
            title={VERDICT_TITLE[data.verdict]}
            summary={data.summary}
          />

          <CheckList checks={data.checks} />

          <details className="rounded-xl border border-white/10 bg-white/5 p-4 text-sm">
            <summary className="cursor-pointer text-white/60">Response details</summary>
            <dl className="mt-3 grid grid-cols-[auto,1fr] gap-x-4 gap-y-1.5 font-mono text-xs">
              <dt className="text-white/40">HTTP status</dt>
              <dd className="text-white/80">{data.httpStatus}</dd>
              <dt className="text-white/40">Probe Origin</dt>
              <dd className="break-all text-white/80">{data.probeOrigin}</dd>
              <dt className="text-white/40">Allow-Origin</dt>
              <dd className="break-all text-white/80">{data.headers.allowOrigin ?? '(none)'}</dd>
              <dt className="text-white/40">Allow-Credentials</dt>
              <dd className="text-white/80">{String(data.headers.allowCredentials)}</dd>
              {data.headers.allowMethods && (
                <>
                  <dt className="text-white/40">Allow-Methods</dt>
                  <dd className="break-all text-white/80">{data.headers.allowMethods}</dd>
                </>
              )}
              {data.headers.allowHeaders && (
                <>
                  <dt className="text-white/40">Allow-Headers</dt>
                  <dd className="break-all text-white/80">{data.headers.allowHeaders}</dd>
                </>
              )}
            </dl>
          </details>
        </>
      )}
    </div>
  );
}
