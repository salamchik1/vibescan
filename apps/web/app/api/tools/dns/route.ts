import { NextResponse } from 'next/server';
import { assertSafeHostname, SsrfError } from '../../../../lib/server/ssrf';
import { dohQuery, RECORD_TYPE } from '../../../../lib/server/doh';
import type { DnsResult } from '../../../../lib/tools/dns';
import type { Check } from '../../../../components/tools/CheckRow';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST(req: Request) {
  let body: { domain?: unknown };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'Invalid request.' }, { status: 400 });
  }

  let domain: string;
  try {
    domain = assertSafeHostname(typeof body.domain === 'string' ? body.domain : '');
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof SsrfError ? e.message : 'Invalid domain.' },
      { status: 400 }
    );
  }

  let aRes, dsRes, caaRes;
  try {
    // The A query carries the AD flag (resolver DNSSEC validation); DS confirms the
    // chain of trust is published at the parent zone.
    [aRes, dsRes, caaRes] = await Promise.all([
      dohQuery(domain, RECORD_TYPE.A),
      dohQuery(domain, RECORD_TYPE.DS),
      dohQuery(domain, RECORD_TYPE.CAA),
    ]);
  } catch {
    return NextResponse.json(
      { error: 'DNS lookup failed. Please try again in a moment.' },
      { status: 502 }
    );
  }

  const hasDs = (dsRes.Answer ?? []).length > 0;
  const dnssec = aRes.AD && hasDs;
  const caa = (caaRes.Answer ?? []).map((a) => a.data.trim()).filter(Boolean);

  const checks: Check[] = [];

  // DNSSEC.
  if (dnssec) {
    checks.push({
      id: 'dnssec',
      label: 'DNSSEC',
      status: 'pass',
      detail: 'DNSSEC is enabled and the resolver validated the signatures (AD flag set), so DNS answers cannot be forged.',
    });
  } else if (hasDs) {
    checks.push({
      id: 'dnssec',
      label: 'DNSSEC',
      status: 'warn',
      detail: 'A DS record exists but the answer was not validated. The chain may be incomplete or broken — verify your DNSSEC setup.',
    });
  } else {
    checks.push({
      id: 'dnssec',
      label: 'DNSSEC',
      status: 'fail',
      detail: 'DNSSEC is not enabled (no DS record at the parent). Responses can be spoofed via cache poisoning. Enable DNSSEC at your registrar/DNS host.',
    });
  }

  // CAA.
  if (caa.length > 0) {
    const issuers = caa
      .map((r) => r.match(/issue(?:wild)?\s+"([^"]*)"/i)?.[1])
      .filter(Boolean) as string[];
    checks.push({
      id: 'caa',
      label: 'CAA records',
      status: 'pass',
      detail: issuers.length
        ? `Only these CAs may issue certificates: ${[...new Set(issuers)].join(', ')}.`
        : 'CAA records are present, restricting certificate issuance.',
    });
  } else {
    checks.push({
      id: 'caa',
      label: 'CAA records',
      status: 'warn',
      detail: 'No CAA records. Any certificate authority can issue certificates for this domain. Add a CAA record to allow-list your CA.',
    });
  }

  // Grade.
  let grade: DnsResult['grade'];
  if (dnssec && caa.length > 0) grade = 'A';
  else if (dnssec) grade = 'B';
  else if (caa.length > 0) grade = 'C';
  else grade = 'F';

  const summary =
    grade === 'A'
      ? 'DNSSEC validated and certificate issuance is locked down with CAA.'
      : grade === 'F'
        ? 'No DNSSEC and no CAA — DNS and certificate issuance are unprotected.'
        : 'Some DNS hardening is in place, but there are gaps to close.';

  const result: DnsResult = { domain, dnssec, hasDs, caa, grade, summary, checks };
  return NextResponse.json(result);
}
