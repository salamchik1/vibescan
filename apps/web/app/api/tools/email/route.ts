import { NextResponse } from 'next/server';
import { assertSafeHostname, SsrfError } from '../../../../lib/server/ssrf';
import { dohQuery, unquoteTxt, RECORD_TYPE } from '../../../../lib/server/doh';
import type { EmailResult } from '../../../../lib/tools/email';
import type { Check } from '../../../../components/tools/CheckRow';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/** Pull the first TXT record matching a predicate. */
function findTxt(answers: { data: string }[] | undefined, test: (v: string) => boolean): string | null {
  if (!answers) return null;
  for (const a of answers) {
    const v = unquoteTxt(a.data);
    if (test(v)) return v;
  }
  return null;
}

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

  let mxRes, spfRes, dmarcRes;
  try {
    [mxRes, spfRes, dmarcRes] = await Promise.all([
      dohQuery(domain, RECORD_TYPE.MX),
      dohQuery(domain, RECORD_TYPE.TXT),
      dohQuery(`_dmarc.${domain}`, RECORD_TYPE.TXT),
    ]);
  } catch {
    return NextResponse.json(
      { error: 'DNS lookup failed. Please try again in a moment.' },
      { status: 502 }
    );
  }

  const mx = (mxRes.Answer ?? [])
    .map((a) => a.data.replace(/^\d+\s+/, '').replace(/\.$/, ''))
    .filter(Boolean)
    .sort();

  const spf = findTxt(spfRes.Answer, (v) => /^v=spf1\b/i.test(v));
  const dmarc = findTxt(dmarcRes.Answer, (v) => /^v=dmarc1\b/i.test(v));
  const dmarcPolicy = dmarc?.match(/\bp\s*=\s*(none|quarantine|reject)\b/i)?.[1]?.toLowerCase() ?? null;

  const checks: Check[] = [];

  // MX.
  checks.push(
    mx.length > 0
      ? { id: 'mx', label: 'MX records', status: 'info', detail: `Mail handled by: ${mx.join(', ')}` }
      : {
          id: 'mx',
          label: 'MX records',
          status: 'info',
          detail: 'No MX records. This domain does not receive email (still worth protecting from spoofing).',
        }
  );

  // SPF.
  if (!spf) {
    checks.push({
      id: 'spf',
      label: 'SPF',
      status: 'fail',
      detail: 'No SPF record. Anyone can forge mail from this domain — add a v=spf1 TXT record.',
    });
  } else {
    const all = spf.match(/([~\-+?])all\b/i)?.[1];
    const soft = all === '~';
    const hard = all === '-';
    checks.push({
      id: 'spf',
      label: 'SPF',
      status: hard ? 'pass' : soft ? 'warn' : 'fail',
      detail: hard
        ? 'Ends in -all (hard fail): unauthorised senders are rejected.'
        : soft
          ? 'Ends in ~all (soft fail): forged mail is accepted but marked. Consider -all once you’ve confirmed all senders.'
          : all === '+'
            ? 'Ends in +all, which authorises any sender — this defeats SPF. Use -all.'
            : 'SPF record present but has no all mechanism, so its enforcement is undefined.',
    });
  }

  // DMARC.
  if (!dmarc) {
    checks.push({
      id: 'dmarc',
      label: 'DMARC',
      status: 'fail',
      detail: 'No DMARC record at _dmarc.' + domain + '. Add one to control how spoofed mail is handled.',
    });
  } else if (dmarcPolicy === 'reject' || dmarcPolicy === 'quarantine') {
    checks.push({
      id: 'dmarc',
      label: 'DMARC',
      status: 'pass',
      detail: `Policy p=${dmarcPolicy}: spoofed mail is ${dmarcPolicy === 'reject' ? 'rejected' : 'quarantined'}.`,
    });
  } else {
    checks.push({
      id: 'dmarc',
      label: 'DMARC',
      status: 'warn',
      detail:
        'Policy is p=none — you receive reports but spoofed mail is still delivered. Move to quarantine, then reject.',
    });
  }

  // Grade.
  const hasSpf = !!spf;
  const strongSpf = /-all\b/i.test(spf ?? '');
  const strongDmarc = dmarcPolicy === 'reject' || dmarcPolicy === 'quarantine';
  let grade: EmailResult['grade'];
  if (strongSpf && dmarcPolicy === 'reject') grade = 'A';
  else if (hasSpf && strongDmarc) grade = 'B';
  else if (hasSpf && dmarc) grade = 'C';
  else if (hasSpf || dmarc) grade = 'D';
  else grade = 'F';

  const summary =
    grade === 'A'
      ? 'Strong anti-spoofing: SPF hard-fail and DMARC reject are in place.'
      : grade === 'F'
        ? 'No SPF or DMARC — this domain can be freely spoofed.'
        : 'Anti-spoofing is partially configured; tighten SPF and DMARC.';

  const result: EmailResult = { domain, mx, spf, dmarc, dmarcPolicy, grade, summary, checks };
  return NextResponse.json(result);
}
