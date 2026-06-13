import { NextResponse } from 'next/server';
import { assertSafeHostname, SsrfError } from '../../../../lib/server/ssrf';
import { validateSecurityTxt } from '../../../../lib/tools/securityTxt';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const MAX_BYTES = 64 * 1024;

async function tryFetch(url: string): Promise<{ ok: boolean; body: string; status: number }> {
  const res = await fetch(url, {
    headers: { 'user-agent': 'VibeScan-securitytxt-Validator/1.0 (+https://vibescan.dev)' },
    redirect: 'follow',
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) return { ok: false, body: '', status: res.status };
  const buf = await res.arrayBuffer();
  const body = Buffer.from(buf.slice(0, MAX_BYTES)).toString('utf8');
  return { ok: true, body, status: res.status };
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

  const wellKnownUrl = `https://${domain}/.well-known/security.txt`;
  const legacyUrl = `https://${domain}/security.txt`;

  let found: { url: string; wellKnown: boolean; body: string } | null = null;
  try {
    const wk = await tryFetch(wellKnownUrl);
    if (wk.ok && wk.body.trim()) {
      found = { url: wellKnownUrl, wellKnown: true, body: wk.body };
    } else {
      const legacy = await tryFetch(legacyUrl);
      if (legacy.ok && legacy.body.trim()) {
        found = { url: legacyUrl, wellKnown: false, body: legacy.body };
      }
    }
  } catch {
    return NextResponse.json(
      { error: `Could not reach ${domain}. It may be down or blocking requests.` },
      { status: 502 }
    );
  }

  if (!found) {
    return NextResponse.json(
      {
        error: `No security.txt found at ${wellKnownUrl} or ${legacyUrl}. Add one so researchers know how to report issues.`,
      },
      { status: 404 }
    );
  }

  const result = validateSecurityTxt({
    url: found.url,
    wellKnown: found.wellKnown,
    servedOverHttps: found.url.startsWith('https://'),
    body: found.body,
  });

  return NextResponse.json(result);
}
