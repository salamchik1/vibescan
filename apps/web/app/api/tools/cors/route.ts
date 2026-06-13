import { NextResponse } from 'next/server';
import { assertSafeUrl, SsrfError } from '../../../../lib/server/ssrf';
import type { CorsResult } from '../../../../lib/tools/cors';
import type { Check } from '../../../../components/tools/CheckRow';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const PROBE_ORIGIN = 'https://vibescan-cors-probe.example';

/** Fetch the target once with a given Origin header and return the CORS headers. */
async function probe(url: string, origin: string) {
  const res = await fetch(url, {
    method: 'GET',
    headers: { origin, 'user-agent': 'VibeScan-CORS-Tester/1.0 (+https://vibescan.dev)' },
    redirect: 'manual',
    signal: AbortSignal.timeout(10_000),
  });
  const h = res.headers;
  return {
    status: res.status,
    allowOrigin: h.get('access-control-allow-origin'),
    allowCredentials: (h.get('access-control-allow-credentials') ?? '').toLowerCase() === 'true',
    allowMethods: h.get('access-control-allow-methods'),
    allowHeaders: h.get('access-control-allow-headers'),
  };
}

export async function POST(req: Request) {
  let body: { url?: unknown };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'Invalid request.' }, { status: 400 });
  }

  const raw = typeof body.url === 'string' ? body.url.trim() : '';
  if (!raw) return NextResponse.json({ error: 'Please enter a URL.' }, { status: 400 });
  const target = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;

  let url: URL;
  try {
    url = await assertSafeUrl(target);
  } catch (e) {
    if (e instanceof SsrfError) return NextResponse.json({ error: e.message }, { status: 400 });
    return NextResponse.json({ error: 'Could not validate that URL.' }, { status: 400 });
  }

  let arbitrary: Awaited<ReturnType<typeof probe>>;
  try {
    arbitrary = await probe(url.toString(), PROBE_ORIGIN);
  } catch {
    return NextResponse.json(
      { error: 'Could not reach that URL. It may be down, blocking requests, or too slow.' },
      { status: 502 }
    );
  }

  // Only spend a second request probing `null` when the first showed reflection
  // behaviour worth confirming.
  let allowsNull = false;
  if (arbitrary.allowOrigin) {
    try {
      const nullProbe = await probe(url.toString(), 'null');
      allowsNull = nullProbe.allowOrigin === 'null';
    } catch {
      /* best-effort */
    }
  }

  const acao = arbitrary.allowOrigin;
  const acac = arbitrary.allowCredentials;
  const reflectsArbitrary = acao === PROBE_ORIGIN;
  const isWildcard = acao === '*';

  const checks: Check[] = [];

  if (!acao) {
    checks.push({
      id: 'acao',
      label: 'Cross-origin access',
      status: 'pass',
      detail:
        'No Access-Control-Allow-Origin header was returned, so browsers block cross-origin reads by default.',
    });
  } else if (reflectsArbitrary && acac) {
    checks.push({
      id: 'acao',
      label: 'Reflects any origin with credentials',
      status: 'fail',
      detail: `The server echoed our arbitrary Origin (${PROBE_ORIGIN}) and sets Allow-Credentials: true. Any website can read authenticated responses on behalf of a logged-in user.`,
    });
  } else if (reflectsArbitrary) {
    checks.push({
      id: 'acao',
      label: 'Reflects any origin',
      status: 'warn',
      detail:
        'The server echoes whatever Origin it receives. Without credentials the impact is limited, but it usually signals an allow-list that is too loose.',
    });
  } else if (isWildcard) {
    checks.push({
      id: 'acao',
      label: 'Wildcard Allow-Origin (*)',
      status: 'warn',
      detail:
        'Access-Control-Allow-Origin is *. Fine for genuinely public, unauthenticated data; never combine it with credentials (browsers forbid that anyway).',
    });
  } else {
    checks.push({
      id: 'acao',
      label: 'Restricted Allow-Origin',
      status: 'pass',
      detail: `The server returned a fixed origin (${acao}) rather than reflecting ours — a sound, restrictive policy.`,
    });
  }

  if (acac) {
    checks.push({
      id: 'acac',
      label: 'Access-Control-Allow-Credentials',
      status: reflectsArbitrary || allowsNull ? 'fail' : 'warn',
      detail:
        'Credentials (cookies, HTTP auth) are allowed cross-origin. This is only safe with a strict, fixed origin allow-list.',
    });
  }

  if (allowsNull) {
    checks.push({
      id: 'null',
      label: "Allows the 'null' origin",
      status: acac ? 'fail' : 'warn',
      detail:
        "The server accepts Origin: null, which sandboxed iframes and some redirects produce — a known way to bypass origin checks.",
    });
  }

  if (arbitrary.allowMethods) {
    checks.push({
      id: 'methods',
      label: 'Access-Control-Allow-Methods',
      status: 'info',
      detail: arbitrary.allowMethods,
    });
  }

  // Verdict + severity.
  let verdict: CorsResult['verdict'];
  let severity: CorsResult['severity'];
  let summary: string;
  if ((reflectsArbitrary || allowsNull) && acac) {
    verdict = 'vulnerable';
    severity = 'critical';
    summary = 'Exploitable CORS misconfiguration: any origin can read credentialed responses.';
  } else if (reflectsArbitrary || allowsNull) {
    verdict = 'risky';
    severity = 'medium';
    summary = 'The server reflects untrusted origins. Tighten this to a fixed allow-list.';
  } else if (isWildcard) {
    verdict = 'permissive';
    severity = 'low';
    summary = 'Open to all origins via *. Acceptable only for public, non-credentialed data.';
  } else {
    verdict = 'restricted';
    severity = 'none';
    summary = acao
      ? 'CORS is configured restrictively — no arbitrary-origin reflection detected.'
      : 'No CORS headers exposed; cross-origin reads are blocked by default.';
  }

  const result: CorsResult = {
    url: url.toString(),
    httpStatus: arbitrary.status,
    probeOrigin: PROBE_ORIGIN,
    headers: {
      allowOrigin: acao,
      allowCredentials: acac,
      allowMethods: arbitrary.allowMethods,
      allowHeaders: arbitrary.allowHeaders,
    },
    reflectsArbitrary,
    allowsNull,
    verdict,
    severity,
    summary,
    checks,
  };

  return NextResponse.json(result);
}
