import { NextResponse } from 'next/server';
import type { Breach, BreachResult } from '../../../../lib/tools/breach';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// HIBP's breach API requires an API key (server-side only, never exposed to the browser).
const HIBP_API_KEY = process.env.HIBP_API_KEY ?? '';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

interface HibpBreach {
  Name: string;
  Domain: string;
  BreachDate: string;
  PwnCount: number;
  Description: string;
  DataClasses: string[];
  IsVerified: boolean;
  IsSensitive: boolean;
}

export async function POST(req: Request) {
  if (!HIBP_API_KEY) {
    return NextResponse.json(
      {
        error:
          'Breach checking isn’t configured on this server. Set the HIBP_API_KEY environment variable (Have I Been Pwned API key) to enable it.',
      },
      { status: 501 }
    );
  }

  let body: { email?: unknown };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'Invalid request.' }, { status: 400 });
  }

  const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
  if (!EMAIL_RE.test(email)) {
    return NextResponse.json({ error: 'Please enter a valid email address.' }, { status: 400 });
  }

  const url = `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(
    email
  )}?truncateResponse=false`;

  let res: Response;
  try {
    res = await fetch(url, {
      headers: {
        'hibp-api-key': HIBP_API_KEY,
        'user-agent': 'VibeScan-Breach-Checker/1.0 (+https://vibescan.dev)',
      },
      signal: AbortSignal.timeout(12_000),
    });
  } catch {
    return NextResponse.json(
      { error: 'Could not reach Have I Been Pwned. Please try again shortly.' },
      { status: 502 }
    );
  }

  // 404 = the address appears in no breaches (a clean result, not an error).
  if (res.status === 404) {
    const result: BreachResult = { email, pwned: false, breachCount: 0, breaches: [] };
    return NextResponse.json(result);
  }

  if (res.status === 429) {
    return NextResponse.json(
      { error: 'Rate limited by Have I Been Pwned. Please wait a few seconds and try again.' },
      { status: 429 }
    );
  }
  if (res.status === 401) {
    return NextResponse.json(
      { error: 'The configured Have I Been Pwned API key was rejected.' },
      { status: 502 }
    );
  }
  if (!res.ok) {
    return NextResponse.json(
      { error: `Have I Been Pwned returned an unexpected response (${res.status}).` },
      { status: 502 }
    );
  }

  let raw: HibpBreach[];
  try {
    raw = (await res.json()) as HibpBreach[];
  } catch {
    return NextResponse.json({ error: 'Unreadable response from Have I Been Pwned.' }, { status: 502 });
  }

  const breaches: Breach[] = raw
    .map((b) => ({
      name: b.Name,
      domain: b.Domain,
      breachDate: b.BreachDate,
      pwnCount: b.PwnCount,
      description: b.Description,
      dataClasses: b.DataClasses ?? [],
      isVerified: b.IsVerified,
      isSensitive: b.IsSensitive,
    }))
    .sort((a, b) => (a.breachDate < b.breachDate ? 1 : -1));

  const result: BreachResult = {
    email,
    pwned: breaches.length > 0,
    breachCount: breaches.length,
    breaches,
  };
  return NextResponse.json(result);
}
