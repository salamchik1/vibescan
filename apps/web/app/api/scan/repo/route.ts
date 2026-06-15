import { NextResponse } from 'next/server';
import { getCurrentUser } from '../../../../lib/supabase/server';
import { resolveScannerUrl } from '../../../../lib/scannerEndpoint';

// Server-side only. Enqueues an async repository scan on the scanner and returns
// a jobId; the browser then polls GET /api/scan/repo/[id] (which reads Supabase
// directly). This call only enqueues, so it is fast.
const SCANNER_SECRET = process.env.SCANNER_SHARED_SECRET ?? '';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST(req: Request) {
  let body: { repoUrl?: unknown };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'Invalid request.' }, { status: 400 });
  }

  const repoUrl = typeof body.repoUrl === 'string' ? body.repoUrl.trim() : '';
  if (!repoUrl) {
    return NextResponse.json({ error: 'Enter a public repository URL.' }, { status: 400 });
  }
  if (!/^https:\/\/(github\.com|gitlab\.com|bitbucket\.org)\//i.test(repoUrl)) {
    return NextResponse.json(
      { error: 'Only public GitHub, GitLab and Bitbucket https URLs can be scanned.' },
      { status: 400 }
    );
  }

  const scanner = await resolveScannerUrl();
  if ('error' in scanner) {
    return NextResponse.json({ error: scanner.error }, { status: scanner.status });
  }

  // Attach the signed-in user (if any) so the job + saved scan are owned by them.
  const user = await getCurrentUser().catch(() => null);

  try {
    const res = await fetch(`${scanner.url.replace(/\/+$/, '')}/scan/repo`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-scan-secret': SCANNER_SECRET,
        // Skip localtunnel's reminder interstitial so we get JSON, not HTML.
        'bypass-tunnel-reminder': '1',
      },
      body: JSON.stringify({ repoUrl, userId: user?.id ?? null }),
      // Enqueue only — should return almost immediately.
      signal: AbortSignal.timeout(15_000),
    });
    const data = await res.json().catch(() => ({ error: 'Scanner returned an unreadable response.' }));
    return NextResponse.json(data, { status: res.status });
  } catch {
    return NextResponse.json(
      { error: 'The scanner is unavailable right now. Please try again shortly.' },
      { status: 502 }
    );
  }
}
