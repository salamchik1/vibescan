import { NextResponse } from 'next/server';
import type { ScanResult } from '@vibescan/findings';
import { saveScan } from '../../../lib/scans';
import { getCurrentUser } from '../../../lib/supabase/server';
import { getDynamicScannerUrl } from '../../../lib/scannerEndpoint';

// These run server-side only and are never exposed to the browser.
// SCANNER_URL, when set, pins a fixed scanner (local dev = http://localhost:8787,
// or a 24/7 host like Render/Fly). When it is NOT set, we look up the local
// agent's current tunnel URL from Supabase at request time — so a changing
// tunnelmole URL is picked up live, with no env edit or redeploy.
const STATIC_SCANNER_URL = process.env.SCANNER_URL?.trim() || '';
const SCANNER_SECRET = process.env.SCANNER_SHARED_SECRET ?? '';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const MAX_CODE_LENGTH = 512 * 1024; // keep in step with the scanner's body limit

type ResolvedScanner = { url: string } | { error: string; status: number };

/** Where to send this scan: a pinned URL, or the live tunnel URL from Supabase. */
async function resolveScannerUrl(): Promise<ResolvedScanner> {
  if (STATIC_SCANNER_URL) return { url: STATIC_SCANNER_URL };

  const ep = await getDynamicScannerUrl();
  if (ep.status === 'live') return { url: ep.url };
  if (ep.status === 'stale') {
    return {
      error: 'The scanner is offline right now (the host machine looks powered off). Please try again later.',
      status: 503,
    };
  }
  return {
    error: 'The scanner is not connected right now. Please try again shortly.',
    status: 503,
  };
}

export async function POST(req: Request) {
  let body: { url?: unknown; code?: unknown };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'Invalid request.' }, { status: 400 });
  }

  const code = typeof body.code === 'string' ? body.code : '';
  let payload: { url: string } | { code: string };

  if (code.trim()) {
    if (code.length > MAX_CODE_LENGTH) {
      return NextResponse.json({ error: 'That is a lot of code — please paste under ~500 KB.' }, { status: 400 });
    }
    payload = { code };
  } else {
    const raw = typeof body.url === 'string' ? body.url.trim() : '';
    if (!raw) {
      return NextResponse.json({ error: 'Please enter a URL or paste some code.' }, { status: 400 });
    }
    // Be forgiving: add https:// if the user omitted the scheme.
    payload = { url: /^https?:\/\//i.test(raw) ? raw : `https://${raw}` };
  }

  const scanner = await resolveScannerUrl();
  if ('error' in scanner) {
    return NextResponse.json({ error: scanner.error }, { status: scanner.status });
  }

  try {
    const res = await fetch(`${scanner.url.replace(/\/+$/, '')}/scan`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-scan-secret': SCANNER_SECRET },
      body: JSON.stringify(payload),
      // Give the scanner room to finish (Playwright + probes).
      signal: AbortSignal.timeout(90_000),
    });
    const data = await res.json().catch(() => ({ error: 'Scanner returned an unreadable response.' }));

    // Persist the finished scan so it lives at /r/{id}. Best-effort: if Supabase
    // isn't configured (or saving fails) the scan response is returned anyway.
    if (res.ok && data && typeof data === 'object' && Array.isArray(data.findings)) {
      const user = await getCurrentUser().catch(() => null);
      const id = await saveScan(data as ScanResult, user?.id ?? null);
      if (id) return NextResponse.json({ ...data, id }, { status: res.status });
    }

    return NextResponse.json(data, { status: res.status });
  } catch {
    return NextResponse.json(
      { error: 'The scanner is unavailable right now. Please try again shortly.' },
      { status: 502 }
    );
  }
}
