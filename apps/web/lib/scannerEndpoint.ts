import 'server-only';
import { getAdminClient } from './supabase/admin';

// How long a heartbeat stays "fresh". The local agent re-writes updated_at every
// ~30s; allowing a few missed beats avoids false "offline" on a brief hiccup.
const FRESH_MS = 120_000;

export type ScannerEndpoint =
  | { status: 'live'; url: string }
  | { status: 'stale'; url: string; ageMs: number } // PC was online but heartbeat went quiet
  | { status: 'missing' }; // no row yet, or Supabase not configured

/**
 * Read the local scanner's current public URL, published by the on-PC agent
 * (tools/scanner-online.mjs). Lets a changing tunnel URL be picked up live,
 * with no Vercel env edit or redeploy. Never throws.
 */
export async function getDynamicScannerUrl(): Promise<ScannerEndpoint> {
  const admin = getAdminClient();
  if (!admin) return { status: 'missing' };

  try {
    const { data, error } = await admin
      .from('scanner_endpoint')
      .select('url, updated_at')
      .eq('id', 1)
      .maybeSingle();

    if (error || !data?.url) return { status: 'missing' };

    const ageMs = Date.now() - new Date(data.updated_at as string).getTime();
    if (ageMs > FRESH_MS) return { status: 'stale', url: data.url as string, ageMs };
    return { status: 'live', url: data.url as string };
  } catch {
    return { status: 'missing' };
  }
}

export type ResolvedScanner = { url: string } | { error: string; status: number };

/**
 * Where to send a scan: a pinned SCANNER_URL (local dev / 24-7 host), or the
 * live tunnel URL the on-PC agent published to Supabase. Shared by the URL/code
 * proxy (/api/scan) and the repo proxy (/api/scan/repo). Never throws.
 */
export async function resolveScannerUrl(): Promise<ResolvedScanner> {
  const pinned = process.env.SCANNER_URL?.trim() || '';
  if (pinned) return { url: pinned };

  const ep = await getDynamicScannerUrl();
  if (ep.status === 'live') return { url: ep.url };
  if (ep.status === 'stale') {
    return {
      error: 'The scanner is offline right now (the host machine looks powered off). Please try again later.',
      status: 503,
    };
  }
  return { error: 'The scanner is not connected right now. Please try again shortly.', status: 503 };
}

// Gateway/edge errors that come from the tunnel provider itself (not the scanner)
// when the tunnel is mid-blip. Safe to retry — the scanner never saw the request.
const TUNNEL_GATEWAY_STATUSES = new Set([502, 503, 504, 521, 522, 523, 525, 530]);

/**
 * POST to the resolved scanner, retrying once when the *tunnel* blips. loca.lt's
 * free tunnels drop and reopen constantly; a request that lands in that
 * seconds-long window fails at the connection level (or gets a provider gateway
 * error page) even though the scanner itself is healthy. One quick retry lands on
 * the reopened tunnel instead of surfacing a spurious "scanner unavailable".
 *
 * A genuine scan timeout (our AbortSignal fired) is NOT retried — the scan already
 * spent its full budget, so trying again would just make the user wait twice.
 */
export async function postScanner(
  scannerUrl: string,
  path: string,
  init: Omit<RequestInit, 'signal'> & { timeoutMs: number }
): Promise<Response> {
  const { timeoutMs, ...rest } = init;
  const target = `${scannerUrl.replace(/\/+$/, '')}${path}`;
  let lastErr: unknown;

  for (let attempt = 0; attempt < 2; attempt++) {
    if (attempt > 0) await new Promise((r) => setTimeout(r, 1200)); // give the tunnel a moment to reopen
    try {
      const res = await fetch(target, { ...rest, signal: AbortSignal.timeout(timeoutMs) });
      if (attempt === 0 && TUNNEL_GATEWAY_STATUSES.has(res.status)) {
        lastErr = new Error(`tunnel gateway ${res.status}`);
        continue; // provider edge error, not the scanner — try once more
      }
      return res;
    } catch (err) {
      // The scan hit its time budget; retrying would only double the wait.
      if (err instanceof Error && (err.name === 'TimeoutError' || err.name === 'AbortError')) throw err;
      lastErr = err; // fast connection failure (tunnel between reopens) — retry once
    }
  }
  throw lastErr ?? new Error('scanner request failed');
}
