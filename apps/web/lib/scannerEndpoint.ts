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
