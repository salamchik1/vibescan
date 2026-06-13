import 'server-only';
import type { ScanResult } from '@vibescan/findings';
import { getAdminClient } from './supabase/admin';

export interface ScanRow {
  id: string;
  created_at: string;
  user_id: string | null;
  target: string;
  mode: string;
  score: number;
  verdict: string;
  counts: Record<string, number>;
  result: ScanResult;
}

/** A trimmed row for list views (dashboard) — no heavy `result` payload. */
export type ScanListItem = Pick<
  ScanRow,
  'id' | 'created_at' | 'target' | 'mode' | 'score' | 'verdict' | 'counts'
>;

/**
 * Persist a finished scan. Returns the new row id, or null if Supabase isn't
 * configured (in which case the scan still works, it just isn't saved).
 * Never throws — persistence must never break the scan response.
 */
export async function saveScan(
  result: ScanResult,
  userId: string | null
): Promise<string | null> {
  const admin = getAdminClient();
  if (!admin) return null;

  const target =
    result.mode === 'code' ? 'Pasted code' : result.url || 'Unknown target';

  try {
    const { data, error } = await admin
      .from('scans')
      .insert({
        user_id: userId,
        target,
        mode: result.mode ?? 'url',
        score: result.score,
        verdict: result.verdict,
        counts: result.counts,
        result,
      })
      .select('id')
      .single();

    if (error) {
      console.error('[scans] save failed:', error.message);
      return null;
    }
    return data.id as string;
  } catch (err) {
    console.error('[scans] save threw:', err);
    return null;
  }
}

/** Load a single scan by id (public-by-link). Null if missing / not configured. */
export async function getScan(id: string): Promise<ScanRow | null> {
  const admin = getAdminClient();
  if (!admin) return null;

  const { data, error } = await admin
    .from('scans')
    .select('*')
    .eq('id', id)
    .maybeSingle();

  if (error || !data) return null;
  return data as ScanRow;
}
