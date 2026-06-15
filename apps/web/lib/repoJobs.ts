import 'server-only';
import { getAdminClient } from './supabase/admin';

export type RepoJobStatus = 'queued' | 'cloning' | 'scanning' | 'done' | 'failed';

export interface RepoJobView {
  status: RepoJobStatus;
  scanId: string | null;
  error: string | null;
}

/**
 * Read a repo-scan job straight from Supabase (service role). Polling goes
 * through here — never through the scanner — so it works across the Vercel↔scanner
 * boundary and survives a scanner restart or rotated tunnel URL. Null if the job
 * is unknown or Supabase isn't configured.
 */
export async function getRepoJob(id: string): Promise<RepoJobView | null> {
  const admin = getAdminClient();
  if (!admin) return null;

  const { data, error } = await admin
    .from('repo_scan_jobs')
    .select('status, scan_id, error')
    .eq('id', id)
    .maybeSingle();

  if (error || !data) return null;
  return {
    status: data.status as RepoJobStatus,
    scanId: (data.scan_id as string | null) ?? null,
    error: (data.error as string | null) ?? null,
  };
}
