import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import type { ScanResult } from '@vibescan/findings';

// Service-role Supabase access for the async repo-scan pipeline. The scanner
// owns job execution in-process but writes every state transition here, so the
// web app can poll Supabase directly (surviving scanner restarts / tunnel
// rotation). Reads the same env the web app uses (loaded from the root .env by
// config.ts). When Supabase isn't configured every function is a safe no-op and
// repo scanning is simply unavailable.

const SUPABASE_URL =
  process.env.SUPABASE_URL ?? process.env.NEXT_PUBLIC_SUPABASE_URL ?? '';
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY ?? '';

export const repoJobsConfigured = Boolean(SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY);

export type JobStatus = 'queued' | 'cloning' | 'scanning' | 'done' | 'failed';

let cached: SupabaseClient | null = null;
function client(): SupabaseClient | null {
  if (!repoJobsConfigured) return null;
  if (cached) return cached;
  cached = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  return cached;
}

export interface RepoJob {
  id: string;
  repo_url: string;
  status: JobStatus;
  scan_id: string | null;
  error: string | null;
}

/** Insert a 'queued' job. Returns the new job id, or null if Supabase is off. */
export async function createJob(repoUrl: string, userId: string | null): Promise<string | null> {
  const db = client();
  if (!db) return null;
  const { data, error } = await db
    .from('repo_scan_jobs')
    .insert({ repo_url: repoUrl, user_id: userId, status: 'queued' })
    .select('id')
    .single();
  if (error) {
    console.error('[repo-jobs] create failed:', error.message);
    return null;
  }
  return data.id as string;
}

/** Move a job to a new running status. Best-effort; never throws. */
export async function updateJobStatus(id: string, status: JobStatus): Promise<void> {
  const db = client();
  if (!db) return;
  await db
    .from('repo_scan_jobs')
    .update({ status, updated_at: new Date().toISOString() })
    .eq('id', id)
    .then(undefined, (e) => console.error('[repo-jobs] status update threw:', e));
}

/** Mark a job done and link the persisted scan row. */
export async function completeJob(id: string, scanId: string | null): Promise<void> {
  const db = client();
  if (!db) return;
  await db
    .from('repo_scan_jobs')
    .update({ status: 'done', scan_id: scanId, updated_at: new Date().toISOString() })
    .eq('id', id)
    .then(undefined, (e) => console.error('[repo-jobs] complete threw:', e));
}

/** Mark a job failed with a safe, non-leaky message. */
export async function failJob(id: string, message: string): Promise<void> {
  const db = client();
  if (!db) return;
  await db
    .from('repo_scan_jobs')
    .update({ status: 'failed', error: message.slice(0, 300), updated_at: new Date().toISOString() })
    .eq('id', id)
    .then(undefined, (e) => console.error('[repo-jobs] fail threw:', e));
}

/** Read a single job (used by the scanner's GET /scan/repo/:id convenience route). */
export async function getJob(id: string): Promise<RepoJob | null> {
  const db = client();
  if (!db) return null;
  const { data, error } = await db
    .from('repo_scan_jobs')
    .select('id, repo_url, status, scan_id, error')
    .eq('id', id)
    .maybeSingle();
  if (error || !data) return null;
  return data as RepoJob;
}

/**
 * Persist a finished repo ScanResult into public.scans (same table the URL/code
 * scans use), returning the new scan id so the report renders at /r/{id}.
 */
export async function saveRepoScan(result: ScanResult, userId: string | null): Promise<string | null> {
  const db = client();
  if (!db) return null;
  const target = result.url || 'Repository';
  const { data, error } = await db
    .from('scans')
    .insert({
      user_id: userId,
      target,
      mode: result.mode ?? 'repo',
      score: result.score,
      verdict: result.verdict,
      counts: result.counts,
      result,
    })
    .select('id')
    .single();
  if (error) {
    console.error('[repo-jobs] save scan failed:', error.message);
    return null;
  }
  return data.id as string;
}

/**
 * On scanner boot, fail any jobs left mid-flight by a previous process so they
 * don't poll forever. Cheap and acceptable for a free product (user re-runs).
 */
export async function recoverOrphanJobs(): Promise<void> {
  const db = client();
  if (!db) return;
  await db
    .from('repo_scan_jobs')
    .update({ status: 'failed', error: 'Scanner restarted', updated_at: new Date().toISOString() })
    .in('status', ['queued', 'cloning', 'scanning'])
    .then(undefined, (e) => console.error('[repo-jobs] recovery threw:', e));
}
