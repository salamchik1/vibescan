import { NextResponse } from 'next/server';
import { getRepoJob } from '../../../../../lib/repoJobs';

// Poll a repo-scan job. Reads Supabase directly (never the scanner), so it is
// cheap and works regardless of scanner cold-starts or tunnel state.
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const job = await getRepoJob(id);
  if (!job) return NextResponse.json({ error: 'Job not found.' }, { status: 404 });
  return NextResponse.json(job);
}
