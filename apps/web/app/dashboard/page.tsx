import { redirect } from 'next/navigation';
import Link from 'next/link';
import { SiteHeader } from '../../components/SiteHeader';
import { getServerSupabase } from '../../lib/supabase/server';
import type { ScanListItem } from '../../lib/scans';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const VERDICT_DOT: Record<string, string> = {
  red: 'bg-red-400',
  yellow: 'bg-amber-300',
  green: 'bg-emerald-400',
};

export default async function DashboardPage() {
  const supabase = await getServerSupabase();
  if (!supabase) redirect('/login?error=not_configured');

  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) redirect('/login');

  // RLS restricts this to the signed-in user's own scans.
  const { data } = await supabase
    .from('scans')
    .select('id, created_at, target, mode, score, verdict, counts')
    .order('created_at', { ascending: false })
    .limit(100);

  const scans = (data ?? []) as ScanListItem[];

  return (
    <main className="mx-auto flex min-h-screen max-w-3xl flex-col px-5 py-12 sm:py-16">
      <SiteHeader />

      <div className="mt-12 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-ink">Your scans</h1>
          <p className="mt-1 text-sm text-ink/50">{user.email}</p>
        </div>
        <form action="/auth/signout" method="post">
          <button className="rounded-full border border-ink/15 px-4 py-1.5 text-sm text-ink/70 transition hover:border-ink/40 hover:text-ink">
            Sign out
          </button>
        </form>
      </div>

      {scans.length === 0 ? (
        <div className="mt-10 rounded-xl border border-ink/10 bg-white p-6 text-center text-sm text-ink/60">
          No scans yet.{' '}
          <Link href="/" className="text-primary underline">
            Run your first scan →
          </Link>
        </div>
      ) : (
        <ul className="mt-8 space-y-2">
          {scans.map((s) => (
            <li key={s.id}>
              <Link
                href={`/r/${s.id}`}
                className="flex items-center gap-4 rounded-xl border border-ink/10 bg-white px-4 py-3 transition hover:border-ink/30"
              >
                <span
                  className={`h-2.5 w-2.5 shrink-0 rounded-full ${VERDICT_DOT[s.verdict] ?? 'bg-ink/30'}`}
                />
                <div className="min-w-0 flex-1">
                  <div className="truncate font-mono text-sm text-ink/80">{s.target}</div>
                  <div className="text-xs text-ink/40">
                    {new Date(s.created_at).toLocaleString()}
                  </div>
                </div>
                <span className="shrink-0 text-sm font-semibold text-ink/70">{s.score}/100</span>
              </Link>
            </li>
          ))}
        </ul>
      )}

      <p className="mt-8 text-center text-xs text-ink/30">
        History, monitoring and alerts build on this. Scans you run while signed in are saved here
        automatically.
      </p>
    </main>
  );
}
