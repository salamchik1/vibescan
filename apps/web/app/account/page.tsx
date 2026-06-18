import { redirect } from 'next/navigation';
import Link from 'next/link';
import { SiteHeader } from '../../components/SiteHeader';
import { getServerSupabase } from '../../lib/supabase/server';
import { dbConfigured } from '../../lib/supabase/config';
import { ProfileForm, DeleteAccountButton } from './AccountForms';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// Map a Supabase identity provider to a human label shown under "Sign-in methods".
const PROVIDER_LABELS: Record<string, string> = {
  email: 'Email link',
  google: 'Google',
  github: 'GitHub',
};

const PAGE_ERRORS: Record<string, string> = {
  delete_unavailable: 'Account deletion isn’t available — the server isn’t fully configured.',
  delete_failed: 'We couldn’t delete your account. Please try again.',
};

export default async function AccountPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  const supabase = await getServerSupabase();
  if (!supabase) redirect('/login?error=not_configured');

  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) redirect('/login');

  const { error } = await searchParams;
  const errorMessage = error ? PAGE_ERRORS[error] ?? null : null;

  const fullName = (user.user_metadata?.full_name as string | undefined) ?? '';
  const providers = Array.from(
    new Set((user.identities ?? []).map((i) => i.provider))
  );
  const joined = user.created_at ? new Date(user.created_at).toLocaleDateString() : null;

  return (
    <main className="mx-auto flex min-h-screen max-w-3xl flex-col px-5 py-12 sm:py-16">
      <SiteHeader active="account" />

      <div className="mt-12 flex items-center justify-between">
        <h1 className="text-2xl font-bold text-ink">Account</h1>
        <Link
          href="/dashboard"
          className="rounded-full border border-ink/15 px-4 py-1.5 text-sm text-ink/70 transition hover:border-ink/40 hover:text-ink"
        >
          Your scans →
        </Link>
      </div>

      {errorMessage && (
        <div className="mt-6 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-600">
          {errorMessage}
        </div>
      )}

      {/* Profile */}
      <section className="mt-8 rounded-xl border border-ink/10 bg-white p-6">
        <h2 className="text-sm font-semibold text-ink">Profile</h2>
        <p className="mt-1 text-sm text-ink/50">{user.email}</p>
        <ProfileForm defaultName={fullName} />
      </section>

      {/* Sign-in methods */}
      <section className="mt-4 rounded-xl border border-ink/10 bg-white p-6">
        <h2 className="text-sm font-semibold text-ink">Sign-in methods</h2>
        <ul className="mt-3 flex flex-wrap gap-2">
          {providers.length === 0 ? (
            <li className="text-sm text-ink/50">Email link</li>
          ) : (
            providers.map((p) => (
              <li
                key={p}
                className="rounded-full border border-ink/15 bg-paper px-3 py-1 text-sm text-ink/70"
              >
                {PROVIDER_LABELS[p] ?? p}
              </li>
            ))
          )}
        </ul>
        {joined && <p className="mt-4 text-xs text-ink/40">Member since {joined}</p>}
      </section>

      {/* Danger zone */}
      <section className="mt-4 rounded-xl border border-red-500/20 bg-red-500/[0.03] p-6">
        <h2 className="text-sm font-semibold text-red-600">Danger zone</h2>
        <p className="mt-1 text-sm text-ink/60">
          Permanently delete your account and scan history. This cannot be undone.
        </p>
        <div className="mt-4">
          {dbConfigured ? (
            <DeleteAccountButton />
          ) : (
            <p className="text-sm text-ink/40">
              Deletion is unavailable until the server is fully configured.
            </p>
          )}
        </div>
      </section>
    </main>
  );
}
