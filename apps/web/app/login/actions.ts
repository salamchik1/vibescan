'use server';

import { headers } from 'next/headers';
import { redirect } from 'next/navigation';
import type { Provider } from '@supabase/supabase-js';
import { getServerSupabase } from '../../lib/supabase/server';

export type LoginState = { ok: boolean; message: string };

/** Build an absolute origin from env or the incoming request's host. */
async function resolveOrigin(): Promise<string> {
  const h = await headers();
  return (
    process.env.NEXT_PUBLIC_SITE_URL ??
    `${h.get('x-forwarded-proto') ?? 'http'}://${h.get('host') ?? 'localhost:3000'}`
  );
}

/**
 * Send a passwordless magic link to the given email. Supabase mails the link;
 * clicking it lands on /auth/confirm which establishes the session.
 */
export async function sendMagicLink(
  _prev: LoginState,
  formData: FormData
): Promise<LoginState> {
  const email = String(formData.get('email') ?? '').trim();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return { ok: false, message: 'Please enter a valid email address.' };
  }

  const supabase = await getServerSupabase();
  if (!supabase) {
    return {
      ok: false,
      message: 'Login isn’t configured yet. Add your Supabase keys to enable accounts.',
    };
  }

  // Build an absolute redirect from the incoming request's host so it works on
  // localhost and in production without hard-coding the origin.
  const origin = await resolveOrigin();

  const { error } = await supabase.auth.signInWithOtp({
    email,
    options: {
      emailRedirectTo: `${origin}/auth/confirm`,
      shouldCreateUser: true,
    },
  });

  if (error) {
    return { ok: false, message: error.message };
  }
  return {
    ok: true,
    message: `Check ${email} — we sent you a one-click sign-in link.`,
  };
}

/**
 * Start an OAuth sign-in (Google / GitHub). Supabase returns a provider URL we
 * redirect the browser to; the PKCE verifier is stored in a cookie by the
 * server client and read back at /auth/confirm, which exchanges the returned
 * ?code= for a session — the same path the magic link uses.
 *
 * Invoked from a <form action={signInWithProvider}> with a hidden `provider`
 * field, so it never throws into the UI — every failure redirects to /login.
 */
export async function signInWithProvider(formData: FormData): Promise<never> {
  const provider = String(formData.get('provider') ?? '') as Provider;
  if (provider !== 'google' && provider !== 'github') {
    redirect('/login?error=oauth_failed');
  }

  const supabase = await getServerSupabase();
  if (!supabase) {
    redirect('/login?error=not_configured');
  }

  const origin = await resolveOrigin();
  const { data, error } = await supabase.auth.signInWithOAuth({
    provider,
    options: { redirectTo: `${origin}/auth/confirm?next=/dashboard` },
  });

  if (error || !data?.url) {
    redirect('/login?error=oauth_failed');
  }

  redirect(data.url);
}
