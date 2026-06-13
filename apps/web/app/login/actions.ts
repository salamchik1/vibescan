'use server';

import { headers } from 'next/headers';
import { getServerSupabase } from '../../lib/supabase/server';

export type LoginState = { ok: boolean; message: string };

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
  const h = await headers();
  const origin =
    process.env.NEXT_PUBLIC_SITE_URL ??
    `${h.get('x-forwarded-proto') ?? 'http'}://${h.get('host') ?? 'localhost:3000'}`;

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
