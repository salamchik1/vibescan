import 'server-only';
import { cookies } from 'next/headers';
import { createServerClient, type CookieOptions } from '@supabase/ssr';
import { SUPABASE_URL, SUPABASE_ANON_KEY, authConfigured } from './config';

// Cookie-backed client for the logged-in user's session (Server Components,
// route handlers, server actions). Reads/writes the auth cookies that the
// middleware keeps fresh. Honours RLS — a user only sees their own rows.

export async function getServerSupabase() {
  if (!authConfigured) return null;
  const cookieStore = await cookies();

  return createServerClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    cookies: {
      getAll() {
        return cookieStore.getAll();
      },
      setAll(cookiesToSet: { name: string; value: string; options?: CookieOptions }[]) {
        try {
          cookiesToSet.forEach(({ name, value, options }) =>
            cookieStore.set(name, value, options)
          );
        } catch {
          // Called from a Server Component where cookies are read-only.
          // The middleware refreshes the session, so this is safe to ignore.
        }
      },
    },
  });
}

/** Convenience: the current signed-in user, or null. */
export async function getCurrentUser() {
  const supabase = await getServerSupabase();
  if (!supabase) return null;
  const {
    data: { user },
  } = await supabase.auth.getUser();
  return user;
}
