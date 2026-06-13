// Single source of truth for "is Supabase wired up?".
// Everything degrades gracefully when these are unset: scans simply don't
// persist and the login page shows a "not configured yet" notice, so the free
// one-shot scan keeps working with zero backend.

export const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL ?? '';
export const SUPABASE_ANON_KEY = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? '';
/** Server-only. Never exposed to the browser (no NEXT_PUBLIC_ prefix). */
export const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY ?? '';

/** Auth (login, sessions, dashboard) needs the public URL + anon key. */
export const authConfigured = Boolean(SUPABASE_URL && SUPABASE_ANON_KEY);

/** Saving/reading scans server-side needs the service-role key on top of that. */
export const dbConfigured = Boolean(SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY);
