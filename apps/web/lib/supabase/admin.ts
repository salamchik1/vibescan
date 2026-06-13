import 'server-only';
import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, dbConfigured } from './config';

// Service-role client. Bypasses RLS, so it is used ONLY in trusted server code:
//  - saving a freshly finished scan (the scanner has no user session)
//  - loading a report on /r/[id] (public-by-link, like every paid competitor)
// Never import this from a client component.

let cached: SupabaseClient | null = null;

/** Returns the admin client, or null when Supabase isn't configured. */
export function getAdminClient(): SupabaseClient | null {
  if (!dbConfigured) return null;
  if (cached) return cached;
  cached = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  return cached;
}
