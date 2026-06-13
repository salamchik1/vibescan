'use client';
import { createBrowserClient } from '@supabase/ssr';
import { SUPABASE_URL, SUPABASE_ANON_KEY } from './config';

// Browser client for client components (the login form). Safe to ship to the
// browser — it only holds the public URL + anon key.
export function createClient() {
  return createBrowserClient(SUPABASE_URL, SUPABASE_ANON_KEY);
}
