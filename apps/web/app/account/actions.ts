'use server';

import { redirect } from 'next/navigation';
import { revalidatePath } from 'next/cache';
import { getServerSupabase } from '../../lib/supabase/server';
import { getAdminClient } from '../../lib/supabase/admin';

export type ProfileState = { ok: boolean; message: string };

/** Save the user's display name into Supabase user_metadata (no extra table). */
export async function updateProfile(
  _prev: ProfileState,
  formData: FormData
): Promise<ProfileState> {
  const fullName = String(formData.get('full_name') ?? '').trim().slice(0, 80);

  const supabase = await getServerSupabase();
  if (!supabase) return { ok: false, message: 'Accounts aren’t configured.' };

  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) redirect('/login');

  const { error } = await supabase.auth.updateUser({ data: { full_name: fullName } });
  if (error) return { ok: false, message: error.message };

  revalidatePath('/account');
  return { ok: true, message: 'Saved.' };
}

/**
 * Permanently delete the signed-in user. Uses the service-role admin client to
 * remove their data (scans + repo jobs) and then the auth user itself, then
 * clears the session cookie and sends them home. Irreversible.
 */
export async function deleteAccount(): Promise<never> {
  const supabase = await getServerSupabase();
  if (!supabase) redirect('/login');

  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) redirect('/login');

  const admin = getAdminClient();
  if (!admin) redirect('/account?error=delete_unavailable');

  // Remove the user's own data first, then the auth identity.
  await admin.from('scans').delete().eq('user_id', user.id);
  await admin.from('repo_scan_jobs').delete().eq('user_id', user.id);
  const { error } = await admin.auth.admin.deleteUser(user.id);
  if (error) redirect('/account?error=delete_failed');

  await supabase.auth.signOut();
  redirect('/');
}
