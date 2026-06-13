import { NextResponse, type NextRequest } from 'next/server';
import { getServerSupabase } from '../../../lib/supabase/server';

export const dynamic = 'force-dynamic';

export async function POST(request: NextRequest) {
  const { origin } = new URL(request.url);
  const supabase = await getServerSupabase();
  if (supabase) await supabase.auth.signOut();
  return NextResponse.redirect(`${origin}/`, { status: 303 });
}
