import { NextResponse, type NextRequest } from 'next/server';
import type { EmailOtpType } from '@supabase/supabase-js';
import { getServerSupabase } from '../../../lib/supabase/server';

export const dynamic = 'force-dynamic';

// Landing point for the magic link. Supabase may deliver either:
//  - ?code=...                         (PKCE flow, default for @supabase/ssr)
//  - ?token_hash=...&type=magiclink    (if you switch the email template to {{ .TokenHash }})
// We support both, then redirect to the dashboard. On failure → /login?error=...
export async function GET(request: NextRequest) {
  const { searchParams, origin } = new URL(request.url);
  const next = searchParams.get('next') ?? '/dashboard';

  // OAuth providers (and Supabase) append ?error=...&error_description=... when
  // the user cancels or the exchange is rejected. Bail out early with a friendly
  // message instead of falling through to a generic "link invalid".
  if (searchParams.get('error')) {
    return NextResponse.redirect(`${origin}/login?error=oauth_failed`);
  }

  const supabase = await getServerSupabase();
  if (!supabase) {
    return NextResponse.redirect(`${origin}/login?error=not_configured`);
  }

  const code = searchParams.get('code');
  const tokenHash = searchParams.get('token_hash');
  const type = searchParams.get('type') as EmailOtpType | null;

  if (code) {
    const { error } = await supabase.auth.exchangeCodeForSession(code);
    if (!error) return NextResponse.redirect(`${origin}${next}`);
  } else if (tokenHash && type) {
    const { error } = await supabase.auth.verifyOtp({ type, token_hash: tokenHash });
    if (!error) return NextResponse.redirect(`${origin}${next}`);
  }

  return NextResponse.redirect(`${origin}/login?error=link_invalid`);
}
