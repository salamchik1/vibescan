import { NextResponse, type NextRequest } from 'next/server';
import { createServerClient, type CookieOptions } from '@supabase/ssr';

const isDev = process.env.NODE_ENV !== 'production';

// Builds the Content-Security-Policy for a single response. A fresh, unguessable
// nonce is minted per request (below) and threaded into script-src, so every
// inline hydration <script> Next.js injects is allow-listed individually — no
// 'unsafe-inline'. 'strict-dynamic' lets those nonce-trusted scripts pull in the
// chunk files Next loads at runtime, so we don't have to allow-list script hosts
// (and 'self' stays only as a fallback for older CSP2 browsers that ignore
// 'strict-dynamic'). 'unsafe-eval' is added ONLY in dev, where Next's Fast
// Refresh / eval source maps need it; the production policy never contains it.
//
// style-src deliberately keeps 'unsafe-inline': the UI renders dynamic inline
// style attributes (gauge colors, score bars) via React's style={...} prop, and
// inline style *attributes* cannot carry a nonce or hash. Style injection is far
// lower risk than script injection, so this is an accepted, documented trade-off.
function buildCsp(nonce: string): string {
  return [
    "default-src 'self'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDev ? " 'unsafe-eval'" : ''}`,
    "style-src 'self' 'unsafe-inline'",
    "connect-src 'self' https://*.supabase.co wss://*.supabase.co",
    'upgrade-insecure-requests',
  ].join('; ');
}

export async function middleware(request: NextRequest) {
  // One unguessable nonce per request. We forward it to Next via a request
  // header (alongside the CSP) so the framework stamps the same value onto the
  // <script> tags it injects; the response header is what the browser enforces.
  const nonce = Buffer.from(crypto.randomUUID()).toString('base64');
  const csp = buildCsp(nonce);

  // Re-derive the forwarded response from the *current* request state on each
  // call: the Supabase callback below mutates request.cookies, and we must keep
  // re-applying the nonce/CSP request headers and the CSP response header.
  const makeResponse = () => {
    const requestHeaders = new Headers(request.headers);
    requestHeaders.set('x-nonce', nonce);
    requestHeaders.set('Content-Security-Policy', csp);
    const res = NextResponse.next({ request: { headers: requestHeaders } });
    res.headers.set('Content-Security-Policy', csp);
    return res;
  };

  let response = makeResponse();

  // Keep the Supabase auth session fresh by rotating the auth cookies. No-op
  // when Supabase isn't configured. See:
  // https://supabase.com/docs/guides/auth/server-side/nextjs
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anon = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  if (url && anon) {
    const supabase = createServerClient(url, anon, {
      cookies: {
        getAll() {
          return request.cookies.getAll();
        },
        setAll(cookiesToSet: { name: string; value: string; options?: CookieOptions }[]) {
          cookiesToSet.forEach(({ name, value }) => request.cookies.set(name, value));
          response = makeResponse();
          cookiesToSet.forEach(({ name, value, options }) =>
            response.cookies.set(name, value, options)
          );
        },
      },
    });

    // Touch the session so expired tokens get refreshed into the response cookies.
    await supabase.auth.getUser();
  }

  return response;
}

export const config = {
  // Run on app pages, skip static assets. Auth routes are included so the
  // session cookie set during /auth/confirm survives the redirect.
  matcher: ['/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)'],
};
