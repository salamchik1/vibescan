import type { CollectResult } from '../collector';

/**
 * Shared host helpers used by the DNS-flavoured infra detectors (email, dns).
 *
 * Two things live here so they have a single source of truth:
 *  - the list of platform-issued public suffixes whose DNS the user does NOT
 *    control (vercel.app, github.io, …), and
 *  - small, PSL-free helpers for pulling the scanned hostname and walking it up
 *    toward its registrable apex.
 */

/**
 * Platform-issued public suffixes: hosting providers that hand out free
 * `<app>.<suffix>` subdomains. The user does NOT own the registrable apex here
 * (DNS for `vercel.app`, `github.io`, … is run by the provider), so they cannot
 * add CAA / SPF / DMARC even if they wanted to, and the provider — not the user —
 * owns the underlying CNAME target. Flagging these is an un-actionable false alarm.
 *
 * A real custom domain pointed at one of these platforms (e.g. `app.acme.com`)
 * does NOT match — it ends in `acme.com`, whose DNS the user controls.
 */
export const PLATFORM_SUFFIXES = [
  'vercel.app',
  'netlify.app',
  'github.io',
  'pages.dev', // Cloudflare Pages
  'workers.dev', // Cloudflare Workers
  'web.app', // Firebase Hosting
  'firebaseapp.com',
  'onrender.com', // Render
  'herokuapp.com',
  'fly.dev',
  'railway.app',
  'surge.sh',
  'glitch.me',
  'replit.app',
  'repl.co',
  'streamlit.app',
];

/** True when the host sits under a platform-issued public suffix (DNS not user-controlled). */
export function isPlatformSubdomain(host: string): boolean {
  return PLATFORM_SUFFIXES.some((suffix) => host === suffix || host.endsWith(`.${suffix}`));
}

/**
 * Lowercased hostname of the scanned target, or null for non-web targets
 * (code-paste scans) and raw IP literals (no DNS hygiene to check there).
 */
export function scannedHost(collected: CollectResult): string | null {
  let host = '';
  try {
    host = new URL(collected.finalUrl).hostname;
  } catch {
    try {
      host = new URL(collected.origin).hostname;
    } catch {
      return null;
    }
  }
  if (!host) return null;
  host = host.toLowerCase();
  // Must look like a real registrable name (a dot, no raw IPv4 literal).
  if (!host.includes('.') || /^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return null;
  return host;
}

/**
 * Naive registrable apex: the last two labels. We deliberately avoid a Public
 * Suffix List dependency — this over-shortens multi-part TLDs (e.g. `acme.co.uk`
 * → `co.uk`), which at worst makes a CAA/enumeration probe hit a name that simply
 * has no records (a silent no-op), never a false positive.
 */
export function apexGuess(host: string): string {
  return host.split('.').slice(-2).join('.');
}

/**
 * Every name from the full host down to (and including) the 2-label apex —
 * the chain a CAA lookup climbs, since a CAA record on any ancestor covers all
 * names below it. For `a.b.acme.com` → ["a.b.acme.com", "b.acme.com", "acme.com"].
 */
export function ancestorsToApex(host: string): string[] {
  const parts = host.split('.');
  const out: string[] = [];
  for (let i = 0; i + 2 <= parts.length; i++) {
    out.push(parts.slice(i).join('.'));
  }
  return out.length ? out : [host];
}
