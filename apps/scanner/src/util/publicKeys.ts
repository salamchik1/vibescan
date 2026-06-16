/**
 * Public-by-design analytics / tag keys.
 *
 * A whole class of "keys" are MEANT to ship to the browser: analytics scripts
 * and tag managers embed them in the page so the client can send events. They
 * are not credentials — they grant no read access and are rate-limited /
 * abuse-gated on the vendor side, exactly like a Supabase anon key. But
 * gitleaks' broad `generic-api-key` rule and our high-entropy fallback both
 * trip on the way they are written (`data-key="…"`, `writeKey: "…"`), producing
 * a false "leaked secret". We recognise the well-known ones and drop them so the
 * report doesn't scream about a value the vendor's own snippet puts on the page.
 *
 * Two independent ways to recognise them, used by the callers as appropriate:
 *  - by value — Google's tag / measurement ids have a fixed, unmistakable shape
 *    (`G-…`, `GTM-…`, `UA-…`, `AW-…`, `DC-…`) and carry no secret material at
 *    all, so they are safe to drop wherever they appear.
 *  - by context — Segment / Ahrefs / Plausible / GA *keys* are random-looking,
 *    so we key off the surrounding vendor marker (the loader CDN host or the
 *    documented init call) that only ever wraps a public, client-side key.
 *
 * Mirrors the publishable-Google-key handling in `detectSecrets`: a value is
 * only ever DROPPED here, never escalated, and (in gitleaks) context-based
 * dropping is restricted to the low-confidence generic rule, so a precise
 * provider hit (Stripe/AWS/…) that happens to sit near an analytics snippet is
 * never silenced.
 */

// Google Analytics (GA4 `G-`, Universal `UA-`), Tag Manager (`GTM-`), Google
// Ads (`AW-`) and Campaign Manager (`DC-`) ids. Anchored to the whole value:
// the entire token must be the id, so a real key that merely contains these
// letters can't match. `{4,}` rules out a stray `G-1`. No global flag — `.test`
// must stay stateless.
const GOOGLE_TAG_ID_RE = /^(?:G|GTM|UA|AW|DC)-[A-Z0-9]{4,}(?:-[A-Z0-9]+)?$/i;

/** True when the whole value is a Google analytics / tag / ads id (never a secret). */
export function isPublicAnalyticsId(value: string): boolean {
  return GOOGLE_TAG_ID_RE.test(value.trim());
}

// Vendor markers that only ever wrap a public, client-side analytics key: a
// loader CDN host or the documented init call. Deliberately specific (a host or
// a call signature, not the bare word "analytics", which countless apps use) so
// an unrelated random token that merely sits near the word is never dropped.
const PUBLIC_ANALYTICS_CONTEXT_RE =
  /analytics\.ahrefs\.com|cdn\.segment\.(?:com|io)|segment\.com\/analytics(?:\.min)?\.js|analytics\.load\s*\(|googletagmanager\.com|www\.google-analytics\.com|google-analytics\.com\/(?:analytics|ga|g\/collect)|plausible\.io|data-domain=/i;

/** How far either side of a token we look for a public-analytics vendor marker. */
export const PUBLIC_ANALYTICS_WINDOW = 200;

/** True when `text` contains a marker that only wraps a public analytics key. */
export function hasPublicAnalyticsContext(text: string): boolean {
  return PUBLIC_ANALYTICS_CONTEXT_RE.test(text);
}
