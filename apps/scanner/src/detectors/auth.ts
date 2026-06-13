import type { Finding } from '@vibescan/findings';
import type { CollectResult } from '../collector';
import { safeFetch, looksLikeHtml } from '../util/fetch';

const HTML_ROUTES = ['/admin', '/dashboard', '/account', '/settings'];
const API_ROUTES = ['/api/users', '/api/me', '/api/orders', '/api/customers'];

function isErrorJson(value: unknown): boolean {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const o = value as Record<string, unknown>;
    const keys = Object.keys(o);
    if (keys.length === 0) return true;
    if (keys.every((k) => ['error', 'message', 'statusCode', 'code'].includes(k))) return true;
  }
  return false;
}

export async function detectAuth(collected: CollectResult): Promise<Finding[]> {
  const findings: Finding[] = [];
  if (!collected.origin) return findings;

  const homepageLen = collected.html.length || 1;

  // 1) HTML routes: a 200 that returns the same SPA shell = auth is client-side only (informational).
  // Probe all routes in parallel; on a slow host this caps the wait at one
  // timeout instead of one-per-route summed.
  const htmlResults = await Promise.all(
    HTML_ROUTES.map(async (path) => {
      try {
        const res = await safeFetch(collected.origin + path, {
          timeoutMs: 8_000,
          maxBytes: 200_000,
          redirect: 'manual',
        });
        // Redirect (e.g. to /login) means the route is guarded — good, skip.
        if (res.status >= 300 && res.status < 400) return null;
        if (res.status === 200 && looksLikeHtml(res.headers, res.body)) {
          const ratio = res.body.length / homepageLen;
          if (ratio > 0.6 && ratio < 1.6) return path;
        }
      } catch {
        /* skip */
      }
      return null;
    })
  );
  const shellRoutes = htmlResults.filter((p): p is string => p !== null);
  if (shellRoutes.length >= 2) {
    findings.push({
      type: 'auth_client_only',
      severity: 'info',
      category: 'auth',
      summary: `Private pages (${shellRoutes.join(', ')}) are served to everyone and rely on in-browser checks.`,
      evidence: shellRoutes.join(', '),
    });
  }

  // 2) API routes: JSON data returned without auth = real exposure. Probed in
  // parallel for the same reason as the HTML routes above.
  const apiResults = await Promise.all(
    API_ROUTES.map(async (path): Promise<Finding | null> => {
      try {
        const res = await safeFetch(collected.origin + path, { timeoutMs: 8_000, maxBytes: 100_000 });
        if (res.status !== 200) return null;
        const ct = res.headers['content-type'] ?? '';
        if (!ct.includes('json')) return null;
        let parsed: unknown;
        try {
          parsed = JSON.parse(res.body);
        } catch {
          return null;
        }
        if (Array.isArray(parsed) && parsed.length > 0) {
          return {
            type: 'auth_unprotected_route',
            severity: 'high',
            category: 'auth',
            summary: `${path} returns data without any login.`,
            evidence: `GET ${path} → 200 JSON array`,
            params: { path },
          };
        }
        if (!Array.isArray(parsed) && !isErrorJson(parsed)) {
          return {
            type: 'auth_unprotected_route',
            severity: 'medium',
            category: 'auth',
            summary: `${path} responds without a login — verify it exposes no private data.`,
            evidence: `GET ${path} → 200 JSON`,
            params: { path },
          };
        }
      } catch {
        /* skip */
      }
      return null;
    })
  );
  for (const f of apiResults) if (f) findings.push(f);

  return findings;
}
