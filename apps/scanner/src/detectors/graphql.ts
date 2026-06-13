import type { Finding } from '@vibescan/findings';
import type { CollectResult } from '../collector';
import { safeFetch } from '../util/fetch';

const ENDPOINTS = ['/graphql', '/api/graphql', '/v1/graphql', '/query'];
const INTROSPECTION = JSON.stringify({ query: 'query{__schema{queryType{name}}}' });

/**
 * Probe common GraphQL endpoints with an introspection query. If the schema comes
 * back, introspection is enabled in production — a free map of the whole API.
 */
export async function detectGraphql(collected: CollectResult): Promise<Finding[]> {
  if (!collected.origin) return [];

  // Probe all endpoints in parallel, then report the first hit in ENDPOINTS
  // order. Sequential probing would sum one timeout per endpoint on a slow host.
  const hits = await Promise.all(
    ENDPOINTS.map(async (path) => {
      try {
        const res = await safeFetch(collected.origin + path, {
          method: 'POST',
          body: INTROSPECTION,
          timeoutMs: 7_000,
          maxBytes: 50_000,
          headers: { 'content-type': 'application/json' },
        });
        if (res.status !== 200) return null;
        if (!(res.headers['content-type'] ?? '').includes('json')) return null;
        if (/"__schema"/.test(res.body) && /"queryType"/.test(res.body)) return path;
      } catch {
        /* endpoint not reachable */
      }
      return null;
    })
  );

  const path = hits.find((p): p is string => p !== null);
  if (path) {
    return [
      {
        type: 'graphql_introspection',
        severity: 'low',
        category: 'auth',
        summary: `GraphQL introspection is enabled at ${path}, exposing your full schema.`,
        evidence: `POST ${path} (introspection) → 200 with __schema`,
        params: { path },
      },
    ];
  }

  return [];
}
