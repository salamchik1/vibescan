import type { Finding } from '@vibescan/findings';
import type { CollectResult } from '../collector';
import { extractJwts, jwtRole } from '../util/jwt';
import { safeFetch } from '../util/fetch';

const PROJECT_RE = /https?:\/\/([a-z0-9]{20})\.supabase\.co/gi;
const FROM_RE = /\.from\(\s*['"`]([a-zA-Z_][a-zA-Z0-9_]*)['"`]\s*\)/g;
const PUBLIC_BUCKET_RE = /\/storage\/v1\/object\/public\/([a-zA-Z0-9_-]+)\//g;

const DEFAULT_TABLES = ['users', 'profiles', 'orders', 'messages', 'payments', 'customers', 'subscriptions'];
const MAX_TABLES_TO_PROBE = 20;
const MAX_BUCKETS_TO_PROBE = 5;

function findAnonKey(text: string): string | null {
  for (const jwt of extractJwts(text)) {
    const role = jwtRole(jwt);
    if (role === 'anon' || role === 'authenticated') return jwt.raw;
  }
  return null;
}

/**
 * PostgREST serves an OpenAPI document at the REST root. With just the public anon
 * key it lists every exposed table — so we can probe the real schema instead of guessing.
 */
async function enumerateTables(base: string, anonKey: string): Promise<string[]> {
  try {
    const res = await safeFetch(`${base}/`, {
      timeoutMs: 8_000,
      maxBytes: 300_000,
      headers: { apikey: anonKey, authorization: `Bearer ${anonKey}` },
    });
    if (res.status !== 200) return [];
    const doc = JSON.parse(res.body) as { definitions?: Record<string, unknown>; paths?: Record<string, unknown> };
    const names = new Set<string>();
    if (doc.definitions) for (const k of Object.keys(doc.definitions)) names.add(k);
    if (doc.paths) {
      for (const p of Object.keys(doc.paths)) {
        const name = p.replace(/^\//, '');
        if (name && !name.startsWith('rpc/') && !name.includes('{')) names.add(name);
      }
    }
    return [...names];
  } catch {
    return [];
  }
}

async function probeTableOpen(base: string, table: string, anonKey: string): Promise<Finding | null> {
  const url = `${base}/${encodeURIComponent(table)}?select=*&limit=1`;
  try {
    const res = await safeFetch(url, {
      timeoutMs: 8_000,
      maxBytes: 50_000,
      headers: { apikey: anonKey, authorization: `Bearer ${anonKey}` },
    });
    if (res.status !== 200) return null;
    let parsed: unknown;
    try {
      parsed = JSON.parse(res.body);
    } catch {
      return null;
    }
    // RLS off / permissive -> rows are returned. Empty array is ambiguous (empty table or RLS) -> skip.
    if (Array.isArray(parsed) && parsed.length > 0) {
      return {
        type: 'supabase_rls_open',
        severity: 'critical',
        category: 'database',
        summary: `Table "${table}" returns data to anyone without logging in (RLS off).`,
        evidence: `GET /rest/v1/${table} → 200 with rows`,
        params: { table },
      };
    }
  } catch {
    /* network/timeout — skip this table */
  }
  return null;
}

async function probeBucketListable(
  ref: string,
  bucket: string,
  anonKey: string
): Promise<Finding | null> {
  const url = `https://${ref}.supabase.co/storage/v1/object/list/${encodeURIComponent(bucket)}`;
  try {
    const res = await safeFetch(url, {
      method: 'POST',
      timeoutMs: 8_000,
      maxBytes: 50_000,
      headers: { apikey: anonKey, authorization: `Bearer ${anonKey}`, 'content-type': 'application/json' },
      body: JSON.stringify({ prefix: '', limit: 100, offset: 0 }),
    });
    if (res.status !== 200) return null;
    const parsed = JSON.parse(res.body);
    if (Array.isArray(parsed) && parsed.length > 0) {
      return {
        type: 'supabase_storage_public',
        severity: 'high',
        category: 'database',
        summary: `Storage bucket "${bucket}" can be listed and downloaded by anyone.`,
        evidence: `POST /storage/v1/object/list/${bucket} → 200 with ${parsed.length} object(s)`,
        params: { bucket },
      };
    }
  } catch {
    /* skip */
  }
  return null;
}

export async function detectSupabase(collected: CollectResult): Promise<Finding[]> {
  const text = collected.jsCombined;
  const findings: Finding[] = [];

  // Locate the project ref (also check requested hosts in case it's not literal in JS).
  const refs = new Set<string>();
  for (const m of text.matchAll(PROJECT_RE)) if (m[1]) refs.add(m[1].toLowerCase());
  for (const host of collected.requestedHosts) {
    const hm = /^([a-z0-9]{20})\.supabase\.co$/i.exec(host);
    if (hm?.[1]) refs.add(hm[1].toLowerCase());
  }
  if (refs.size === 0) return findings;

  const anonKey = findAnonKey(text);
  if (!anonKey) {
    findings.push({
      type: 'supabase_rls_open',
      severity: 'low',
      category: 'database',
      summary: 'Supabase detected, but the anon key was not found — RLS could not be verified automatically.',
      params: { table: 'your tables' },
    });
    return findings;
  }

  // Candidate table names: real schema (OpenAPI) + .from() calls + common defaults.
  const haystackTables = new Set<string>(DEFAULT_TABLES);
  for (const m of text.matchAll(FROM_RE)) if (m[1]) haystackTables.add(m[1]);

  // Candidate public storage buckets referenced in the page.
  const buckets = new Set<string>();
  for (const m of text.matchAll(PUBLIC_BUCKET_RE)) if (m[1]) buckets.add(m[1]);
  for (const m of collected.html.matchAll(PUBLIC_BUCKET_RE)) if (m[1]) buckets.add(m[1]);

  for (const ref of refs) {
    const base = `https://${ref}.supabase.co/rest/v1`;

    const enumerated = await enumerateTables(base, anonKey);
    const tableList = [...new Set([...enumerated, ...haystackTables])].slice(0, MAX_TABLES_TO_PROBE);

    const tableFindings = await Promise.all(tableList.map((t) => probeTableOpen(base, t, anonKey)));
    for (const f of tableFindings) if (f) findings.push(f);

    const bucketFindings = await Promise.all(
      [...buckets].slice(0, MAX_BUCKETS_TO_PROBE).map((b) => probeBucketListable(ref, b, anonKey))
    );
    for (const f of bucketFindings) if (f) findings.push(f);
  }

  return findings;
}
