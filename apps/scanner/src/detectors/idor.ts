import { createHash } from 'node:crypto';
import type { Finding, Severity } from '@vibescan/findings';
import type { CollectResult } from '../collector';
import { safeFetch, looksLikeHtml, type SafeFetchResult } from '../util/fetch';

/**
 * IDOR / BOLA detector (read-only).
 *
 * Broken Object-Level Authorization is the #1 bug in vibe-coded apps: an endpoint
 * returns an object based only on the id in the URL, without checking who is asking.
 *
 * We confirm it WITHOUT attacking, using only idempotent GET requests and a
 * three-way differential:
 *
 *   real id      → does the endpoint hand back a real object to an anonymous client?
 *   neighbour id → does a *different* id return a *different* real object? (you can walk the space)
 *   bogus id     → does an obviously-nonexistent id 404? (proves it's a real lookup, not an SPA catch-all)
 *
 * Nothing is written, deleted, or stored: we keep only structural fingerprints
 * (status, body shape, field *names*, a hash to tell records apart) — never values.
 */

// ---- Tunables (kept small: this is verification, not enumeration) -----------
const MAX_ENDPOINTS = 6; // distinct endpoint templates we probe
const PER_REQUEST_TIMEOUT_MS = 8_000;
const PER_REQUEST_MAX_BYTES = 60_000;
const ID_PLACEHOLDER = '%ID%';

// Resource words that strongly imply per-user, owned data. Used both to find
// endpoints worth testing and to raise confidence on a hit.
const SENSITIVE_WORDS = [
  'user', 'users', 'account', 'accounts', 'customer', 'customers', 'order', 'orders',
  'invoice', 'invoices', 'payment', 'payments', 'subscription', 'subscriptions',
  'message', 'messages', 'chat', 'chats', 'profile', 'profiles', 'document', 'documents',
  'file', 'files', 'ticket', 'tickets', 'project', 'projects', 'team', 'teams', 'org',
  'orgs', 'organization', 'organizations', 'booking', 'bookings', 'reservation',
  'reservations', 'transaction', 'transactions', 'card', 'cards', 'address', 'addresses',
  'me', 'session', 'sessions', 'notification', 'notifications', 'report', 'reports',
];
const SENSITIVE_RE = new RegExp(`(?:^|[/_-])(${SENSITIVE_WORDS.join('|')})s?(?:$|[/_-])`, 'i');

export type IdKind = 'numeric' | 'uuid' | 'objectid' | 'unknown';

export interface EndpointTemplate {
  /** Origin-relative path with the id replaced by ID_PLACEHOLDER, e.g. "/api/orders/%ID%". */
  template: string;
  /** The observed id value (or a synthesised "1" for dynamic templates with no literal id). */
  sampleId: string;
  kind: IdKind;
  /** The resource segment ("orders", "users", …) for messaging. */
  resource: string;
  sensitive: boolean;
  source: 'literal' | 'dynamic';
}

export interface Fingerprint {
  status: number;
  shape: 'html' | 'object' | 'array' | 'error' | 'empty' | 'other' | 'unreachable';
  /** Sorted top-level JSON key NAMES only (schema, not data). Capped. */
  keys: string[];
  len: number;
  /** Hash of the body — used only to tell two records apart; never surfaced. */
  hash: string;
}

export type Confidence = 'confirmed' | 'likely' | 'suspected';

// ---------------------------------------------------------------------------
// 1) Discovery — pull the REAL id-bearing endpoints out of the page's own code.
// ---------------------------------------------------------------------------

const UUID = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}';
const OBJECTID = '[0-9a-fA-F]{24}';

// Concrete URLs with an id at the end of the path: /api/orders/1042, /users/<uuid>, …
const LITERAL_RES: { re: RegExp; kind: IdKind }[] = [
  { re: new RegExp(`(/[A-Za-z0-9_\\-/]*?/[A-Za-z][A-Za-z0-9_-]*)/(${UUID})(?![\\w-])`, 'g'), kind: 'uuid' },
  { re: new RegExp(`(/[A-Za-z0-9_\\-/]*?/[A-Za-z][A-Za-z0-9_-]*)/(${OBJECTID})(?![\\w])`, 'g'), kind: 'objectid' },
  { re: /(\/[A-Za-z0-9_\-/]*?\/[A-Za-z][A-Za-z0-9_-]*)\/(\d{1,15})(?![\w])/g, kind: 'numeric' },
];

// Dynamic templates the SPA builds at runtime: `/api/orders/${id}` or '/api/users/' + uid
const DYNAMIC_RES: RegExp[] = [
  /["'`](\/[A-Za-z0-9_\-/]*?\/[A-Za-z][A-Za-z0-9_-]*\/)\$\{/g, // `/api/orders/${...}`
  /["'](\/[A-Za-z0-9_\-/]*?\/[A-Za-z][A-Za-z0-9_-]*\/)["']\s*\+/g, // '/api/users/' + id
];

/** Last meaningful path segment before the id ("/api/orders/" -> "orders"). */
function resourceOf(pathPrefix: string): string {
  const segs = pathPrefix.split('/').filter(Boolean);
  return segs[segs.length - 1] ?? '';
}

/** Skip paths that are almost never object lookups (assets, versions, etc.). */
function isNoise(prefix: string): boolean {
  return /\.(js|css|png|jpe?g|svg|woff2?|map|json|ico)$/i.test(prefix) ||
    /\/(?:assets?|static|images?|fonts?|chunks?|_next|node_modules)\//i.test(prefix);
}

export function harvestEndpoints(jsCombined: string, html: string): EndpointTemplate[] {
  const haystack = `${jsCombined}\n${html}`;
  const byTemplate = new Map<string, EndpointTemplate>();

  const add = (prefixWithId: string, sampleId: string, kind: IdKind, source: EndpointTemplate['source']) => {
    // prefixWithId is the path up to AND including the trailing slash before the id.
    const prefix = prefixWithId.replace(/\/$/, '');
    if (!prefix.startsWith('/') || prefix.startsWith('//') || isNoise(prefix)) return;
    const template = `${prefix}/${ID_PLACEHOLDER}`;
    if (byTemplate.has(template)) return;
    const resource = resourceOf(prefix);
    if (!resource) return;
    byTemplate.set(template, {
      template,
      sampleId,
      kind,
      resource,
      sensitive: SENSITIVE_RE.test(`/${resource}`) || SENSITIVE_RE.test(prefix),
      source,
    });
  };

  for (const { re, kind } of LITERAL_RES) {
    for (const m of haystack.matchAll(re)) {
      if (m[1] && m[2]) add(`${m[1]}/`, m[2], kind, 'literal');
    }
  }
  for (const re of DYNAMIC_RES) {
    for (const m of haystack.matchAll(re)) {
      // No literal id to observe — synthesise "1" and treat the space as numeric-ish.
      if (m[1]) add(m[1], '1', 'numeric', 'dynamic');
    }
  }

  // Prioritise: sensitive resources first, then concrete (literal) over synthesised.
  return [...byTemplate.values()]
    .sort((a, b) => Number(b.sensitive) - Number(a.sensitive) || Number(a.source === 'dynamic') - Number(b.source === 'dynamic'))
    .slice(0, MAX_ENDPOINTS);
}

// ---------------------------------------------------------------------------
// 2) Safe id mutation — neighbours (walkable) and a deliberately-bogus id.
// ---------------------------------------------------------------------------

function randHex(n: number): string {
  let s = '';
  while (s.length < n) s += Math.floor(Math.random() * 16).toString(16);
  return s.slice(0, n);
}

/** An id that should NOT resolve to any real object — proves the endpoint is a real lookup. */
export function bogusId(kind: IdKind, sample: string): string {
  switch (kind) {
    case 'uuid':
      return `${randHex(8)}-${randHex(4)}-4${randHex(3)}-8${randHex(3)}-${randHex(12)}`;
    case 'objectid':
      return randHex(24);
    default: {
      // A long random number in a range unlikely to exist, keeping the digit-shape.
      const width = Math.max(sample.length + 3, 9);
      let d = String(7 + Math.floor(Math.random() * 2));
      while (d.length < width) d += Math.floor(Math.random() * 10);
      return d;
    }
  }
}

/** A neighbouring id you could "walk" to. Only meaningful for sequential numeric ids. */
export function neighborId(kind: IdKind, sample: string): string | null {
  if (kind !== 'numeric' || !/^\d+$/.test(sample)) return null;
  try {
    const n = BigInt(sample);
    return (n > 1n ? n - 1n : n + 1n).toString();
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// 3) Fingerprinting — structural only; no values retained.
// ---------------------------------------------------------------------------

const ERROR_KEYS = new Set(['error', 'message', 'statuscode', 'code', 'errors', 'detail', 'status']);

export function fingerprint(res: SafeFetchResult | null): Fingerprint {
  if (!res) return { status: 0, shape: 'unreachable', keys: [], len: 0, hash: '' };
  const hash = createHash('sha1').update(res.body).digest('hex');
  const base = { status: res.status, len: res.body.length, hash };

  if (looksLikeHtml(res.headers, res.body)) return { ...base, shape: 'html', keys: [] };

  const ct = res.headers['content-type'] ?? '';
  if (!ct.includes('json')) return { ...base, shape: 'other', keys: [] };

  let parsed: unknown;
  try {
    parsed = JSON.parse(res.body);
  } catch {
    return { ...base, shape: 'other', keys: [] };
  }
  if (Array.isArray(parsed)) {
    return { ...base, shape: parsed.length > 0 ? 'array' : 'empty', keys: [] };
  }
  if (parsed && typeof parsed === 'object') {
    const keys = Object.keys(parsed as Record<string, unknown>);
    if (keys.length === 0) return { ...base, shape: 'empty', keys: [] };
    if (keys.every((k) => ERROR_KEYS.has(k.toLowerCase()))) return { ...base, shape: 'error', keys: [] };
    return { ...base, shape: 'object', keys: keys.slice(0, 12).sort() };
  }
  return { ...base, shape: 'other', keys: [] };
}

/** A 200 that actually carries object/array data (not an HTML shell or an error body). */
function isData(fp: Fingerprint): boolean {
  return fp.status === 200 && (fp.shape === 'object' || fp.shape === 'array');
}
/** A response that proves a *specific* object was looked up and not found. */
function isRealMiss(fp: Fingerprint): boolean {
  if (fp.shape === 'unreachable') return false;
  if (fp.status >= 400) return true; // 404/403/401/400 -> the lookup discriminates
  return fp.shape === 'empty' || fp.shape === 'error' || fp.shape === 'html';
}
function sameKeys(a: Fingerprint, b: Fingerprint): boolean {
  return a.keys.length > 0 && a.keys.length === b.keys.length && a.keys.every((k, i) => k === b.keys[i]);
}

// ---------------------------------------------------------------------------
// 4) Decision — combine the three probes into a confidence-rated verdict.
// ---------------------------------------------------------------------------

export interface IdorVerdict {
  confidence: Confidence;
  severity: Severity;
  reason: string;
}

export function decide(
  ep: EndpointTemplate,
  real: Fingerprint,
  neighbor: Fingerprint | null,
  bogus: Fingerprint
): IdorVerdict | null {
  // The endpoint must hand back real object data to our anonymous (no-auth) request.
  if (!isData(real)) return null;

  // False-positive guard: if a deliberately-nonexistent id returns the SAME body,
  // this is a static/public/catch-all response, not a per-object lookup. Suppress.
  if (isData(bogus) && bogus.hash === real.hash) return null;
  // If the bogus id returns data with the same shape but a *different* body, the
  // endpoint may just echo random data — treat as ambiguous, not confirmed.
  const bogusIsRealMiss = isRealMiss(bogus);

  const neighborConfirms =
    neighbor !== null && isData(neighbor) && sameKeys(real, neighbor) && neighbor.hash !== real.hash;

  // Confirmed: real object returned with no auth, a *different* neighbour record is
  // reachable (walkable id space), and a bogus id is correctly rejected.
  if (neighborConfirms && bogusIsRealMiss) {
    return {
      confidence: 'confirmed',
      severity: 'critical',
      reason: 'anonymous request returned a real record; a neighbouring id returned a different record; a nonexistent id was rejected',
    };
  }

  // Likely: no-auth object access on a real lookup (bogus rejected), but we could not
  // demonstrate a walk (e.g. random UUID ids). Strong when the resource is owned data.
  if (bogusIsRealMiss) {
    return {
      confidence: 'likely',
      severity: ep.sensitive ? 'high' : 'medium',
      reason: 'anonymous request returned a real record by direct id reference; a nonexistent id was rejected',
    };
  }

  // Suspected: returns data without auth, but the bogus id also returned object-shaped
  // data, so we cannot rule out a public/catch-all endpoint. Flag softly to verify.
  return {
    confidence: 'suspected',
    severity: ep.sensitive ? 'medium' : 'low',
    reason: 'endpoint returns object data to anonymous requests; could not confirm it is per-object — please verify',
  };
}

// ---------------------------------------------------------------------------
// 5) Orchestration — the detector itself. Fetcher is injectable for tests.
// ---------------------------------------------------------------------------

export type Fetcher = (url: string) => Promise<SafeFetchResult>;

const defaultFetcher: Fetcher = (url) =>
  safeFetch(url, {
    method: 'GET',
    redirect: 'manual', // don't get pulled into a login redirect flow
    timeoutMs: PER_REQUEST_TIMEOUT_MS,
    maxBytes: PER_REQUEST_MAX_BYTES,
    // No cookies, no Authorization: this is the "anonymous client" probe by design.
    headers: { accept: 'application/json' },
  });

function buildUrl(origin: string, template: string, id: string): string {
  return origin + template.replace(ID_PLACEHOLDER, encodeURIComponent(id));
}

async function probe(fetcher: Fetcher, url: string): Promise<Fingerprint> {
  try {
    return fingerprint(await fetcher(url));
  } catch {
    return fingerprint(null);
  }
}

function describe(ep: EndpointTemplate, real: Fingerprint, neighbor: Fingerprint | null, bogus: Fingerprint, v: IdorVerdict): string {
  const realPath = ep.template.replace(ID_PLACEHOLDER, ep.sampleId);
  const parts = [`GET ${realPath} → ${real.status} (record)`];
  if (neighbor) {
    const nId = neighborId(ep.kind, ep.sampleId);
    const diff = isData(neighbor) && neighbor.hash !== real.hash ? 'different record' : `${neighbor.status}`;
    if (nId) parts.push(`${ep.template.replace(ID_PLACEHOLDER, nId)} → ${diff}`);
  }
  parts.push(`bogus id → ${bogus.status === 0 ? 'no response' : bogus.shape === 'html' ? '200 (not found)' : bogus.status}`);
  const fields = real.keys.length ? ` · fields: ${real.keys.join(', ')}` : '';
  return `${parts.join(' · ')} — no auth sent (${v.confidence})${fields}`;
}

export async function detectIdor(
  collected: CollectResult,
  fetcher: Fetcher = defaultFetcher
): Promise<Finding[]> {
  if (!collected.origin) return [];

  const endpoints = harvestEndpoints(collected.jsCombined, collected.html);
  if (endpoints.length === 0) return [];

  // Probe every endpoint concurrently (each is 3 parallel requests). On a slow
  // host this bounds the wait at the slowest endpoint, not the sum of all.
  const probed = await Promise.all(
    endpoints.map(async (ep) => {
      const nId = neighborId(ep.kind, ep.sampleId);
      const [real, neighbor, bogus] = await Promise.all([
        probe(fetcher, buildUrl(collected.origin, ep.template, ep.sampleId)),
        nId ? probe(fetcher, buildUrl(collected.origin, ep.template, nId)) : Promise.resolve(null),
        probe(fetcher, buildUrl(collected.origin, ep.template, bogusId(ep.kind, ep.sampleId))),
      ]);
      return { ep, real, neighbor, bogus, verdict: decide(ep, real, neighbor, bogus) };
    })
  );

  const findings: Finding[] = [];
  const seenResources = new Set<string>(); // one finding per resource — no spam

  // Apply the per-resource dedup in the original endpoint order so the same
  // endpoint "wins" a resource as before parallelizing.
  for (const { ep, real, neighbor, bogus, verdict } of probed) {
    if (!verdict) continue;
    if (seenResources.has(ep.resource)) continue;
    seenResources.add(ep.resource);

    findings.push({
      type: 'bola_idor',
      severity: verdict.severity,
      category: 'auth',
      summary:
        verdict.confidence === 'confirmed'
          ? `Anyone can read other users’ ${ep.resource} by changing the id at ${ep.template} — no login required.`
          : verdict.confidence === 'likely'
            ? `${ep.template} returns a ${ep.resource} record to anyone with no login — verify it isn’t meant to be private.`
            : `${ep.template} returns data without a login; confirm ${ep.resource} there is meant to be public.`,
      evidence: describe(ep, real, neighbor, bogus, verdict),
      params: { path: ep.template, resource: ep.resource },
    });
  }

  return findings;
}
