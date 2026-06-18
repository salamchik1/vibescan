/** A JWT found in scanned JS, with its decoded header/payload (if parseable). */
export interface FoundJwt {
  raw: string;
  /** Decoded header (first segment) — carries `alg`/`typ`. Null if unparseable. */
  header: Record<string, unknown> | null;
  /** Decoded payload (second segment) — carries `role`/`exp`/… Null if unparseable. */
  payload: Record<string, unknown> | null;
  /** Raw base64url signature (third segment). Empty string for `alg:none` tokens. */
  signature: string;
}

// Signed tokens: all three segments present (signature 8+ chars). Used by the
// secret/gitleaks/supabase detectors, which only care about real, signed keys.
const JWT_RE = /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;
// Candidate tokens: signature may be short or empty — an `alg:none` token is
// `header.payload.` with NO signature, so the strict regex above would miss it.
const JWT_CANDIDATE_RE = /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g;

/** Decode one base64url JWT segment to an object, or null if it isn't valid JSON. */
export function decodeJwtSegment(seg: string): Record<string, unknown> | null {
  try {
    const json = Buffer.from(seg.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    const obj = JSON.parse(json);
    return obj && typeof obj === 'object' ? (obj as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function toFoundJwt(raw: string): FoundJwt {
  const parts = raw.split('.');
  return {
    raw,
    header: parts[0] ? decodeJwtSegment(parts[0]) : null,
    payload: parts[1] ? decodeJwtSegment(parts[1]) : null,
    signature: parts[2] ?? '',
  };
}

function extract(text: string, re: RegExp): FoundJwt[] {
  const out: FoundJwt[] = [];
  const seen = new Set<string>();
  for (const match of text.matchAll(re)) {
    const raw = match[0];
    if (seen.has(raw)) continue;
    seen.add(raw);
    out.push(toFoundJwt(raw));
  }
  return out;
}

/** Extract all signed JWTs from text and decode their header/payload. */
export function extractJwts(text: string): FoundJwt[] {
  return extract(text, JWT_RE);
}

/**
 * Extract JWT-shaped tokens including unsigned (`alg:none`) ones, whose empty
 * signature the strict {@link extractJwts} pattern skips. For the JWT-weakness
 * detector, which must see tokens the others ignore.
 */
export function extractJwtCandidates(text: string): FoundJwt[] {
  return extract(text, JWT_CANDIDATE_RE);
}

/** Supabase keys are JWTs whose payload carries a `role`. */
export function jwtRole(jwt: FoundJwt): string | null {
  const role = jwt.payload?.['role'];
  return typeof role === 'string' ? role : null;
}
