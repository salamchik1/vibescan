/** A JWT found in scanned JS, with its decoded payload (if parseable). */
export interface FoundJwt {
  raw: string;
  payload: Record<string, unknown> | null;
}

const JWT_RE = /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;

function decodeSegment(seg: string): Record<string, unknown> | null {
  try {
    const json = Buffer.from(seg.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    const obj = JSON.parse(json);
    return obj && typeof obj === 'object' ? (obj as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** Extract all JWT-looking tokens from text and decode their payloads. */
export function extractJwts(text: string): FoundJwt[] {
  const out: FoundJwt[] = [];
  const seen = new Set<string>();
  for (const match of text.matchAll(JWT_RE)) {
    const raw = match[0];
    if (seen.has(raw)) continue;
    seen.add(raw);
    const parts = raw.split('.');
    out.push({ raw, payload: parts[1] ? decodeSegment(parts[1]) : null });
  }
  return out;
}

/** Supabase keys are JWTs whose payload carries a `role`. */
export function jwtRole(jwt: FoundJwt): string | null {
  const role = jwt.payload?.['role'];
  return typeof role === 'string' ? role : null;
}
