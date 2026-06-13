import { base64ToBytes } from './bytes';

// Browser-side port of apps/scanner/src/util/jwt.ts, extended with the security
// checks a debugger needs: alg:none, long-lived / non-expiring tokens, and
// sensitive data carried in the claims.

export type IssueLevel = 'critical' | 'warning' | 'info';

export interface JwtIssue {
  level: IssueLevel;
  title: string;
  detail: string;
}

export interface JwtAnalysis {
  valid: boolean;
  error?: string;
  header: Record<string, unknown> | null;
  payload: Record<string, unknown> | null;
  signature: string;
  alg: string | null;
  /** Friendly rows for the standard time claims, when present. */
  timeline: { label: string; claim: string; value: string }[];
  issues: JwtIssue[];
}

const SECONDS_PER_DAY = 86_400;

/** Decode one base64url JWT segment into an object (or null if not JSON). */
function decodeSegment(seg: string): Record<string, unknown> | null {
  try {
    const json = new TextDecoder('utf-8', { fatal: false }).decode(base64ToBytes(seg));
    const obj = JSON.parse(json);
    return obj && typeof obj === 'object' ? (obj as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

// Claim keys (or substrings) that should never travel inside a token payload.
const SENSITIVE_KEY_RE =
  /pass(word|wd)?|secret|api[_-]?key|private[_-]?key|ssn|social.?security|credit.?card|card.?number|cvv|pin|mfa|otp/i;
// Standard, expected claims we should NOT flag as "sensitive".
const STANDARD_CLAIMS = new Set([
  'iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti', 'role', 'roles', 'scope', 'scopes', 'azp',
  'typ', 'email', 'email_verified', 'name', 'given_name', 'family_name', 'picture', 'preferred_username',
]);

function fmtTime(seconds: number): string {
  const d = new Date(seconds * 1000);
  if (Number.isNaN(d.getTime())) return String(seconds);
  return `${d.toUTCString()} (${seconds})`;
}

function humanizeDuration(seconds: number): string {
  const abs = Math.abs(seconds);
  if (abs < 90) return `${Math.round(abs)} seconds`;
  if (abs < 90 * 60) return `${Math.round(abs / 60)} minutes`;
  if (abs < 36 * 3600) return `${Math.round(abs / 3600)} hours`;
  return `${Math.round(abs / SECONDS_PER_DAY)} days`;
}

export function analyzeJwt(raw: string): JwtAnalysis {
  const token = raw.trim().replace(/^Bearer\s+/i, '');
  const empty: JwtAnalysis = {
    valid: false,
    header: null,
    payload: null,
    signature: '',
    alg: null,
    timeline: [],
    issues: [],
  };

  if (!token) return empty;

  const parts = token.split('.');
  if (parts.length < 2 || parts.length > 3) {
    return { ...empty, error: 'A JWT has the shape header.payload.signature — this does not.' };
  }

  const header = decodeSegment(parts[0]);
  const payload = decodeSegment(parts[1]);
  const signature = parts[2] ?? '';

  if (!header || !payload) {
    return {
      ...empty,
      header,
      payload,
      signature,
      error: 'The header or payload is not valid base64url-encoded JSON.',
    };
  }

  const alg = typeof header['alg'] === 'string' ? (header['alg'] as string) : null;
  const issues: JwtIssue[] = [];

  // 1) alg:none — signature is not verified at all.
  if (alg && alg.toLowerCase() === 'none') {
    issues.push({
      level: 'critical',
      title: 'Algorithm is "none"',
      detail:
        'This token is unsigned. Any server that accepts alg:none will trust a payload anyone can forge. Reject "none" and pin the expected algorithm when you verify.',
    });
  }
  if (parts.length === 2 || signature === '') {
    issues.push({
      level: 'warning',
      title: 'No signature segment',
      detail: 'This token carries no signature, so its contents cannot be trusted unless re-issued.',
    });
  }

  // 2) Expiry / lifetime checks.
  const exp = typeof payload['exp'] === 'number' ? (payload['exp'] as number) : null;
  const iat = typeof payload['iat'] === 'number' ? (payload['iat'] as number) : null;
  const nbf = typeof payload['nbf'] === 'number' ? (payload['nbf'] as number) : null;
  const now = Math.floor(Date.now() / 1000);

  const timeline: JwtAnalysis['timeline'] = [];
  if (iat !== null) timeline.push({ label: 'Issued at', claim: 'iat', value: fmtTime(iat) });
  if (nbf !== null) timeline.push({ label: 'Not before', claim: 'nbf', value: fmtTime(nbf) });
  if (exp !== null) timeline.push({ label: 'Expires', claim: 'exp', value: fmtTime(exp) });

  if (exp === null) {
    issues.push({
      level: 'warning',
      title: 'No expiry (exp)',
      detail:
        'This token never expires. If it leaks, it works forever. Always set a short exp and refresh tokens server-side.',
    });
  } else if (exp < now) {
    issues.push({
      level: 'info',
      title: 'Already expired',
      detail: `This token expired ${humanizeDuration(now - exp)} ago (${fmtTime(exp)}).`,
    });
  } else {
    const lifetime = iat !== null ? exp - iat : exp - now;
    if (lifetime > 30 * SECONDS_PER_DAY) {
      issues.push({
        level: 'warning',
        title: 'Very long-lived token',
        detail: `This token is valid for about ${humanizeDuration(lifetime)}. Long lifetimes turn a single leak into long-term access — prefer minutes/hours plus refresh tokens.`,
      });
    } else if (lifetime > SECONDS_PER_DAY) {
      issues.push({
        level: 'info',
        title: 'Long-lived token',
        detail: `This token is valid for about ${humanizeDuration(lifetime)}. Consider a shorter lifetime for access tokens.`,
      });
    }
  }

  // 3) Sensitive data in claims.
  const sensitive = Object.keys(payload).filter(
    (k) => !STANDARD_CLAIMS.has(k.toLowerCase()) && SENSITIVE_KEY_RE.test(k)
  );
  if (sensitive.length > 0) {
    issues.push({
      level: 'warning',
      title: 'Sensitive data in claims',
      detail: `The payload contains claim(s) that look sensitive: ${sensitive.join(', ')}. Remember a JWT payload is only base64 — anyone holding the token can read it. Never put passwords, secrets, or card data in claims.`,
    });
  }

  if (issues.length === 0) {
    issues.push({
      level: 'info',
      title: 'No common problems found',
      detail:
        'No alg:none, missing expiry, or sensitive claims detected. Note this tool cannot verify the signature — that requires the secret/public key on your server.',
    });
  }

  return { valid: true, header, payload, signature, alg, timeline, issues };
}
