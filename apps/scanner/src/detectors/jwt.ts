import { createHmac, timingSafeEqual } from 'node:crypto';
import type { Finding } from '@vibescan/findings';
import type { CollectResult } from '../collector';
import { extractJwtCandidates, type FoundJwt } from '../util/jwt';
import { maskSecret } from '../util/mask';

/**
 * JWT-weakness detector (the `auth` category) — an auth-bypass angle that is
 * strictly OFFLINE and safe: it reasons about JWTs already present in the
 * scanned JS/source, makes zero network calls, and forges nothing live.
 *
 * Three classic, high-signal token flaws:
 *  1. `alg:none`         — an unsigned token. If the backend accepts it, anyone
 *                          can mint any identity. Finding one minted in the code
 *                          is strong evidence the server issues/accepts them.
 *  2. weak HS256 secret  — the token is HMAC-signed with a guessable secret. We
 *                          confirm it by re-signing the token offline against a
 *                          tiny dictionary; a match means the signing key is
 *                          public-knowledge, so anyone can forge admin tokens.
 *  3. expired-but-shipped — a hard-coded token whose `exp` is already in the
 *                          past: a stale credential committed into the code.
 *
 * Only (2) is proven by computation (we reproduce the signature); it is the
 * critical, zero-false-positive case. (1) and (3) are read off the token itself.
 */

// A deliberately TINY dictionary of secrets people actually ship: framework
// defaults, tutorial copy-paste values, and lazy placeholders. We are not
// brute-forcing — we only catch keys that are essentially public knowledge.
const WEAK_SECRETS = [
  'secret',
  'secretkey',
  'secret-key',
  'secret_key',
  'jwt',
  'jwtsecret',
  'jwt-secret',
  'jwt_secret',
  'jwtSecret',
  'jwtPrivateKey',
  'mysecret',
  'mysecretkey',
  'supersecret',
  'supersecretkey',
  'password',
  'passw0rd',
  'changeme',
  'change-me',
  'changethis',
  'please-change-me',
  'topsecret',
  'shhhh',
  'secret123',
  's3cr3t',
  'test',
  'testing',
  'dev',
  'default',
  'example',
  'token',
  'key',
  'admin',
  'qwerty',
  '123456',
  '12345678',
  'your-256-bit-secret', // the jwt.io default
  'your_jwt_secret',
  'your-secret-key',
  'supabase',
  'supabase-jwt-secret',
  'nestjs',
  'auth0',
];

// HS* algorithms map to their HMAC hash. RS*/ES*/PS* are asymmetric — we cannot
// (and must not) attempt to recover a private key, so they are skipped.
const HMAC_HASH: Record<string, string> = { HS256: 'sha256', HS384: 'sha384', HS512: 'sha512' };

/** The token's `alg` header, upper-cased, or '' if absent/non-string. */
function jwtAlg(jwt: FoundJwt): string {
  const alg = jwt.header?.['alg'];
  return typeof alg === 'string' ? alg.toUpperCase() : '';
}

/**
 * Try to reproduce the token's signature with each dictionary secret. Returns
 * the matching weak secret, or null if none works. Pure local computation — the
 * same HMAC the server does, no network, nothing forged or sent anywhere.
 */
function crackHmacSecret(jwt: FoundJwt, hash: string): string | null {
  const dot = jwt.raw.lastIndexOf('.');
  if (dot <= 0) return null;
  const signingInput = jwt.raw.slice(0, dot);
  let expected: Buffer;
  try {
    expected = Buffer.from(jwt.signature.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  } catch {
    return null;
  }
  if (expected.length === 0) return null;
  for (const secret of WEAK_SECRETS) {
    const actual = createHmac(hash, secret).update(signingInput).digest();
    if (actual.length === expected.length && timingSafeEqual(actual, expected)) return secret;
  }
  return null;
}

/** Read the token's `exp` (seconds since epoch) as a number, or null if absent. */
function jwtExp(jwt: FoundJwt): number | null {
  const exp = jwt.payload?.['exp'];
  return typeof exp === 'number' && Number.isFinite(exp) ? exp : null;
}

export function detectJwt(collected: CollectResult): Finding[] {
  const findings: Finding[] = [];
  const nowSec = Date.now() / 1000;
  // One finding per (token, kind): a token reused across bundles shouldn't pile up.
  const seen = new Set<string>();
  const push = (key: string, finding: Finding): void => {
    if (seen.has(key)) return;
    seen.add(key);
    findings.push(finding);
  };

  for (const jwt of extractJwtCandidates(collected.jsCombined)) {
    const masked = maskSecret(jwt.raw, 12, 6); // keep `eyJ…header` recognizable
    const alg = jwtAlg(jwt);

    // 1) alg:none — an unsigned token. Critical if real: it's a forged-identity
    //    primitive. We require a parseable payload so random base64 can't trip it.
    if (alg === 'NONE' && jwt.payload) {
      push(`none::${jwt.raw}`, {
        type: 'jwt_alg_none',
        severity: 'high',
        category: 'auth',
        summary: `A JSON Web Token using "alg":"none" (unsigned) is present in your code (${masked}) — if your server accepts it, anyone can forge a login.`,
        evidence: masked,
        params: { token: masked },
      });
      continue; // an unsigned token has no secret to crack
    }

    // 2) Weak HS256 secret — confirmed by reproducing the signature offline.
    const hash = HMAC_HASH[alg];
    if (hash) {
      const weak = crackHmacSecret(jwt, hash);
      if (weak) {
        push(`weak::${jwt.raw}`, {
          type: 'jwt_weak_secret',
          severity: 'critical',
          category: 'auth',
          summary: `A JSON Web Token is signed with a trivially guessable ${alg} secret ("${weak}") — anyone can forge valid tokens for any user (${masked}).`,
          evidence: masked,
          params: { token: masked, algorithm: alg, secret: weak },
        });
        continue; // already the worst case for this token
      }
    }

    // 3) Expired token still hard-coded in the shipped code.
    const exp = jwtExp(jwt);
    if (exp !== null && exp < nowSec) {
      const daysAgo = Math.floor((nowSec - exp) / 86_400);
      const ago = daysAgo >= 1 ? `${daysAgo} day${daysAgo === 1 ? '' : 's'} ago` : 'recently';
      push(`exp::${jwt.raw}`, {
        type: 'jwt_expired',
        severity: 'low',
        category: 'auth',
        summary: `An expired JSON Web Token (expired ${ago}) is hard-coded in your code (${masked}) — a stale credential that should not be committed.`,
        evidence: masked,
        params: { token: masked },
      });
    }
  }

  return findings;
}
