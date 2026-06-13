import type { Finding } from '@vibescan/findings';
import type { CollectResult } from '../collector';
import { safeFetch } from '../util/fetch';

interface HeaderCheck {
  label: string;
  present: (h: Record<string, string>) => boolean;
}

const HEADER_CHECKS: HeaderCheck[] = [
  { label: 'Content-Security-Policy', present: (h) => 'content-security-policy' in h },
  {
    label: 'X-Frame-Options',
    present: (h) =>
      'x-frame-options' in h || /frame-ancestors/i.test(h['content-security-policy'] ?? ''),
  },
  { label: 'Strict-Transport-Security', present: (h) => 'strict-transport-security' in h },
  { label: 'X-Content-Type-Options', present: (h) => 'x-content-type-options' in h },
  { label: 'Referrer-Policy', present: (h) => 'referrer-policy' in h },
];

const CORS_PROBE_ORIGIN = 'https://vibescan-cors-probe.example';
const AUTH_COOKIE_RE = /(sess|sid|auth|token|jwt|login|sb-|connect|csrf|xsrf)/i;

export async function detectOwasp(collected: CollectResult): Promise<Finding[]> {
  const findings: Finding[] = [];
  const h = collected.responseHeaders;
  const isHttps = collected.origin.startsWith('https://');

  // 1) Missing security headers (HSTS only meaningful on https).
  const missing = HEADER_CHECKS.filter((c) => {
    if (c.label === 'Strict-Transport-Security' && !isHttps) return false;
    return !c.present(h);
  }).map((c) => c.label);

  if (missing.length > 0) {
    findings.push({
      type: 'missing_security_headers',
      severity: missing.length >= 3 ? 'medium' : 'low',
      category: 'owasp',
      summary: `Missing ${missing.length} security header(s): ${missing.join(', ')}.`,
      evidence: missing.join(', '),
      params: { headers: missing.join(', ') },
    });
  }

  // 2) Clickjacking: no frame protection at all.
  const frameProtected =
    'x-frame-options' in h || /frame-ancestors/i.test(h['content-security-policy'] ?? '');
  if (!frameProtected) {
    findings.push({
      type: 'clickjacking',
      severity: 'low',
      category: 'owasp',
      summary: 'Your site can be embedded in a hidden frame by other sites.',
    });
  }

  // 3) Weak CSP: present but neutered by unsafe-inline / unsafe-eval / wildcard script source.
  const csp = h['content-security-policy'];
  if (csp) {
    const weakness = analyzeCsp(csp);
    if (weakness) {
      findings.push({
        type: 'weak_csp',
        severity: weakness.includes('unsafe-eval') ? 'medium' : 'low',
        category: 'owasp',
        summary: `Your Content-Security-Policy is weakened by ${weakness}.`,
        evidence: weakness,
        params: { weakness },
      });
    }
  }

  // 4) Source maps served in production (no network needed — read from collected JS).
  if (/\/\/[#@]\s*sourceMappingURL=.+\.map/.test(collected.jsCombined)) {
    findings.push({
      type: 'exposed_sourcemap',
      severity: 'low',
      category: 'owasp',
      summary: 'Source maps (.js.map) are served, revealing your original source code.',
    });
  }

  // 5) Insecure cookies: session/auth cookies missing HttpOnly / Secure / SameSite.
  for (const finding of analyzeCookies(collected.setCookies, isHttps)) findings.push(finding);

  // 6) Mixed content: an HTTPS page pulling active resources over plain HTTP.
  if (isHttps) {
    const example = findMixedContent(collected.html);
    if (example) {
      findings.push({
        type: 'mixed_content',
        severity: 'low',
        category: 'owasp',
        summary: 'Your HTTPS page loads an active resource over insecure HTTP.',
        evidence: example,
        params: { example },
      });
    }
  }

  // 7) CORS: does the API reflect any Origin while allowing credentials?
  if (collected.origin) {
    const cors = await safe(() => checkCors(collected.origin));
    if (cors) findings.push(cors);
  }

  return findings;
}

/** Source-map exposure — the one OWASP signal derivable from JS text alone (reused by code-paste scans). */
export function detectSourceMaps(collected: CollectResult): Finding[] {
  if (/\/\/[#@]\s*sourceMappingURL=.+\.map/.test(collected.jsCombined)) {
    return [
      {
        type: 'exposed_sourcemap',
        severity: 'low',
        category: 'owasp',
        summary: 'Source maps (.js.map) are referenced, revealing your original source code.',
      },
    ];
  }
  return [];
}

function analyzeCsp(csp: string): string | null {
  const lower = csp.toLowerCase();
  const directives = lower.split(';').map((d) => d.trim());
  const scriptSrc =
    directives.find((d) => d.startsWith('script-src')) ??
    directives.find((d) => d.startsWith('default-src')) ??
    '';
  const issues: string[] = [];
  if (scriptSrc.includes("'unsafe-inline'")) issues.push("'unsafe-inline'");
  if (scriptSrc.includes("'unsafe-eval'")) issues.push("'unsafe-eval'");
  // A bare wildcard source (not part of a domain like *.example.com).
  if (/(^|\s)\*(\s|$)/.test(scriptSrc)) issues.push('a wildcard (*) script source');
  return issues.length ? issues.join(', ') : null;
}

function analyzeCookies(setCookies: string[], isHttps: boolean): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();
  for (const raw of setCookies) {
    const name = raw.split('=')[0]?.trim() ?? '';
    if (!name || !AUTH_COOKIE_RE.test(name)) continue; // only flag session/auth-looking cookies
    if (seen.has(name)) continue;
    seen.add(name);
    const attrs = raw.toLowerCase();
    const missing: string[] = [];
    if (!/;\s*httponly/.test(attrs)) missing.push('HttpOnly');
    if (isHttps && !/;\s*secure/.test(attrs)) missing.push('Secure');
    if (!/;\s*samesite/.test(attrs)) missing.push('SameSite');
    if (missing.length === 0) continue;
    findings.push({
      type: 'insecure_cookie',
      severity: 'medium',
      category: 'owasp',
      summary: `Cookie "${name}" is missing ${missing.join(', ')}.`,
      evidence: `${name}: missing ${missing.join(', ')}`,
      params: { name, flags: missing.join(', ') },
    });
  }
  return findings;
}

function findMixedContent(html: string): string | null {
  const re = /<(?:script|iframe|link)\b[^>]*?(?:src|href)\s*=\s*["'](http:\/\/[^"']+)["']/i;
  const m = re.exec(html);
  return m?.[1] ? m[1].slice(0, 120) : null;
}

async function checkCors(origin: string): Promise<Finding | null> {
  const res = await safeFetch(origin + '/', {
    timeoutMs: 7_000,
    maxBytes: 2_000,
    headers: { origin: CORS_PROBE_ORIGIN },
  });
  const acao = res.headers['access-control-allow-origin'];
  const acac = (res.headers['access-control-allow-credentials'] ?? '').toLowerCase() === 'true';
  if (!acao) return null;
  const reflected = acao === CORS_PROBE_ORIGIN;
  if (reflected && acac) {
    return {
      type: 'cors_misconfig',
      severity: 'high',
      category: 'owasp',
      summary: 'Your server reflects any website as an allowed origin while sending credentials.',
      evidence: `Origin ${CORS_PROBE_ORIGIN} reflected + Allow-Credentials: true`,
      params: { origin: 'any website' },
    };
  }
  if (reflected) {
    return {
      type: 'cors_misconfig',
      severity: 'low',
      category: 'owasp',
      summary: 'Your server reflects any website in Access-Control-Allow-Origin.',
      evidence: `Origin ${CORS_PROBE_ORIGIN} reflected back`,
      params: { origin: 'any website' },
    };
  }
  return null;
}

async function safe<T>(fn: () => Promise<T>): Promise<T | null> {
  try {
    return await fn();
  } catch {
    return null;
  }
}
