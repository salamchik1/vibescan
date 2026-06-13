import { detectSecrets } from './detectors/secrets';
import { detectOwasp } from './detectors/owasp';
import { detectIdor, harvestEndpoints, type Fetcher } from './detectors/idor';
import type { CollectResult } from './collector';
import type { SafeFetchResult } from './util/fetch';
import type { Probe, ProbeResponse } from './verify/liveness';
import type { Finding } from '@vibescan/findings';

let failures = 0;
function check(name: string, ok: boolean) {
  console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${name}`);
  if (!ok) failures += 1;
}
function has(findings: Finding[], predicate: (f: Finding) => boolean): boolean {
  return findings.some(predicate);
}
function b64url(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}

// A service_role JWT (admin key that must never be in the browser).
const serviceRoleJwt = `${b64url({ alg: 'HS256', typ: 'JWT' })}.${b64url({
  role: 'service_role',
  iss: 'supabase',
})}.c2lnbmF0dXJlX3Rlc3Q`;

const js = [
  `const stripeKey = "sk_live_${'A1b2C3d4'.repeat(3)}";`,
  `const openaiKey = "sk-proj-${'Zx9Yw8Vu'.repeat(5)}";`,
  `const awsKey = "AKIAIOSFODNN7EXAMPLE";`,
  `const anthropic = "sk-ant-api03-${'Aa0Bb1Cc2'.repeat(9)}";`,
  `const gh = "ghp_${'A1b2C3d4e5'.repeat(3)}aaaaaa";`,
  `const dbUrl = "postgresql://app_user:S3cr3tPass@db.prod.example.com:5432/main";`,
  `const supabaseAdmin = "${serviceRoleJwt}";`,
  `//# sourceMappingURL=/assets/main-abc123.js.map`,
].join('\n');

const collected: CollectResult = {
  finalUrl: 'https://demo.test',
  origin: '', // empty -> owasp skips network probes, runs header/clickjacking/sourcemap only
  status: 200,
  responseHeaders: {}, // no security headers set
  setCookies: [],
  html: '',
  scripts: [],
  jsCombined: js,
  requestedHosts: [],
  notes: [],
};

console.log('Detector tests (offline):');

const secrets = await detectSecrets(collected);
check('finds Stripe live secret key', has(secrets, (f) => /Stripe live/.test(f.summary) && f.severity === 'critical'));
check('finds OpenAI key', has(secrets, (f) => /OpenAI/.test(f.summary) && f.severity === 'critical'));
check('finds AWS access key id', has(secrets, (f) => /AWS access key/.test(f.summary)));
check('finds Anthropic API key', has(secrets, (f) => /Anthropic/.test(f.summary) && f.severity === 'critical'));
check('finds GitHub token', has(secrets, (f) => /GitHub token/.test(f.summary)));
check('finds DB connection string', has(secrets, (f) => f.type === 'database_url_exposed' && /PostgreSQL/.test(f.summary) && f.severity === 'critical'));
check('connection string password is masked', !secrets.some((f) => /S3cr3tPass/.test(f.summary + (f.evidence ?? ''))));
check('finds Supabase service_role key', has(secrets, (f) => /service_role/.test(f.summary) && f.severity === 'critical'));
check('all secret findings are masked (no raw sk_live_)', !secrets.some((f) => /sk_live_[A-Za-z0-9]{8,}/.test(f.summary + (f.evidence ?? ''))));
check('OpenAI rule does not swallow the Anthropic key', !secrets.some((f) => /OpenAI/.test(f.summary) && /ant/.test(f.evidence ?? '')));

// --- Secret liveness verification (offline, mock probe) ---------------------

function probeResponse(status: number, body: unknown, headers: Record<string, string> = {}): ProbeResponse {
  const lower: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;
  return {
    status,
    bodyText: typeof body === 'string' ? body : JSON.stringify(body),
    getHeader: (name) => lower[name.toLowerCase()] ?? null,
  };
}

// Every provider accepts the key (200 + a benign identity body).
const liveProbe: Probe = async () =>
  probeResponse(200, { login: 'octocat', ok: true, name: 'octocat', username: 'octocat' }, { 'x-oauth-scopes': 'repo, gist' });
const verified = await detectSecrets(collected, { verify: true, probe: liveProbe });
check('marks a live Stripe key as confirmed active', has(verified, (f) => /Stripe live/.test(f.summary) && f.verification?.status === 'active'));
check('confirmed-live finding stays critical', has(verified, (f) => /Stripe live/.test(f.summary) && f.severity === 'critical'));
check('records the read-only endpoint used', has(verified, (f) => /OpenAI/.test(f.summary) && /api\.openai\.com/.test(f.verification?.checkedEndpoint ?? '')));
check('does NOT attach verification to unsupported providers (AWS)', verified.find((f) => /AWS access key/.test(f.summary))?.verification === undefined);
check('verification never leaks the raw secret', !verified.some((f) => /sk_live_[A-Za-z0-9]{8,}|sk-proj-/.test(JSON.stringify(f.verification ?? {}))));

// Every provider rejects the key (401) -> revoked.
const deadProbe: Probe = async () => probeResponse(401, { error: 'invalid', ok: false });
const revoked = await detectSecrets(collected, { verify: true, probe: deadProbe });
check('flags a revoked key as inactive', has(revoked, (f) => /Stripe live/.test(f.summary) && f.verification?.status === 'inactive'));
check('downgrades a revoked critical key to low (kills the false alarm)', has(revoked, (f) => /Stripe live/.test(f.summary) && f.severity === 'low'));

// Provider unreachable (probe returns null) -> unverified, severity untouched.
const downProbe: Probe = async () => null;
const unconfirmed = await detectSecrets(collected, { verify: true, probe: downProbe });
check('marks a key unverified when the provider is unreachable', has(unconfirmed, (f) => /OpenAI/.test(f.summary) && f.verification?.status === 'unverified'));
check('unverified key keeps its original severity', has(unconfirmed, (f) => /OpenAI/.test(f.summary) && f.severity === 'critical'));

// Verification is opt-in: default scan attaches nothing.
check('no verification field when verify is off', !secrets.some((f) => f.verification !== undefined));

const owasp = await detectOwasp(collected);
check('flags missing security headers', has(owasp, (f) => f.type === 'missing_security_headers'));
check('flags clickjacking (no frame protection)', has(owasp, (f) => f.type === 'clickjacking'));
check('flags exposed source maps', has(owasp, (f) => f.type === 'exposed_sourcemap'));

// Headers present -> no header/clickjacking findings.
const secured: CollectResult = {
  ...collected,
  origin: '',
  responseHeaders: {
    'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'strict-origin-when-cross-origin',
  },
  jsCombined: 'const x = 1;',
};
const owaspSecured = await detectOwasp(secured);
check('no header findings when headers are present', !has(owaspSecured, (f) => f.type === 'missing_security_headers'));
check('no clickjacking when frame protection present', !has(owaspSecured, (f) => f.type === 'clickjacking'));

// Weak CSP: present but neutered by unsafe-inline.
const weakCsp: CollectResult = {
  ...collected,
  origin: '',
  responseHeaders: {
    'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'",
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
  },
  jsCombined: 'const x = 1;',
};
const owaspWeakCsp = await detectOwasp(weakCsp);
check('flags weak CSP (unsafe-inline/unsafe-eval)', has(owaspWeakCsp, (f) => f.type === 'weak_csp'));
check('weak CSP with unsafe-eval is medium', has(owaspWeakCsp, (f) => f.type === 'weak_csp' && f.severity === 'medium'));

// Insecure session cookie missing HttpOnly + SameSite (origin '' -> no Secure requirement, no CORS network).
const cookieCase: CollectResult = {
  ...collected,
  origin: '',
  responseHeaders: { 'content-security-policy': "default-src 'self'; frame-ancestors 'none'" },
  setCookies: ['session_id=abc123; Path=/', 'theme=dark; Path=/'],
  jsCombined: 'const x = 1;',
};
const owaspCookie = await detectOwasp(cookieCase);
check('flags insecure session cookie', has(owaspCookie, (f) => f.type === 'insecure_cookie' && /session_id/.test(f.summary)));
check('ignores non-auth cookies', !has(owaspCookie, (f) => f.type === 'insecure_cookie' && /theme/.test(f.summary)));

// --- IDOR / BOLA detector (offline, mock fetcher) ---------------------------

function json(status: number, body: unknown): SafeFetchResult {
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  return { ok: status < 400, status, headers: { 'content-type': 'application/json' }, body: text, truncated: false, url: 'mock' };
}
function htmlRes(status: number): SafeFetchResult {
  return { ok: status < 400, status, headers: { 'content-type': 'text/html' }, body: '<!doctype html><html><body>app</body></html>', truncated: false, url: 'mock' };
}
const lastId = (url: string) => (url.split('?')[0] ?? '').split('/').pop() ?? '';

const idorBase: CollectResult = {
  finalUrl: 'https://demo.test',
  origin: 'https://demo.test',
  status: 200,
  responseHeaders: {},
  setCookies: [],
  html: '',
  scripts: [],
  jsCombined: '',
  requestedHosts: [],
  notes: [],
};

// Harvesting: real id-bearing endpoints from the page's own code; assets ignored.
const harvested = harvestEndpoints(
  "fetch('/api/orders/1042'); const u = `/api/users/${id}`; img.src='/assets/logo/12.png';",
  ''
);
check('harvests literal numeric endpoint /api/orders', harvested.some((e) => e.template === '/api/orders/%ID%' && e.sampleId === '1042' && e.kind === 'numeric'));
check('harvests dynamic template /api/users', harvested.some((e) => e.template === '/api/users/%ID%' && e.source === 'dynamic'));
check('ignores asset paths', !harvested.some((e) => e.template.includes('assets')));
check('marks owned resources as sensitive', harvested.find((e) => e.resource === 'orders')?.sensitive === true);

// Confirmed IDOR: real record returned with no auth, neighbour is a different record,
// bogus id is rejected.
const confirmFetch: Fetcher = async (url) => {
  const id = lastId(url);
  if (id === '1042') return json(200, { id: 1042, total: 59, email: 'a@b.com' });
  if (id === '1041') return json(200, { id: 1041, total: 12, email: 'c@d.com' });
  return json(404, { error: 'not found' });
};
const idorConfirmed = await detectIdor({ ...idorBase, jsCombined: "fetch('/api/orders/1042')" }, confirmFetch);
check('flags confirmed IDOR as critical', has(idorConfirmed, (f) => f.type === 'bola_idor' && f.severity === 'critical'));
check('confirmed IDOR mentions the endpoint', has(idorConfirmed, (f) => /\/api\/orders\/%ID%/.test(f.summary)));
check('IDOR evidence never leaks record values', !idorConfirmed.some((f) => /a@b\.com|c@d\.com/.test(f.evidence ?? '')));

// False-positive guard: a public/static endpoint returns the SAME body for every id.
const staticFetch: Fetcher = async () => json(200, { headline: 'About us', body: 'public' });
const idorStatic = await detectIdor({ ...idorBase, jsCombined: "fetch('/api/products/5')" }, staticFetch);
check('does NOT flag a static/public endpoint (same body for any id)', !has(idorStatic, (f) => f.type === 'bola_idor'));

// SPA-shell guard: every id returns the index.html fallback -> not object data.
const shellFetch: Fetcher = async () => htmlRes(200);
const idorShell = await detectIdor({ ...idorBase, jsCombined: "fetch('/api/posts/7')" }, shellFetch);
check('does NOT flag an SPA catch-all (HTML for any id)', !has(idorShell, (f) => f.type === 'bola_idor'));

// Likely (UUID): no-auth object access, bogus rejected, but no walkable neighbour.
const uuidId = '11111111-1111-4111-8111-111111111111';
const uuidFetch: Fetcher = async (url) =>
  lastId(url) === uuidId ? json(200, { id: uuidId, owner: 'x', balance: 100 }) : json(404, { error: 'no' });
const idorUuid = await detectIdor({ ...idorBase, jsCombined: `fetch('/api/accounts/${uuidId}')` }, uuidFetch);
check('flags no-auth UUID object access as high (likely)', has(idorUuid, (f) => f.type === 'bola_idor' && f.severity === 'high'));

if (failures > 0) {
  console.error(`\n${failures} detector test(s) failed.`);
  process.exit(1);
}
console.log('\nAll detector tests passed.');
