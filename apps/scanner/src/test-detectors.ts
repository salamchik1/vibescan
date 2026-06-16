import { detectSecrets } from './detectors/secrets';
import { detectOwasp } from './detectors/owasp';
import { detectIdor, harvestEndpoints, type Fetcher } from './detectors/idor';
import { hitsToFindings, type GitleaksHit } from './detectors/gitleaks';
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
  // A real response that carries no *security* headers (only the baseline
  // Content-Type every response has). The detector's gotResponse guard treats
  // a fully empty header map as "navigation failed", so we include this to
  // exercise the missing-header / clickjacking paths.
  responseHeaders: { 'content-type': 'text/html' },
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

// --- Generic high-entropy fallback: precision over recall -------------------
// A random, high-entropy token with NO secret-ish keyword nearby (build hash,
// asset blob, ad/tracking payload) must NOT be reported.
const noiseJs = [
  `<link href="/assets/app.${'Zx9Yw8Vu7t6'.repeat(3)}.css">`,
  `t.src="https://ads.example/p?afid=${'Qw3Er5Ty7Ui'.repeat(3)}";`,
].join('\n');
const noise = await detectSecrets({ ...collected, jsCombined: noiseJs });
check('does NOT flag high-entropy blobs without secret context', !has(noise, (f) => /high-entropy/.test(f.summary)));
// Base64 (contains '/') is treated as encoded binary, not a key — even with context.
const b64Js = `const apiKey = "${'AbC9/dEf2+'.repeat(4)}";`;
const b64 = await detectSecrets({ ...collected, jsCombined: b64Js });
check('does NOT flag base64 blobs as high-entropy secrets', !has(b64, (f) => /high-entropy/.test(f.summary)));
// A genuinely random token DOES get flagged when a keyword sits right before it.
const ctxJs = `const apiKey = "aB3xK9mZ2pQ7wL5vR8tN4cF6yH1jD0sGqW";`;
const ctx = await detectSecrets({ ...collected, jsCombined: ctxJs });
check('flags a high-entropy token that has secret context', has(ctx, (f) => /high-entropy/.test(f.summary) && f.severity === 'low'));

// --- Google API keys: publishable (safe) vs. unidentified -------------------
// `AIza…` keys are publishable by design for browser SDKs. A Firebase web config
// key MUST NOT be reported as a leaked secret — that's the false alarm we're killing.
const fakeGoogleKey = `AIza${'A1b2C3d4E5'.repeat(4).slice(0, 35)}`;
const firebaseJs = [
  'const firebaseConfig = {',
  `  apiKey: "${fakeGoogleKey}",`,
  '  authDomain: "demo.firebaseapp.com",',
  '  projectId: "demo",',
  '  messagingSenderId: "123456789",',
  '};',
].join('\n');
const fb = await detectSecrets({ ...collected, jsCombined: firebaseJs });
check('does NOT flag a publishable Firebase Google key', !has(fb, (f) => /Google API key/.test(f.summary)));

// A Maps JavaScript loader key is likewise publishable.
const mapsJs = `<script src="https://maps.googleapis.com/maps/api/js?key=${fakeGoogleKey}&libraries=places"></script>`;
const maps = await detectSecrets({ ...collected, jsCombined: mapsJs });
check('does NOT flag a Google Maps loader key', !has(maps, (f) => /Google API key/.test(f.summary)));

// An AIza key with no browser-SDK context is still surfaced, but only at low
// (it is dangerous solely when unrestricted, which the pattern cannot confirm).
const bareGoogleJs = `const k = "${fakeGoogleKey}";`;
const bareGoogle = await detectSecrets({ ...collected, jsCombined: bareGoogleJs });
check('flags an unidentified Google key as low (not high)', has(bareGoogle, (f) => /Google API key/.test(f.summary) && f.severity === 'low'));
check('a genuinely dangerous Google OAuth client secret is still high', !has(fb, (f) => /Google API key/.test(f.summary)) && (await detectSecrets({ ...collected, jsCombined: 'const s = "GOCSPX-aZ19bQ_dummyClientSecretValue";' })).some((f) => /OAuth client secret/.test(f.summary) && f.severity === 'high'));

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

// --- Google key live restriction probe (verify on) --------------------------
// An unrestricted key that works against a billable API is escalated to high.
const gWorksProbe: Probe = async () => probeResponse(200, { status: 'OK', results: [] });
const gWorks = await detectSecrets({ ...collected, jsCombined: bareGoogleJs }, { verify: true, probe: gWorksProbe });
check('escalates a confirmed-unrestricted Google key to high', has(gWorks, (f) => /Google API key/.test(f.summary) && f.severity === 'high' && f.verification?.status === 'active'));

// A referrer-restricted key is proven safe and dropped from the report.
const gRestrictedProbe: Probe = async () =>
  probeResponse(200, { status: 'REQUEST_DENIED', error_message: 'API keys with referer restrictions cannot be used with this API.' });
const gRestricted = await detectSecrets({ ...collected, jsCombined: bareGoogleJs }, { verify: true, probe: gRestrictedProbe });
check('drops a Google key proven restricted/safe', !has(gRestricted, (f) => /Google API key/.test(f.summary)));

// A publishable-context key that turns out to be unrestricted IS surfaced (high) —
// verification overrides the by-design suppression so real misconfigs aren't hidden.
const gFirebaseDanger = await detectSecrets({ ...collected, jsCombined: firebaseJs }, { verify: true, probe: gWorksProbe });
check('surfaces a publishable key proven unrestricted as high', has(gFirebaseDanger, (f) => /Google API key/.test(f.summary) && f.severity === 'high'));

// An invalid / revoked key is dropped.
const gInvalidProbe: Probe = async () =>
  probeResponse(200, { status: 'REQUEST_DENIED', error_message: 'The provided API key is invalid.' });
const gInvalid = await detectSecrets({ ...collected, jsCombined: bareGoogleJs }, { verify: true, probe: gInvalidProbe });
check('drops an invalid/revoked Google key', !has(gInvalid, (f) => /Google API key/.test(f.summary)));

// The live check never leaks the raw key into the verification record.
check('Google verification never leaks the raw key', !gWorks.some((f) => new RegExp(fakeGoogleKey).test(JSON.stringify(f.verification ?? {}))));

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

// Advisory-only gap (the Apple case): every core header is set, only the
// browser-defaulted Referrer-Policy is absent -> not a finding.
const advisoryOnly: CollectResult = {
  ...secured,
  responseHeaders: {
    'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff',
    'strict-transport-security': 'max-age=63072000',
    // no referrer-policy
  },
};
const owaspAdvisory = await detectOwasp(advisoryOnly);
check('no finding when only Referrer-Policy (advisory) is missing', !has(owaspAdvisory, (f) => f.type === 'missing_security_headers'));

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

// A nonce + 'strict-dynamic' makes browsers ignore 'unsafe-inline' and the
// wildcard, so a policy like Google/YouTube's must NOT be flagged as weak.
const noncedCsp: CollectResult = {
  ...weakCsp,
  responseHeaders: {
    ...weakCsp.responseHeaders,
    'content-security-policy':
      "script-src 'nonce-r4nd0m' 'strict-dynamic' 'unsafe-inline' https: *",
  },
};
check(
  'no weak CSP finding when a nonce + strict-dynamic neutralise unsafe-inline/wildcard',
  !has(await detectOwasp(noncedCsp), (f) => f.type === 'weak_csp')
);

// ...but 'unsafe-eval' survives a nonce/strict-dynamic, so it is still flagged.
const noncedEvalCsp: CollectResult = {
  ...weakCsp,
  responseHeaders: {
    ...weakCsp.responseHeaders,
    'content-security-policy':
      "script-src 'nonce-r4nd0m' 'strict-dynamic' 'unsafe-inline' 'unsafe-eval'",
  },
};
check(
  "unsafe-eval is still flagged (medium) even with a nonce/strict-dynamic",
  has(await detectOwasp(noncedEvalCsp), (f) => f.type === 'weak_csp' && f.severity === 'medium')
);

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

// --- Gitleaks hit classification (JWT roles + repo vs URL wording) ----------
// A Supabase anon JWT (public by design — gated by RLS, not secrecy) and a
// service_role JWT (full admin). gitleaks' broad `jwt` rule fires on both.
const anonJwt = `${b64url({ alg: 'HS256', typ: 'JWT' })}.${b64url({ role: 'anon', iss: 'supabase' })}.c2lnbmF0dXJlX3Rlc3Q`;
const svcJwt = `${b64url({ alg: 'HS256', typ: 'JWT' })}.${b64url({ role: 'service_role', iss: 'supabase' })}.c2lnbmF0dXJlX3Rlc3Q`;

const anonHits = hitsToFindings([{ RuleID: 'jwt', Secret: anonJwt, File: 'src/db.ts', Commit: 'abc1234567def' }], true);
check('drops a public-by-design Supabase anon JWT (no false positive)', anonHits.length === 0);

const svcHits = hitsToFindings([{ RuleID: 'jwt', Secret: svcJwt, File: 'src/db.ts', Commit: 'abc1234567def' }], true);
check('keeps a Supabase service_role JWT as critical', svcHits.some((f) => f.severity === 'critical' && /service_role/.test(f.summary)));
check('service_role finding never leaks the raw JWT', !svcHits.some((f) => (f.summary + (f.evidence ?? '')).includes(svcJwt)));

// A roleless JWT (session/demo token, e.g. the jwt.io sample our JWT decoder
// ships) is low-signal: surfaced, but as a `low` unverified finding, not a
// screaming critical. Only role:service_role stays critical (checked above).
const plainJwt = `${b64url({ alg: 'HS256', typ: 'JWT' })}.${b64url({ sub: '1234567890', name: 'John Doe', iat: 1516239022 })}.c2lnbmF0dXJlX3Rlc3Q`;
const plainHits = hitsToFindings([{ RuleID: 'jwt', Secret: plainJwt }], false);
check('demotes a roleless JWT to low confidence', plainHits.some((f) => f.severity === 'low' && f.verification?.status === 'unverified'));
check('roleless JWT is still surfaced (not dropped)', plainHits.length === 1);

// NOTE: every key-shaped fixture below is assembled at runtime (split string
// fragments / template parts) so the full, contiguous literal never appears in
// this source file. That keeps gitleaks from matching our OWN test data when the
// scanner is pointed at its own repo — the very false positive this block guards.

// Repo-history hits are `secret_committed` (talks about commits), not the
// browser-flavoured `secret_exposed`. A realistic, high-entropy provider-format
// key stays critical — only fake/example values are demoted (tested below).
const realRepoSecret = `sk_live_${'R9kZqW7mNp3vXb'}${'2TfGcL8dHj'}`;
const repoHits = hitsToFindings([{ RuleID: 'stripe-access-token', Secret: realRepoSecret, File: 'src/pay.ts', Commit: 'deadbeef00cafe' }], true);
check('repo-history secret is typed secret_committed', repoHits.some((f) => f.type === 'secret_committed'));
check('a real provider-format repo secret stays critical', repoHits.some((f) => f.severity === 'critical'));
check('secret_committed carries file + commit params', repoHits.some((f) => f.params?.file === 'src/pay.ts' && f.params?.commit === 'deadbeef00'));
check('repo-history secret is masked (no raw key)', !repoHits.some((f) => new RegExp(realRepoSecret).test(f.summary + (f.evidence ?? ''))));

// Placeholder / example / test-fixture secrets: gitleaks' provider rules match on
// FORMAT, so they fire on fake keys too — doc examples (AWS's AKIA…EXAMPLE), our
// own detector fixtures, hand-typed sequential values. These must NOT be a FIX-NOW
// critical: demote to a low-confidence, unverified finding (surfaced, never screamed).
const seqPlaceholderKey = `sk_live_${'abcdef0123456789'}`;
const seqPlaceholder = hitsToFindings([{ RuleID: 'stripe-access-token', Secret: seqPlaceholderKey, File: 'src/test-detectors.ts', Commit: 'cfae1b27aa' }], true);
check('demotes a sequential placeholder key to low (kills the test-fixture false alarm)', seqPlaceholder.some((f) => f.severity === 'low' && f.verification?.status === 'unverified'));
check('placeholder key is still surfaced (not dropped)', seqPlaceholder.length === 1);
const awsExampleKey = `AKIA${'IOSFODNN7EXAMPLE'}`;
const awsExample = hitsToFindings([{ RuleID: 'aws-access-token', Secret: awsExampleKey, File: 'README.md', Commit: 'beadfeed00cafe' }], true);
check("demotes AWS's AKIA…EXAMPLE doc key to low", awsExample.some((f) => f.severity === 'low' && f.verification?.status === 'unverified'));

// Loose-script hits (no location) stay `secret_exposed` (shipped in page JS).
const urlHits = hitsToFindings([{ RuleID: 'stripe-access-token', Secret: realRepoSecret }], false);
check('loose-script secret stays secret_exposed', urlHits.some((f) => f.type === 'secret_exposed') && !urlHits.some((f) => f.params?.commit));

if (failures > 0) {
  console.error(`\n${failures} detector test(s) failed.`);
  process.exit(1);
}
console.log('\nAll detector tests passed.');
