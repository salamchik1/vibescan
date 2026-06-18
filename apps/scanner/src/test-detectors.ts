import { detectSecrets } from './detectors/secrets';
import { detectOwasp } from './detectors/owasp';
import { detectEmail, type TxtResolver } from './detectors/email';
import { detectTls, type TlsInspection, type HttpRedirectResult } from './detectors/tls';
import { detectIdor, harvestEndpoints, type Fetcher } from './detectors/idor';
import { detectJwt } from './detectors/jwt';
import { hitsToFindings, type GitleaksHit } from './detectors/gitleaks';
import type { CollectResult } from './collector';
import type { SafeFetchResult } from './util/fetch';
import type { Probe, ProbeResponse } from './verify/liveness';
import { createHmac } from 'node:crypto';
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

// --- Extended provider coverage (modern AI / vibe stack) --------------------
// Format-valid (but fake) keys, assembled from fragments so the scanner doesn't
// flag this very fixture when pointed at its own repo.
const hex = '0123456789abcdef';
const alnum = 'a1B2c3D4e5';
const newKeysJs = [
  `const groq = "gsk_${alnum.repeat(6).slice(0, 52)}";`,
  `const openrouter = "sk-or-v1-${hex.repeat(4)}";`,
  `const xai = "xai-${alnum.repeat(8)}";`,
  `const replicate = "r8_${alnum.repeat(4).slice(0, 37)}";`,
  `const resend = "re_${alnum}1_${alnum.repeat(3).slice(0, 24)}";`,
  `const render = "rnd_${alnum.repeat(2)}";`,
  `const mailchimp = "${hex.repeat(2)}-us21";`,
  `const airtable = "pat${alnum.slice(0, 4) + alnum}.${hex.repeat(4)}";`,
  `const figma = "figd_${alnum.repeat(4)}";`,
  `const newrelic = "NRAK-${'A1B2C3D4E5'.repeat(3).slice(0, 27)}";`,
  `const postman = "PMAK-${hex.repeat(2).slice(0, 24)}-${hex.repeat(3).slice(0, 34)}";`,
].join('\n');
const newKeys = await detectSecrets({ ...collected, jsCombined: newKeysJs });
check('finds Groq API key (critical)', has(newKeys, (f) => /Groq/.test(f.summary) && f.severity === 'critical'));
check('finds OpenRouter API key (critical)', has(newKeys, (f) => /OpenRouter/.test(f.summary) && f.severity === 'critical'));
check('OpenRouter key is NOT mislabeled as OpenAI', !newKeys.some((f) => /OpenAI/.test(f.summary) && /or-v1|^sk-or/.test(f.evidence ?? '')));
check('finds xAI (Grok) API key', has(newKeys, (f) => /xAI/.test(f.summary)));
check('finds Replicate API token', has(newKeys, (f) => /Replicate/.test(f.summary)));
check('finds Resend API key', has(newKeys, (f) => /Resend/.test(f.summary)));
check('finds Render API key (critical)', has(newKeys, (f) => /Render/.test(f.summary) && f.severity === 'critical'));
check('finds Mailchimp API key', has(newKeys, (f) => /Mailchimp/.test(f.summary)));
check('finds Airtable personal access token', has(newKeys, (f) => /Airtable/.test(f.summary)));
check('finds Figma access token', has(newKeys, (f) => /Figma/.test(f.summary)));
check('finds New Relic user key', has(newKeys, (f) => /New Relic/.test(f.summary)));
check('finds Postman API key', has(newKeys, (f) => /Postman/.test(f.summary)));
check('all new-provider findings are masked (no raw gsk_/xai-/re_)', !newKeys.some((f) => /gsk_[A-Za-z0-9]{20,}|xai-[A-Za-z0-9]{40,}/.test(f.summary + (f.evidence ?? ''))));

// A new-provider key verifies live through its read-only probe.
const newKeysLive = await detectSecrets({ ...collected, jsCombined: newKeysJs }, {
  verify: true,
  probe: async () => probeResponse(200, { ok: true }),
});
check('verifies a live Groq key (active) via its read-only endpoint', has(newKeysLive, (f) => /Groq/.test(f.summary) && f.verification?.status === 'active' && /api\.groq\.com/.test(f.verification?.checkedEndpoint ?? '')));
check('verifies a live Resend key (active)', has(newKeysLive, (f) => /Resend/.test(f.summary) && f.verification?.status === 'active'));

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
// The token is assembled from fragments (like the gitleaks block below) so the
// scanner doesn't match this very fixture when pointed at its own repo.
const ctxToken = 'aB3xK9mZ2pQ7w' + 'L5vR8tN4cF' + '6yH1jD0sGqW';
const ctxJs = `const apiKey = "${ctxToken}";`;
const ctx = await detectSecrets({ ...collected, jsCombined: ctxJs });
check('flags a high-entropy token that has secret context', has(ctx, (f) => /high-entropy/.test(f.summary) && f.severity === 'low'));

// --- Public-by-design analytics keys: dropped, not screamed -----------------
// A Segment/Ahrefs client key is MEANT to ship in the page (rate-limited on the
// vendor side, like a Supabase anon key). Even with a secret-ish keyword right
// before it, the entropy fallback must NOT report it once it sits in a known
// analytics loader context — that's the false alarm we're killing.
// Assembled from fragments (see the gitleaks note below) so this fixture isn't
// flagged as a generic-api-key hit when the scanner is pointed at its own repo.
const segmentToken = 'qZ7wL5vR8tN4c' + 'F6yH1jD0sG' + 'qWaB3xK9mZ2p';
const segmentJs = `<script src="https://cdn.segment.com/analytics.js"></script>\nconst apiKey = "${segmentToken}";\nanalytics.load(apiKey);`;
const segment = await detectSecrets({ ...collected, jsCombined: segmentJs });
check('drops a Segment/analytics client key in loader context', !has(segment, (f) => /high-entropy/.test(f.summary)));
// Sanity: the SAME token with no analytics marker is still surfaced (low), so the
// drop is the analytics context doing the work, not the token being unflaggable.
const segmentBare = await detectSecrets({ ...collected, jsCombined: `const apiKey = "${segmentToken}";` });
check('the same token without analytics context is still flagged', has(segmentBare, (f) => /high-entropy/.test(f.summary) && f.severity === 'low'));

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

// --- JWT weaknesses detector (offline, no network) --------------------------
// Every token is built at runtime (b64url fragments + a local HMAC) so no
// contiguous JWT literal lives in this file — the scanner won't flag its own
// fixtures when pointed at this repo.

/** Sign a JWT locally with HS256 over the given secret. */
function signHs256(header: unknown, payload: unknown, secret: string): string {
  const input = `${b64url(header)}.${b64url(payload)}`;
  return `${input}.${createHmac('sha256', secret).update(input).digest('base64url')}`;
}
const jwtCollected = { ...collected, jsCombined: '' };
const STRONG_SECRET = 'kQ9-Zr2_Wt7xN4cF6yH1jD0sGqW-aB3xK9mZ2pL5vR8tN'; // not in the dictionary

// alg:none — an unsigned token (header.payload. with an empty signature).
const noneToken = `${b64url({ alg: 'none', typ: 'JWT' })}.${b64url({ sub: '1', role: 'admin', name: 'attacker' })}.`;
const jwtNone = detectJwt({ ...jwtCollected, jsCombined: `const t = "${noneToken}";` });
check('flags an alg:none JWT as high', has(jwtNone, (f) => f.type === 'jwt_alg_none' && f.severity === 'high'));
check('alg:none finding masks the raw token', !jwtNone.some((f) => (f.summary + (f.evidence ?? '')).includes(noneToken)));

// Weak HS256 secret — signed with the dictionary word "secret".
const weakToken = signHs256({ alg: 'HS256', typ: 'JWT' }, { sub: '1', role: 'admin' }, 'secret');
const jwtWeak = detectJwt({ ...jwtCollected, jsCombined: `const t = "${weakToken}";` });
check('flags a weak HS256 secret as critical', has(jwtWeak, (f) => f.type === 'jwt_weak_secret' && f.severity === 'critical'));
check('weak-secret finding names the cracked secret', has(jwtWeak, (f) => f.type === 'jwt_weak_secret' && f.params?.secret === 'secret'));
check('weak-secret finding masks the raw token', !jwtWeak.some((f) => (f.summary + (f.evidence ?? '')).includes(weakToken)));

// A token signed with a strong, random secret must NOT crack.
const strongToken = signHs256({ alg: 'HS256', typ: 'JWT' }, { sub: '1', role: 'admin' }, STRONG_SECRET);
const jwtStrong = detectJwt({ ...jwtCollected, jsCombined: `const t = "${strongToken}";` });
check('does NOT flag a strong HS256 secret as weak', !has(jwtStrong, (f) => f.type === 'jwt_weak_secret'));

// An expired token (strong secret, so weak-secret doesn't pre-empt it).
const expiredToken = signHs256({ alg: 'HS256', typ: 'JWT' }, { sub: '1', exp: 1_516_239_022 }, STRONG_SECRET);
const jwtExpired = detectJwt({ ...jwtCollected, jsCombined: `const t = "${expiredToken}";` });
check('flags an expired hard-coded token as low', has(jwtExpired, (f) => f.type === 'jwt_expired' && f.severity === 'low'));

// A still-valid token signed with a strong secret produces nothing.
const validToken = signHs256({ alg: 'HS256', typ: 'JWT' }, { sub: '1', exp: Math.floor(Date.now() / 1000) + 86_400 }, STRONG_SECRET);
const jwtValid = detectJwt({ ...jwtCollected, jsCombined: `const t = "${validToken}";` });
check('does NOT flag a valid, strongly-signed token', jwtValid.length === 0);

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
// ships) is an obvious non-secret, so it's DROPPED — never shown. Only a real
// admin key (role:service_role) stays critical (checked above).
const plainJwt = `${b64url({ alg: 'HS256', typ: 'JWT' })}.${b64url({ sub: '1234567890', name: 'John Doe', iat: 1516239022 })}.c2lnbmF0dXJlX3Rlc3Q`;
const plainHits = hitsToFindings([{ RuleID: 'jwt', Secret: plainJwt }], false);
check('drops a roleless demo/session JWT entirely', plainHits.length === 0);

// NOTE: every key-shaped fixture below is assembled at runtime (split string
// fragments / template parts) so the full, contiguous literal never appears in
// this source file. That keeps gitleaks from matching our OWN test data when the
// scanner is pointed at its own repo — the very false positive this block guards.

// Repo-history hits are `secret_committed` (talks about commits), not the
// browser-flavoured `secret_exposed`. A realistic, high-entropy provider-format
// key stays critical — only obvious fake/example values are dropped (tested below).
const realRepoSecret = `sk_live_${'R9kZqW7mNp3vXb'}${'2TfGcL8dHj'}`;
const repoHits = hitsToFindings([{ RuleID: 'stripe-access-token', Secret: realRepoSecret, File: 'src/pay.ts', Commit: 'deadbeef00cafe' }], true);
check('repo-history secret is typed secret_committed', repoHits.some((f) => f.type === 'secret_committed'));
check('a real provider-format repo secret stays critical', repoHits.some((f) => f.severity === 'critical'));
check('secret_committed carries file + commit params', repoHits.some((f) => f.params?.file === 'src/pay.ts' && f.params?.commit === 'deadbeef00'));
check('repo-history secret is masked (no raw key)', !repoHits.some((f) => new RegExp(realRepoSecret).test(f.summary + (f.evidence ?? ''))));

// Placeholder / example / test-fixture secrets: gitleaks' provider rules match on
// FORMAT, so they fire on fake keys too — doc examples (AWS's AKIA…EXAMPLE), our
// own detector fixtures, hand-typed sequential values. These are obvious fakes and
// are DROPPED entirely (a real high-entropy key never carries an example marker or
// a sequential/repeated run, so this can't hide a genuine leak).
const seqPlaceholderKey = `sk_live_${'abcdef0123456789'}`;
const seqPlaceholder = hitsToFindings([{ RuleID: 'stripe-access-token', Secret: seqPlaceholderKey, File: 'src/test-detectors.ts', Commit: 'cfae1b27aa' }], true);
check('drops a sequential placeholder key (kills the test-fixture false alarm)', seqPlaceholder.length === 0);
const awsExampleKey = `AKIA${'IOSFODNN7EXAMPLE'}`;
const awsExample = hitsToFindings([{ RuleID: 'aws-access-token', Secret: awsExampleKey, File: 'README.md', Commit: 'beadfeed00cafe' }], true);
check("drops AWS's AKIA…EXAMPLE doc key", awsExample.length === 0);
// SAFETY GUARD: dropping is by VALUE, never by file path — a real high-entropy key
// committed to a test/example file is still reported critical, so we don't hide a
// genuine leak just because of where it lives.
const realInTestFile = hitsToFindings([{ RuleID: 'stripe-access-token', Secret: realRepoSecret, File: 'src/auth.test.ts', Commit: 'abc1234567' }], true);
check('keeps a real key even in a test-file path', realInTestFile.some((f) => f.severity === 'critical'));

// Loose-script hits (no location) stay `secret_exposed` (shipped in page JS).
const urlHits = hitsToFindings([{ RuleID: 'stripe-access-token', Secret: realRepoSecret }], false);
check('loose-script secret stays secret_exposed', urlHits.some((f) => f.type === 'secret_exposed') && !urlHits.some((f) => f.params?.commit));

// --- Public-by-design analytics / tag keys (gitleaks) -----------------------
// Google tag/measurement ids are pure public identifiers (no secret material),
// so they are dropped by value whatever rule fired.
const gaId = `G-${'AB12CD34EF'}`;
const gaHit = hitsToFindings([{ RuleID: 'generic-api-key', Secret: gaId, Match: `gtag('config','${gaId}')`, File: 'index.html' }], false);
check('drops a Google Analytics measurement id (public identifier)', gaHit.length === 0);
const gtmHit = hitsToFindings([{ RuleID: 'generic-api-key', Secret: `GTM-${'WXYZ123'}`, File: 'index.html' }], false);
check('drops a Google Tag Manager id', gtmHit.length === 0);

// A random-looking client key is dropped by its analytics loader context — but
// only for the low-confidence generic rule (see the AWS guard below).
const ahrefsKey = `${'aBcD1234'}${'EfGh5678'}${'IjKl90Mn'}`;
const ahrefsHit = hitsToFindings(
  [{ RuleID: 'generic-api-key', Secret: ahrefsKey, Match: `<script src="https://analytics.ahrefs.com/analytics.js" data-key="${ahrefsKey}">`, File: 'index.html' }],
  false
);
check('drops an Ahrefs analytics data-key (public by design)', ahrefsHit.length === 0);

// REGRESSION GUARD: a generic-api-key hit with NO analytics context is still
// surfaced (as a low-confidence finding) — we haven't blunted the rule itself.
const genericKey = `${'kV82nQ'}${'pW73mZ'}${'rX64bN'}${'tY55cM'}`;
const genericHit = hitsToFindings([{ RuleID: 'generic-api-key', Secret: genericKey, Match: `const apiKey = "${genericKey}"`, File: 'src/config.ts' }], false);
check('still surfaces a generic-api-key hit with no analytics context', genericHit.some((f) => f.severity === 'low'));

// SAFETY GUARD: a PRECISE provider hit (AWS) that merely sits next to an analytics
// snippet must NEVER be dropped — context-based dropping is generic-rule-only.
const awsRealKey = `AKIA${'J7Q2RW9XK4M6BN5P'}`;
const awsNearAnalytics = hitsToFindings(
  [{ RuleID: 'aws-access-token', Secret: awsRealKey, Match: `// after https://cdn.segment.com/analytics.js\nconst k="${awsRealKey}"`, File: 'src/aws.ts' }],
  false
);
check('keeps a real AWS key even next to an analytics snippet', awsNearAnalytics.some((f) => f.severity === 'critical'));

// --- Email auth detector (offline, mock DNS resolver) -----------------------
// SPF/DMARC live entirely in DNS TXT records, so an injectable resolver lets us
// exercise every branch without a live domain.

const emailBase: CollectResult = {
  ...collected,
  finalUrl: 'https://www.demo.test/path',
  origin: 'https://www.demo.test',
};

/** Build a TXT resolver from a map of hostname -> TXT records (each record one string). */
function txtResolver(records: Record<string, string[]>): TxtResolver {
  return async (hostname) => (records[hostname] ?? []).map((r) => [r]);
}

// No SPF and no DMARC at all -> both medium.
const wideOpen = await detectEmail(emailBase, { resolveTxt: txtResolver({}) });
check('flags a domain with no SPF (medium)', has(wideOpen, (f) => f.type === 'spf_missing' && f.severity === 'medium'));
check('flags a domain with no DMARC (medium)', has(wideOpen, (f) => f.type === 'dmarc_weak' && f.severity === 'medium'));
check('email detector strips www to the bare domain', has(wideOpen, (f) => /(^|\W)demo\.test\b/.test(f.summary) && !/www\./.test(f.summary)));

// Proper SPF (-all) + enforced DMARC (p=reject) -> no findings.
const locked = await detectEmail(emailBase, {
  resolveTxt: txtResolver({
    'demo.test': ['v=spf1 include:_spf.google.com -all'],
    '_dmarc.demo.test': ['v=DMARC1; p=reject; rua=mailto:dmarc@demo.test'],
  }),
});
check('does NOT flag a properly locked-down domain (SPF -all + DMARC reject)', locked.length === 0);

// Permissive SPF (+all) is as bad as none.
const plusAll = await detectEmail(emailBase, {
  resolveTxt: txtResolver({
    'demo.test': ['v=spf1 +all'],
    '_dmarc.demo.test': ['v=DMARC1; p=reject'],
  }),
});
check('flags a permissive SPF +all record (medium)', has(plusAll, (f) => f.type === 'spf_missing' && f.severity === 'medium'));
check('does not double-flag DMARC when DMARC is enforced', !has(plusAll, (f) => f.type === 'dmarc_weak'));

// DMARC present but monitor-only (p=none) -> low.
const pNone = await detectEmail(emailBase, {
  resolveTxt: txtResolver({
    'demo.test': ['v=spf1 -all'],
    '_dmarc.demo.test': ['v=DMARC1; p=none; rua=mailto:dmarc@demo.test'],
  }),
});
check('flags a monitor-only DMARC p=none as low', has(pNone, (f) => f.type === 'dmarc_weak' && f.severity === 'low'));
check('does not flag SPF when SPF ends in -all', !has(pNone, (f) => f.type === 'spf_missing'));

// Code-paste / non-web targets have no DNS domain -> detector stays silent.
const emailCode = await detectEmail(
  { ...collected, finalUrl: 'pasted-code', origin: '' },
  { resolveTxt: txtResolver({}) }
);
check('email detector skips non-web targets (pasted code)', emailCode.length === 0);

// --- TLS hygiene detector (offline, mock handshake + redirect probes) --------

const tlsBase: CollectResult = {
  ...collected,
  finalUrl: 'https://demo.test/',
  origin: 'https://demo.test',
};
const daysFromNow = (n: number): Date => new Date(Date.now() + n * 24 * 60 * 60 * 1000);
const okInspect = (over: Partial<TlsInspection> = {}) =>
  async (): Promise<TlsInspection> => ({ validTo: daysFromNow(90), legacyTlsAccepted: false, ...over });
const okRedirect = async (): Promise<HttpRedirectResult> => ({ redirectsToHttps: true });

// A healthy host: cert far from expiry, no legacy TLS, http redirects -> no findings.
const tlsHealthy = await detectTls(tlsBase, { inspectTls: okInspect(), checkHttpRedirect: okRedirect });
check('does NOT flag a healthy TLS setup', tlsHealthy.length === 0);

// Cert expiring within two weeks -> medium.
const tlsSoon = await detectTls(tlsBase, {
  inspectTls: okInspect({ validTo: daysFromNow(5) }),
  checkHttpRedirect: okRedirect,
});
check('flags a certificate expiring in <14 days (medium)', has(tlsSoon, (f) => f.type === 'tls_expiring' && f.severity === 'medium'));

// Cert already expired -> high.
const tlsExpired = await detectTls(tlsBase, {
  inspectTls: okInspect({ validTo: daysFromNow(-3) }),
  checkHttpRedirect: okRedirect,
});
check('flags an expired certificate as high', has(tlsExpired, (f) => f.type === 'tls_expiring' && f.severity === 'high'));

// Legacy TLS 1.0/1.1 accepted -> medium.
const tlsLegacy = await detectTls(tlsBase, {
  inspectTls: okInspect({ legacyTlsAccepted: true }),
  checkHttpRedirect: okRedirect,
});
check('flags a host that accepts legacy TLS 1.0/1.1 (medium)', has(tlsLegacy, (f) => f.type === 'tls_weak_version' && f.severity === 'medium'));

// http:// not redirected to https -> medium.
const tlsNoRedirect = await detectTls(tlsBase, {
  inspectTls: okInspect(),
  checkHttpRedirect: async () => ({ redirectsToHttps: false }),
});
check('flags a site that does not redirect http to https (medium)', has(tlsNoRedirect, (f) => f.type === 'no_https_redirect' && f.severity === 'medium'));

// An unreachable plain-HTTP probe (https-only host) must NOT be flagged.
const tlsHttpsOnly = await detectTls(tlsBase, { inspectTls: okInspect(), checkHttpRedirect: async () => null });
check('does NOT flag no-redirect when http is unreachable (null probe)', !has(tlsHttpsOnly, (f) => f.type === 'no_https_redirect'));

// A non-https origin skips the cert/version handshake but still checks the redirect.
const tlsPlain: CollectResult = { ...tlsBase, finalUrl: 'http://demo.test/', origin: 'http://demo.test' };
const tlsPlainFindings = await detectTls(tlsPlain, {
  inspectTls: async () => { throw new Error('handshake must not run on http origin'); },
  checkHttpRedirect: async () => ({ redirectsToHttps: false }),
});
check('skips the TLS handshake on a plain-http origin but still flags no redirect', has(tlsPlainFindings, (f) => f.type === 'no_https_redirect') && !has(tlsPlainFindings, (f) => f.type === 'tls_expiring' || f.type === 'tls_weak_version'));

if (failures > 0) {
  console.error(`\n${failures} detector test(s) failed.`);
  process.exit(1);
}
console.log('\nAll detector tests passed.');
