import type { Finding } from '@vibescan/findings';
import type { CollectResult } from '../collector';
import { maskSecret } from '../util/mask';
import { extractJwts, jwtRole } from '../util/jwt';
import { shannonEntropy } from '../util/entropy';
import { hasPublicAnalyticsContext, PUBLIC_ANALYTICS_WINDOW } from '../util/publicKeys';
import { isVerifiable, verifySecret, type LivenessResult, type Probe } from '../verify/liveness';

interface SecretRule {
  provider: string;
  re: RegExp;
  severity: Finding['severity'];
}

// High-signal patterns only — every match should be a real, dangerous secret.
// Publishable keys (pk_live_, anon JWTs) are intentionally NOT here: they are meant to be public.
// Order matters: more specific rules come before broader ones (e.g. Anthropic before the generic sk- key).
const RULES: SecretRule[] = [
  // Payments / billing
  { provider: 'Stripe live secret key', re: /\b(sk|rk)_live_[0-9a-zA-Z]{16,}\b/g, severity: 'critical' },
  { provider: 'Stripe test secret key', re: /\b(sk|rk)_test_[0-9a-zA-Z]{16,}\b/g, severity: 'low' },
  { provider: 'Stripe webhook signing secret', re: /\bwhsec_[A-Za-z0-9]{32,}\b/g, severity: 'high' },

  // AI / LLM providers (the core audience for vibe-coded apps) — every one spends real API credits.
  { provider: 'Anthropic API key', re: /\bsk-ant-(?:api|admin)[A-Za-z0-9-]{2,}-[A-Za-z0-9_-]{20,}\b/g, severity: 'critical' },
  // OpenRouter keys start `sk-or-v1-`; it MUST precede the broad OpenAI `sk-` rule below so it isn't mislabeled as OpenAI.
  { provider: 'OpenRouter API key', re: /\bsk-or-v1-[a-f0-9]{64}\b/g, severity: 'critical' },
  { provider: 'OpenAI API key', re: /\bsk-(?!ant-|or-v1-)(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b/g, severity: 'critical' },
  { provider: 'Groq API key', re: /\bgsk_[A-Za-z0-9]{52}\b/g, severity: 'critical' },
  { provider: 'xAI (Grok) API key', re: /\bxai-[A-Za-z0-9]{80}\b/g, severity: 'critical' },
  { provider: 'Replicate API token', re: /\br8_[A-Za-z0-9]{37}\b/g, severity: 'critical' },
  { provider: 'Perplexity API key', re: /\bpplx-[A-Za-z0-9]{48}\b/g, severity: 'high' },
  { provider: 'Fireworks AI API key', re: /\bfw_[A-Za-z0-9]{24,}\b/g, severity: 'high' },
  { provider: 'Hugging Face token', re: /\bhf_[A-Za-z0-9]{30,}\b/g, severity: 'high' },

  // Cloud / infra
  { provider: 'AWS access key id', re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g, severity: 'critical' },
  { provider: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g, severity: 'high' },
  { provider: 'Google OAuth client secret', re: /\bGOCSPX-[A-Za-z0-9_-]{20,}\b/g, severity: 'high' },
  { provider: 'DigitalOcean token', re: /\bdo[oprt]_v1_[a-f0-9]{64}\b/g, severity: 'critical' },
  { provider: 'Firebase Cloud Messaging server key', re: /\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,}\b/g, severity: 'critical' },

  // Source control / package registries
  { provider: 'GitHub token', re: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b/g, severity: 'critical' },
  { provider: 'GitHub fine-grained token', re: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/g, severity: 'critical' },
  { provider: 'GitLab personal access token', re: /\bglpat-[A-Za-z0-9_-]{20,}\b/g, severity: 'high' },
  { provider: 'npm access token', re: /\bnpm_[A-Za-z0-9]{36}\b/g, severity: 'high' },
  { provider: 'PyPI upload token', re: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b/g, severity: 'critical' },

  // Messaging / email
  { provider: 'SendGrid API key', re: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g, severity: 'critical' },
  { provider: 'Mailgun API key', re: /\bkey-[0-9a-f]{32}\b/g, severity: 'high' },
  { provider: 'Slack token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, severity: 'high' },
  { provider: 'Slack webhook URL', re: /\bhttps:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]+\/B[A-Za-z0-9_]+\/[A-Za-z0-9_]+\b/g, severity: 'medium' },
  { provider: 'Discord bot token', re: /\b[MNO][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}\b/g, severity: 'medium' },
  { provider: 'Telegram bot token', re: /\b\d{8,10}:AA[A-Za-z0-9_-]{32,}\b/g, severity: 'high' },
  { provider: 'Twilio API key', re: /\bSK[0-9a-fA-F]{32}\b/g, severity: 'high' },

  // SaaS / product
  { provider: 'Shopify access token', re: /\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b/g, severity: 'critical' },
  { provider: 'Square access token', re: /\bsq0(?:atp|csp)-[A-Za-z0-9_-]{22,}\b/g, severity: 'high' },
  { provider: 'Notion integration token', re: /\b(?:secret_|ntn_)[A-Za-z0-9]{40,}\b/g, severity: 'high' },
  { provider: 'Linear API key', re: /\blin_api_[A-Za-z0-9]{40,}\b/g, severity: 'high' },
  { provider: 'Doppler token', re: /\bdp\.(?:pt|st|ct|sa)\.[A-Za-z0-9]{40,}\b/g, severity: 'high' },
  { provider: 'Sentry auth token', re: /\bsntrys_[A-Za-z0-9_=]{40,}\b/g, severity: 'high' },
  { provider: 'Mapbox secret token', re: /\bsk\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}\b/g, severity: 'high' },

  // Email / infra / data platforms
  { provider: 'Resend API key', re: /\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{20,}\b/g, severity: 'high' },
  { provider: 'Mailchimp API key', re: /\b[0-9a-f]{32}-us\d{1,2}\b/g, severity: 'high' },
  { provider: 'Render API key', re: /\brnd_[A-Za-z0-9]{14,}\b/g, severity: 'critical' },
  { provider: 'New Relic user key', re: /\bNRAK-[A-Z0-9]{27}\b/g, severity: 'high' },
  { provider: 'Databricks token', re: /\bdapi[a-f0-9]{32}(?:-\d)?\b/g, severity: 'critical' },
  { provider: 'Pinecone API key', re: /\bpcsk_[A-Za-z0-9_]{40,}\b/g, severity: 'high' },
  { provider: 'Airtable personal access token', re: /\bpat[A-Za-z0-9]{14}\.[A-Za-z0-9]{64}\b/g, severity: 'high' },
  { provider: 'Figma access token', re: /\bfigd_[A-Za-z0-9_-]{40,}\b/g, severity: 'medium' },
  { provider: 'Atlassian API token', re: /\bATATT3[A-Za-z0-9_=.\-]{50,}\b/g, severity: 'high' },
  { provider: 'Postman API key', re: /\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b/g, severity: 'high' },

  // Keys / crypto material
  { provider: 'Private key', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g, severity: 'critical' },
];

// Database / message-broker connection strings carrying `user:pass@host` — a direct line into your data.
const CONNECTION_RE =
  /\b(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?|mssql|mariadb|clickhouse|cockroachdb):\/\/([^\s:@/'"`]+):([^\s:@/'"`]+)@([^\s/'"`:]+)/gi;

const ENGINE_LABELS: Record<string, string> = {
  postgres: 'PostgreSQL',
  postgresql: 'PostgreSQL',
  mysql: 'MySQL',
  mariadb: 'MariaDB',
  mongodb: 'MongoDB',
  'mongodb+srv': 'MongoDB',
  redis: 'Redis',
  rediss: 'Redis',
  amqp: 'RabbitMQ/AMQP',
  amqps: 'RabbitMQ/AMQP',
  mssql: 'SQL Server',
  clickhouse: 'ClickHouse',
  cockroachdb: 'CockroachDB',
};

// Entropy scan: long random-looking tokens with no obvious provider prefix.
const TOKEN_RE = /\b[A-Za-z0-9_\-+/]{32,128}\b/g;
const ENTROPY_THRESHOLD = 4.2; // bits/char
const MAX_ENTROPY_FINDINGS = 5;
// How far before a token we look for a secret-ish keyword.
const CONTEXT_WINDOW = 48;
// A real exposed credential almost always sits next to one of these words
// (`apiKey: "..."`, `Authorization: "Bearer ..."`, `const token = "..."`).
// Random base64/build-hash blobs in third-party bundles do not — so requiring
// this context kills the bulk of false positives on large sites.
const CONTEXT_KEYWORD_RE =
  /(api[_-]?key|secret|token|password|passwd|pwd|auth|bearer|credential|private[_-]?key|access[_-]?key|client[_-]?secret|x-api)/i;

function dedupeKey(provider: string, masked: string): string {
  return `${provider}::${masked}`;
}

/** Filters out common high-entropy strings that are not secrets (hashes, UUIDs, asset ids). */
function looksLikeNonSecret(raw: string): boolean {
  // Pure hex of a hash length (md5/sha1/sha256) — asset fingerprints, ETags, content hashes.
  if (/^[0-9a-f]+$/i.test(raw) && [32, 40, 56, 64, 96, 128].includes(raw.length)) return true;
  // UUID.
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(raw)) return true;
  // All letters or all digits — words / ids, not keys.
  if (/^[A-Za-z]+$/.test(raw) || /^[0-9]+$/.test(raw)) return true;
  // Needs a mix of letters and digits to be key-like.
  if (!(/[A-Za-z]/.test(raw) && /[0-9]/.test(raw))) return true;
  // Base64 blobs containing '/' or '+' are almost always encoded binary on big
  // sites (inline assets, sourcemap chunks, ad/tracking payloads), not keys.
  if (/[/+]/.test(raw)) return true;
  return false;
}

/**
 * True when a secret-ish keyword (key/token/secret/auth/...) appears just before
 * `index` in `text`. Generic high-entropy tokens are only worth reporting in this
 * context; without it they are overwhelmingly build hashes and asset ids.
 */
function hasSecretContext(text: string, index: number): boolean {
  const start = Math.max(0, index - CONTEXT_WINDOW);
  return CONTEXT_KEYWORD_RE.test(text.slice(start, index));
}

// Obviously-fake filler inside the captured token itself (xxxx, ****, ••, YOUR_API_KEY…).
// Deliberately narrow: only words that NEVER occur inside a genuine credential. We do NOT
// include "example"/"dummy"/"sample" here — on a live-JS scan we keep format-valid keys
// even when they carry such a substring (e.g. AWS's own AKIA…EXAMPLE), and the broader
// example/sequential drop already lives in the repo-history path (gitleaks looksLikePlaceholder).
const PLACEHOLDER_TOKEN_RE =
  /x{4,}|\*{3,}|•{2,}|your[-_]?(?:api[-_]?)?(?:key|token|secret)|placeholder|redacted|changeme|replace[-_]?me/i;

/**
 * True when a match is really a documentation/marketing placeholder, not a live secret:
 * a truncated example key shown in a curl/X-API-Key snippet ("zf_live_af9e..."), or a
 * token that literally spells out a filler word. Regex char-classes stop at the ".", so
 * the captured token never includes the trailing ellipsis — we check it against the text
 * immediately after the match, not the token. A real key is never written `"...secret..."`
 * in source, so this can't hide an actual leak.
 */
function isPlaceholderMatch(text: string, raw: string, index: number): boolean {
  const after = text.slice(index + raw.length, index + raw.length + 3);
  if (after.startsWith('...') || after.startsWith('…')) return true;
  return PLACEHOLDER_TOKEN_RE.test(raw);
}

// --- Google API key classification ------------------------------------------
// A Google "AIza…" key is NOT automatically a leak. Google publishes these for
// the browser (Firebase web config, Maps JavaScript API, Sign-In / GSI): they are
// MEANT to ship to the client and are safe as long as the key is restricted
// (HTTP referrers + allowed APIs) in Cloud Console. The only dangerous case is an
// unrestricted key — which a regex cannot see. So when the key clearly sits in one
// of these publishable contexts we treat it as expected and do not report it; an
// unidentified one is surfaced only at `low` (we can't prove it's unrestricted).
const GOOGLE_PUBLISHABLE_CONTEXT_RE =
  /(firebase|firebaseapp\.com|firebaseio\.com|firebasedatabase\.app|authdomain|messagingsenderid|measurementid|storagebucket|initializeapp|maps\.googleapis\.com|google\.maps|maps\/api\/js|libraries=|apis\.google\.com|accounts\.google\.com\/gsi|gsi\/client)/i;
const GOOGLE_CONTEXT_WINDOW = 240;

function classifyGoogleKey(text: string, index: number): 'publishable' | 'unknown' {
  const start = Math.max(0, index - GOOGLE_CONTEXT_WINDOW);
  const end = Math.min(text.length, index + GOOGLE_CONTEXT_WINDOW);
  return GOOGLE_PUBLISHABLE_CONTEXT_RE.test(text.slice(start, end)) ? 'publishable' : 'unknown';
}

export interface DetectSecretsOptions {
  /** When true, make a read-only liveness call per supported provider to confirm the key still works. */
  verify?: boolean;
  /** Injectable HTTP probe (tests pass a mock; production uses the real network). */
  probe?: Probe;
}

export async function detectSecrets(
  collected: CollectResult,
  opts: DetectSecretsOptions = {}
): Promise<Finding[]> {
  const text = collected.jsCombined;
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const matchedRaws: string[] = [];
  // Findings whose provider we can confirm live, paired with the raw key (kept local, never serialized).
  const verifiable: Array<{ finding: Finding; provider: string; secret: string }> = [];
  // Google keys get a deferred keep/drop decision (see the filter before return).
  const googleFindings = new Set<Finding>();
  const publishableGoogle = new Set<Finding>();

  // 1) Pattern-based provider rules.
  for (const rule of RULES) {
    for (const m of text.matchAll(rule.re)) {
      const raw = m[0];
      // Skip a raw value already claimed by an earlier, more specific rule.
      if (matchedRaws.includes(raw)) continue;
      // Skip truncated/templated example keys from docs (e.g. `X-API-Key: zf_live_af9e...`).
      if (isPlaceholderMatch(text, raw, m.index ?? 0)) continue;
      matchedRaws.push(raw);

      let severity = rule.severity;
      let note = '';
      // Google keys are publishable by design for browser SDKs (see classifyGoogleKey).
      // We record them but defer the final keep/drop decision to the end: by context
      // when verify is off, and by the live restriction probe when verify is on.
      const isGoogleKey = rule.provider === 'Google API key';
      let googlePublishable = false;
      if (isGoogleKey) {
        severity = 'low';
        if (classifyGoogleKey(text, m.index ?? 0) === 'publishable') {
          googlePublishable = true;
        } else {
          note = ' — only a risk if it has no API/referrer restrictions in Google Cloud Console';
        }
      }

      const masked = rule.provider.startsWith('Private key') ? '(private key block)' : maskSecret(raw);
      const key = dedupeKey(rule.provider, masked);
      if (seen.has(key)) continue;
      seen.add(key);
      const finding: Finding = {
        type: 'secret_exposed',
        severity,
        category: 'secrets',
        summary: `${rule.provider} (${masked})${note}`,
        evidence: masked,
        params: { provider: rule.provider },
      };
      findings.push(finding);
      if (isGoogleKey) {
        googleFindings.add(finding);
        if (googlePublishable) publishableGoogle.add(finding);
      }
      if (isVerifiable(rule.provider)) verifiable.push({ finding, provider: rule.provider, secret: raw });
    }
  }

  // 2) Database / broker connection strings with embedded credentials.
  for (const m of text.matchAll(CONNECTION_RE)) {
    const engineRaw = (m[1] ?? '').toLowerCase();
    const host = m[4] ?? '';
    const engine = ENGINE_LABELS[engineRaw] ?? engineRaw;
    const safeHost = host.length > 40 ? `${host.slice(0, 40)}…` : host;
    const masked = `${engineRaw}://****:****@${safeHost}`;
    matchedRaws.push(m[0]);
    const key = dedupeKey('Database connection string', masked);
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push({
      type: 'database_url_exposed',
      severity: 'critical',
      category: 'secrets',
      summary: `${engine} connection string with password (${masked})`,
      evidence: masked,
      params: { engine, evidence: masked },
    });
  }

  // 3) Supabase service_role JWT — an admin key that must never reach the browser.
  for (const jwt of extractJwts(text)) {
    if (jwtRole(jwt) === 'service_role') {
      const masked = maskSecret(jwt.raw);
      const key = dedupeKey('Supabase service_role key', masked);
      if (seen.has(key)) continue;
      seen.add(key);
      matchedRaws.push(jwt.raw);
      findings.push({
        type: 'secret_exposed',
        severity: 'critical',
        category: 'secrets',
        summary: `Supabase service_role key (${masked}) — full admin access`,
        evidence: masked,
        params: { provider: 'Supabase service_role' },
      });
    }
  }

  // 4) Generic high-entropy tokens (bounded, lower confidence).
  let entropyCount = 0;
  for (const m of text.matchAll(TOKEN_RE)) {
    if (entropyCount >= MAX_ENTROPY_FINDINGS) break;
    const raw = m[0];
    // Skip anything already reported by a specific rule (avoid double-counting).
    if (matchedRaws.some((mr) => mr.includes(raw) || raw.includes(mr))) continue;
    if (looksLikeNonSecret(raw)) continue;
    if (m.index !== undefined && isPlaceholderMatch(text, raw, m.index)) continue;
    if (shannonEntropy(raw) < ENTROPY_THRESHOLD) continue;
    // Require a nearby secret-ish keyword: this is what separates a real exposed
    // credential from random build/asset blobs on large third-party sites.
    if (m.index === undefined || !hasSecretContext(text, m.index)) continue;
    // Drop public-by-design analytics keys (Segment/Ahrefs/GA client keys): when
    // the token sits inside a known analytics loader context it's meant to ship to
    // the browser, exactly like a Supabase anon key, so it isn't a leak. This only
    // touches the low-confidence entropy fallback — every precise provider rule
    // already ran in step 1 — so a real key is never silenced here.
    const ctxStart = Math.max(0, m.index - PUBLIC_ANALYTICS_WINDOW);
    const ctxEnd = Math.min(text.length, m.index + raw.length + PUBLIC_ANALYTICS_WINDOW);
    if (hasPublicAnalyticsContext(text.slice(ctxStart, ctxEnd))) continue;
    const masked = maskSecret(raw);
    const key = dedupeKey('High-entropy token', masked);
    if (seen.has(key)) continue;
    seen.add(key);
    entropyCount += 1;
    findings.push({
      type: 'secret_exposed',
      severity: 'low',
      category: 'secrets',
      summary: `Possible secret / high-entropy token (${masked})`,
      evidence: masked,
      params: { provider: 'an unidentified credential' },
    });
  }

  // 5) Liveness verification — confirm which detected keys actually still work.
  if (opts.verify && verifiable.length > 0) {
    await runVerifications(verifiable, opts.probe);
  }

  // Decide which Google keys actually reach the report:
  //  - verified unrestricted (status 'active')      → keep, now high (a real leak)
  //  - verified restricted / revoked ('inactive')   → drop (safe)
  //  - not verified                                 → drop publishable-context keys
  //                                                    (safe by design), keep the rest at low
  return findings.filter((f) => {
    if (!googleFindings.has(f)) return true;
    const status = f.verification?.status;
    if (status === 'active') return true;
    if (status === 'inactive') return false;
    return !publishableGoogle.has(f);
  });
}

const VERIFY_CONCURRENCY = 5;

/** Probe each verifiable secret (bounded parallelism) and fold the result back into its finding. */
async function runVerifications(
  items: Array<{ finding: Finding; provider: string; secret: string }>,
  probe?: Probe
): Promise<void> {
  let next = 0;
  async function worker(): Promise<void> {
    while (next < items.length) {
      const item = items[next++];
      if (!item) return;
      const result = await verifySecret(item.provider, item.secret, probe);
      if (result) applyVerification(item.finding, result);
    }
  }
  const workers = Array.from({ length: Math.min(VERIFY_CONCURRENCY, items.length) }, worker);
  await Promise.all(workers);
}

/**
 * Fold a liveness result into the finding:
 *  - active   → mark it confirmed (keep the pattern severity; a live critical key stays critical).
 *  - inactive → the key is dead, so drop it to `low` to cut false-alarm noise from revoked keys.
 *  - unverified → annotate only; severity unchanged (we still assume it's live).
 *
 * A result may also carry a `severity` override (e.g. Google escalates to high once
 * proven unrestricted) and a `summarySuffix` to replace the default annotation.
 */
function applyVerification(finding: Finding, result: LivenessResult): void {
  finding.verification = {
    status: result.status,
    checkedEndpoint: result.endpoint || undefined,
    detail: result.detail,
    checkedAt: new Date().toISOString(),
  };
  if (result.severity) finding.severity = result.severity;
  if (result.summarySuffix !== undefined) {
    finding.summary = `${finding.summary}${result.summarySuffix}`;
  } else if (result.status === 'active') {
    finding.summary = `${finding.summary} — ✅ confirmed live`;
  } else if (result.status === 'inactive') {
    if (!result.severity) finding.severity = 'low';
    finding.summary = `${finding.summary} — ⚪ revoked (no longer works)`;
  }
}
