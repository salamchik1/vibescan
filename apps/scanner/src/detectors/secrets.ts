import type { Finding } from '@vibescan/findings';
import type { CollectResult } from '../collector';
import { maskSecret } from '../util/mask';
import { extractJwts, jwtRole } from '../util/jwt';
import { shannonEntropy } from '../util/entropy';
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

  // AI providers (the core audience for vibe-coded apps)
  { provider: 'Anthropic API key', re: /\bsk-ant-(?:api|admin)[A-Za-z0-9-]{2,}-[A-Za-z0-9_-]{20,}\b/g, severity: 'critical' },
  { provider: 'OpenAI API key', re: /\bsk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b/g, severity: 'critical' },
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

  // 1) Pattern-based provider rules.
  for (const rule of RULES) {
    for (const m of text.matchAll(rule.re)) {
      const raw = m[0];
      // Skip a raw value already claimed by an earlier, more specific rule.
      if (matchedRaws.includes(raw)) continue;
      matchedRaws.push(raw);
      const masked = rule.provider.startsWith('Private key') ? '(private key block)' : maskSecret(raw);
      const key = dedupeKey(rule.provider, masked);
      if (seen.has(key)) continue;
      seen.add(key);
      const finding: Finding = {
        type: 'secret_exposed',
        severity: rule.severity,
        category: 'secrets',
        summary: `${rule.provider} (${masked})`,
        evidence: masked,
        params: { provider: rule.provider },
      };
      findings.push(finding);
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
    if (shannonEntropy(raw) < ENTROPY_THRESHOLD) continue;
    // Require a nearby secret-ish keyword: this is what separates a real exposed
    // credential from random build/asset blobs on large third-party sites.
    if (m.index === undefined || !hasSecretContext(text, m.index)) continue;
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

  return findings;
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
 */
function applyVerification(finding: Finding, result: LivenessResult): void {
  finding.verification = {
    status: result.status,
    checkedEndpoint: result.endpoint || undefined,
    detail: result.detail,
    checkedAt: new Date().toISOString(),
  };
  if (result.status === 'active') {
    finding.summary = `${finding.summary} — ✅ confirmed live`;
  } else if (result.status === 'inactive') {
    finding.severity = 'low';
    finding.summary = `${finding.summary} — ⚪ revoked (no longer works)`;
  }
}
