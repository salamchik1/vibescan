// Paste-mode secret scanner. A browser-only port of the scanner's secret
// detector (apps/scanner/src/detectors/secrets.ts): the same high-signal
// provider patterns, database connection strings and a bounded high-entropy
// fallback — but running entirely on the pasted text, with nothing sent away.

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface SecretHit {
  provider: string;
  severity: Severity;
  /** Masked value — the raw secret is never kept in the result. */
  masked: string;
  /** 1-based line number where the match starts. */
  line: number;
}

export interface ScanResult {
  hits: SecretHit[];
  lineCount: number;
  /** Severity → count, for the summary header. */
  counts: Record<Severity, number>;
}

interface SecretRule {
  provider: string;
  re: RegExp;
  severity: Severity;
}

// High-signal patterns only — every match should be a real, dangerous secret.
// Publishable keys (pk_live_, anon JWTs) are intentionally NOT here: they are meant to be public.
// Order matters: more specific rules come before broader ones.
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

// Database / message-broker connection strings carrying `user:pass@host`.
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

const TOKEN_RE = /\b[A-Za-z0-9_\-+/]{32,128}\b/g;
const ENTROPY_THRESHOLD = 4.0; // bits/char
const MAX_ENTROPY_FINDINGS = 5;

/** Shannon entropy (bits per char) — a rough "how random is this" measure. */
function shannonEntropy(s: string): number {
  if (!s) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Mask a secret so we never display the raw value. Keeps a short tail. */
function mask(value: string, keepEnd = 4): string {
  const v = value.trim();
  if (v.length <= keepEnd) return '*'.repeat(Math.max(4, v.length));
  return `${'*'.repeat(4)}${v.slice(v.length - keepEnd)}`;
}

// A Google "AIza…" key is publishable by design for browser SDKs (Firebase web
// config, Maps JS, Sign-In). It is safe as long as it is restricted in Cloud
// Console; only an unrestricted key is a real leak — which a regex can't see. So
// when the key sits in one of those contexts we don't report it, and an
// unidentified one is downgraded to low. (Mirrors the URL scanner's secret detector.)
const GOOGLE_PUBLISHABLE_CONTEXT_RE =
  /(firebase|firebaseapp\.com|firebaseio\.com|firebasedatabase\.app|authdomain|messagingsenderid|measurementid|storagebucket|initializeapp|maps\.googleapis\.com|google\.maps|maps\/api\/js|libraries=|apis\.google\.com|accounts\.google\.com\/gsi|gsi\/client)/i;
const GOOGLE_CONTEXT_WINDOW = 240;

function classifyGoogleKey(text: string, index: number): 'publishable' | 'unknown' {
  const start = Math.max(0, index - GOOGLE_CONTEXT_WINDOW);
  const end = Math.min(text.length, index + GOOGLE_CONTEXT_WINDOW);
  return GOOGLE_PUBLISHABLE_CONTEXT_RE.test(text.slice(start, end)) ? 'publishable' : 'unknown';
}

// Obviously-fake filler inside the captured token itself (xxxx, ****, ••, YOUR_API_KEY…).
// Deliberately narrow: only words that NEVER occur inside a genuine credential — not
// "example"/"dummy"/"sample", which can be a substring of a format-valid key we still
// want to surface in pasted code.
const PLACEHOLDER_TOKEN_RE =
  /x{4,}|\*{3,}|•{2,}|your[-_]?(?:api[-_]?)?(?:key|token|secret)|placeholder|redacted|changeme|replace[-_]?me/i;

/**
 * True when a match is really a documentation placeholder, not a live secret: a truncated
 * example key from a curl/X-API-Key snippet ("zf_live_af9e..."), or a token that spells out
 * a filler word. Regex char-classes stop at the ".", so the captured token never includes the
 * trailing ellipsis — we check the text right after the match. A real key is never written
 * `"...secret..."` in source, so this can't hide an actual leak.
 */
function isPlaceholderMatch(text: string, raw: string, index: number): boolean {
  const after = text.slice(index + raw.length, index + raw.length + 3);
  if (after.startsWith('...') || after.startsWith('…')) return true;
  return PLACEHOLDER_TOKEN_RE.test(raw);
}

/** Filters out common high-entropy strings that are not secrets. */
function looksLikeNonSecret(raw: string): boolean {
  if (/^[0-9a-f]+$/i.test(raw) && [32, 40, 56, 64, 96, 128].includes(raw.length)) return true;
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(raw)) return true;
  if (/^[A-Za-z]+$/.test(raw) || /^[0-9]+$/.test(raw)) return true;
  if (!(/[A-Za-z]/.test(raw) && /[0-9]/.test(raw))) return true;
  return false;
}

/** Line number (1-based) of a character offset within the text. */
function lineAt(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text[i] === '\n') line++;
  }
  return line;
}

const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export function scanForSecrets(text: string): ScanResult {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  const lineCount = text ? text.split('\n').length : 0;
  if (!text.trim()) return { hits: [], lineCount, counts };

  const hits: SecretHit[] = [];
  const seen = new Set<string>();
  const matchedRaws: string[] = [];

  const add = (provider: string, severity: Severity, masked: string, index: number) => {
    const key = `${provider}::${masked}`;
    if (seen.has(key)) return;
    seen.add(key);
    counts[severity]++;
    hits.push({ provider, severity, masked, line: lineAt(text, index) });
  };

  // 1) Provider rules.
  for (const rule of RULES) {
    for (const m of text.matchAll(rule.re)) {
      const raw = m[0];
      if (matchedRaws.includes(raw)) continue;
      // Skip truncated/templated example keys from docs (e.g. `X-API-Key: zf_live_af9e...`).
      if (isPlaceholderMatch(text, raw, m.index ?? 0)) continue;
      matchedRaws.push(raw);
      let severity = rule.severity;
      // Google keys are publishable by design for browser SDKs (see classifyGoogleKey):
      // suppress the clearly-publishable ones, downgrade the unidentified ones to low.
      if (rule.provider === 'Google API key') {
        if (classifyGoogleKey(text, m.index ?? 0) === 'publishable') continue;
        severity = 'low';
      }
      const masked = rule.provider === 'Private key' ? '(private key block)' : mask(raw);
      add(rule.provider, severity, masked, m.index ?? 0);
    }
  }

  // 2) Database / broker connection strings with embedded credentials.
  for (const m of text.matchAll(CONNECTION_RE)) {
    const engineRaw = (m[1] ?? '').toLowerCase();
    const host = m[4] ?? '';
    const engine = ENGINE_LABELS[engineRaw] ?? engineRaw;
    const safeHost = host.length > 40 ? `${host.slice(0, 40)}…` : host;
    matchedRaws.push(m[0]);
    add(`${engine} connection string`, 'critical', `${engineRaw}://****:****@${safeHost}`, m.index ?? 0);
  }

  // 3) Generic high-entropy tokens (bounded, lower confidence).
  let entropyCount = 0;
  for (const m of text.matchAll(TOKEN_RE)) {
    if (entropyCount >= MAX_ENTROPY_FINDINGS) break;
    const raw = m[0];
    if (matchedRaws.some((mr) => mr.includes(raw) || raw.includes(mr))) continue;
    if (looksLikeNonSecret(raw)) continue;
    if (m.index !== undefined && isPlaceholderMatch(text, raw, m.index)) continue;
    if (shannonEntropy(raw) < ENTROPY_THRESHOLD) continue;
    entropyCount++;
    add('High-entropy token', 'low', mask(raw), m.index ?? 0);
  }

  hits.sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || a.line - b.line);
  return { hits, lineCount, counts };
}
