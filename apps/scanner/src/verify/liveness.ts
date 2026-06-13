import type { VerificationStatus } from '@vibescan/findings';
import { USER_AGENT } from '../config';

/**
 * Secret liveness verification.
 *
 * When the scanner finds an API key in a site's public JavaScript, a pattern match
 * alone cannot tell a live, dangerous key from one that was already revoked. This
 * module makes ONE lightweight, strictly read-only request to the issuing provider
 * (an identity / balance / "who am I" endpoint) to find out — the same technique
 * truffleHog uses to mark a secret "verified".
 *
 * Hard safety rules every verifier here obeys:
 *  - Read-only only: GET, or a side-effect-free POST like Slack's auth.test. Never
 *    create, update, delete, or send anything.
 *  - The secret travels only to its own provider's official HTTPS host, in the
 *    Authorization header, over a connection that never follows redirects
 *    (`redirect: 'error'`) — so a hijacked redirect can't leak it to a third party.
 *  - Short timeout, capped response read, and the raw key is never logged or returned;
 *    only a status and a secret-free, human-readable detail string leave this module.
 */

export interface ProbeResponse {
  status: number;
  bodyText: string;
  /** Case-insensitive response header lookup. */
  getHeader(name: string): string | null;
}

/** Injectable HTTP layer so verifiers can be unit-tested offline. */
export type Probe = (
  url: string,
  init?: { method?: string; headers?: Record<string, string> }
) => Promise<ProbeResponse | null>;

export interface LivenessResult {
  status: VerificationStatus;
  /** Human-friendly description of the endpoint, e.g. "GET api.stripe.com/v1/balance". */
  endpoint: string;
  /** Secret-free explanation of what we learned. */
  detail?: string;
}

const PROBE_TIMEOUT_MS = 6_000;
const MAX_BODY_BYTES = 16 * 1024;

/** Real network probe. Returns `null` on any network error, timeout, or blocked redirect. */
export const httpProbe: Probe = async (url, init = {}) => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: init.method ?? 'GET',
      // Never follow a redirect while carrying the secret — that's how credentials leak cross-host.
      redirect: 'error',
      signal: controller.signal,
      headers: { 'user-agent': USER_AGENT, accept: 'application/json', ...(init.headers ?? {}) },
    });
    let bodyText = '';
    try {
      const buf = await res.arrayBuffer();
      bodyText = Buffer.from(buf).subarray(0, MAX_BODY_BYTES).toString('utf8');
    } catch {
      bodyText = '';
    }
    return { status: res.status, bodyText, getHeader: (n) => res.headers.get(n) };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
};

// --- result helpers ---------------------------------------------------------

function active(endpoint: string, detail: string): LivenessResult {
  return { status: 'active', endpoint, detail };
}
function inactive(endpoint: string): LivenessResult {
  return {
    status: 'inactive',
    endpoint,
    detail: 'The provider rejected this key — it has already been revoked or rotated. Low risk now, but still remove it from your code.',
  };
}
function unverified(endpoint: string, why?: string): LivenessResult {
  return {
    status: 'unverified',
    endpoint,
    detail: why ?? "Couldn't confirm with the provider — treat the key as live until you've rotated it.",
  };
}

function parseJson(text: string): any {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

/** Belt-and-suspenders: a detail line must never echo the secret, and stays short/single-line. */
function safeDetail(text: string, secret: string): string {
  let d = text.replace(/\s+/g, ' ').trim().slice(0, 200);
  if (secret.length >= 8 && d.includes(secret)) d = d.split(secret).join('****');
  return d;
}

/** Default status mapping for the common "Bearer key on a /me endpoint" shape. */
function byStatus(r: ProbeResponse, endpoint: string, activeDetail: string): LivenessResult {
  if (r.status >= 200 && r.status < 300) return active(endpoint, activeDetail);
  if (r.status === 401) return inactive(endpoint);
  // 403 = the key is recognised but lacks scope for THIS endpoint → still a live key.
  if (r.status === 403) return active(endpoint, `${activeDetail} (the key is valid but limited in scope)`);
  if (r.status === 429) return unverified(endpoint, 'Provider rate-limited the check — the key looks real but we backed off.');
  return unverified(endpoint, `Provider answered ${r.status}; could not confirm.`);
}

// --- per-provider verifiers -------------------------------------------------
// Keyed by the exact `provider` string used in the secret detector's RULES.

type Verifier = (secret: string, probe: Probe) => Promise<LivenessResult>;

const VERIFIERS: Record<string, Verifier> = {
  'OpenAI API key': async (secret, probe) => {
    const ep = 'GET api.openai.com/v1/models';
    const r = await probe('https://api.openai.com/v1/models', { headers: { authorization: `Bearer ${secret}` } });
    if (!r) return unverified(ep);
    return byStatus(r, ep, 'OpenAI accepted this key — it can spend your API credits right now.');
  },

  'Anthropic API key': async (secret, probe) => {
    const ep = 'GET api.anthropic.com/v1/models';
    const r = await probe('https://api.anthropic.com/v1/models', {
      headers: { 'x-api-key': secret, 'anthropic-version': '2023-06-01' },
    });
    if (!r) return unverified(ep);
    return byStatus(r, ep, 'Anthropic accepted this key — it can spend your API credits right now.');
  },

  'Stripe live secret key': async (secret, probe) => {
    const ep = 'GET api.stripe.com/v1/balance';
    const auth = `Basic ${Buffer.from(`${secret}:`).toString('base64')}`;
    const r = await probe('https://api.stripe.com/v1/balance', { headers: { authorization: auth } });
    if (!r) return unverified(ep);
    return byStatus(r, ep, 'Stripe accepted this key — it can read your balance and move real money.');
  },

  'Stripe test secret key': async (secret, probe) => {
    const ep = 'GET api.stripe.com/v1/balance';
    const auth = `Basic ${Buffer.from(`${secret}:`).toString('base64')}`;
    const r = await probe('https://api.stripe.com/v1/balance', { headers: { authorization: auth } });
    if (!r) return unverified(ep);
    return byStatus(r, ep, 'Stripe accepted this test key (test mode — no real money, but still rotate it).');
  },

  'GitHub token': async (secret, probe) => githubUser(secret, probe),
  'GitHub fine-grained token': async (secret, probe) => githubUser(secret, probe),

  'GitLab personal access token': async (secret, probe) => {
    const ep = 'GET gitlab.com/api/v4/user';
    const r = await probe('https://gitlab.com/api/v4/user', { headers: { authorization: `Bearer ${secret}` } });
    if (!r) return unverified(ep);
    if (r.status >= 200 && r.status < 300) {
      const u = parseJson(r.bodyText);
      const who = typeof u?.username === 'string' ? ` (account @${String(u.username).slice(0, 40)})` : '';
      return active(ep, safeDetail(`GitLab accepted this token${who} — it can act on your projects.`, secret));
    }
    if (r.status === 401) return inactive(ep);
    return unverified(ep, `GitLab answered ${r.status}.`);
  },

  'SendGrid API key': async (secret, probe) => {
    const ep = 'GET api.sendgrid.com/v3/scopes';
    const r = await probe('https://api.sendgrid.com/v3/scopes', { headers: { authorization: `Bearer ${secret}` } });
    if (!r) return unverified(ep);
    if (r.status >= 200 && r.status < 300) {
      const body = parseJson(r.bodyText);
      const scopes: string[] = Array.isArray(body?.scopes) ? body.scopes : [];
      const canSend = scopes.includes('mail.send');
      return active(
        ep,
        canSend
          ? 'SendGrid accepted this key and it has mail.send — anyone can send email as you with it.'
          : 'SendGrid accepted this key — it is live.'
      );
    }
    if (r.status === 401) return inactive(ep);
    return unverified(ep, `SendGrid answered ${r.status}.`);
  },

  'Hugging Face token': async (secret, probe) => {
    const ep = 'GET huggingface.co/api/whoami-v2';
    const r = await probe('https://huggingface.co/api/whoami-v2', { headers: { authorization: `Bearer ${secret}` } });
    if (!r) return unverified(ep);
    if (r.status >= 200 && r.status < 300) {
      const u = parseJson(r.bodyText);
      const who = typeof u?.name === 'string' ? ` (account ${String(u.name).slice(0, 40)})` : '';
      return active(ep, safeDetail(`Hugging Face accepted this token${who} — it is live.`, secret));
    }
    if (r.status === 401) return inactive(ep);
    return unverified(ep, `Hugging Face answered ${r.status}.`);
  },

  'DigitalOcean token': async (secret, probe) => {
    const ep = 'GET api.digitalocean.com/v2/account';
    const r = await probe('https://api.digitalocean.com/v2/account', { headers: { authorization: `Bearer ${secret}` } });
    if (!r) return unverified(ep);
    return byStatus(r, ep, 'DigitalOcean accepted this token — it can control your infrastructure.');
  },

  'Telegram bot token': async (secret, probe) => {
    const ep = 'GET api.telegram.org/bot…/getMe';
    // The token's own `:` is part of Telegram's `bot<token>` path syntax — do not encode it.
    const r = await probe(`https://api.telegram.org/bot${secret}/getMe`);
    if (!r) return unverified(ep);
    const body = parseJson(r.bodyText);
    if (r.status >= 200 && r.status < 300 && body?.ok === true) {
      const name = typeof body?.result?.username === 'string' ? ` (@${String(body.result.username).slice(0, 40)})` : '';
      return active(ep, safeDetail(`Telegram accepted this bot token${name} — it can fully control the bot.`, secret));
    }
    if (r.status === 401 || body?.ok === false) return inactive(ep);
    return unverified(ep, `Telegram answered ${r.status}.`);
  },

  // Slack's auth.test is a documented, side-effect-free identity probe (POST by API design).
  'Slack token': async (secret, probe) => {
    const ep = 'POST slack.com/api/auth.test';
    const r = await probe('https://slack.com/api/auth.test', {
      method: 'POST',
      headers: { authorization: `Bearer ${secret}` },
    });
    if (!r) return unverified(ep);
    const body = parseJson(r.bodyText);
    if (r.status >= 200 && r.status < 300 && body?.ok === true) {
      const team = typeof body?.team === 'string' ? ` (workspace ${String(body.team).slice(0, 40)})` : '';
      return active(ep, safeDetail(`Slack accepted this token${team} — it is live.`, secret));
    }
    if (body?.ok === false || r.status === 401) return inactive(ep);
    return unverified(ep, `Slack answered ${r.status}.`);
  },
};

async function githubUser(secret: string, probe: Probe): Promise<LivenessResult> {
  const ep = 'GET api.github.com/user';
  const r = await probe('https://api.github.com/user', {
    headers: { authorization: `Bearer ${secret}`, accept: 'application/vnd.github+json' },
  });
  if (!r) return unverified(ep);
  if (r.status >= 200 && r.status < 300) {
    const u = parseJson(r.bodyText);
    const login = typeof u?.login === 'string' && /^[A-Za-z0-9-]{1,39}$/.test(u.login) ? `@${u.login}` : null;
    const scopes = (r.getHeader('x-oauth-scopes') ?? '').trim();
    const parts = ['GitHub accepted this token'];
    if (login) parts.push(`(account ${login})`);
    if (scopes) parts.push(`— scopes: ${scopes.slice(0, 80)}`);
    else parts.push('— it can act on your account');
    return active(ep, safeDetail(`${parts.join(' ')}.`, secret));
  }
  if (r.status === 401) return inactive(ep);
  return unverified(ep, `GitHub answered ${r.status}.`);
}

/** True when we have a read-only liveness check for this provider. */
export function isVerifiable(provider: string): boolean {
  return provider in VERIFIERS;
}

/**
 * Run the read-only liveness check for a detected secret.
 * Returns `null` when the provider has no verifier (the caller leaves the finding unannotated).
 * Never throws — any failure collapses to an `unverified` result.
 */
export async function verifySecret(provider: string, secret: string, probe: Probe = httpProbe): Promise<LivenessResult | null> {
  const fn = VERIFIERS[provider];
  if (!fn) return null;
  try {
    return await fn(secret.trim(), probe);
  } catch {
    return unverified('', 'Live check errored out.');
  }
}
