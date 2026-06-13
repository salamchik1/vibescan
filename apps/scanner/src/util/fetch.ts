import { USER_AGENT } from '../config';
import { isLikelyPrivateHost } from '../ssrfGuard';

export interface SafeFetchOptions {
  method?: string;
  headers?: Record<string, string>;
  /** Optional request body (e.g. a GraphQL introspection query). */
  body?: string;
  timeoutMs?: number;
  redirect?: 'follow' | 'manual' | 'error';
  /** Cap the number of response bytes we read. */
  maxBytes?: number;
}

export interface SafeFetchResult {
  ok: boolean;
  status: number;
  headers: Record<string, string>;
  body: string;
  truncated: boolean;
  url: string;
}

/**
 * fetch() wrapper with a timeout, a byte cap, our bot User-Agent, and a
 * second-layer SSRF check on the target host. Never throws on HTTP status;
 * throws only on network/timeout errors.
 */
export async function safeFetch(rawUrl: string, opts: SafeFetchOptions = {}): Promise<SafeFetchResult> {
  const { method = 'GET', headers = {}, body, timeoutMs = 10_000, redirect = 'follow', maxBytes = 1_000_000 } = opts;

  const target = new URL(rawUrl);
  if (isLikelyPrivateHost(target.hostname)) {
    throw new Error('Refusing to fetch a private/internal host.');
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(target, {
      method,
      redirect,
      signal: controller.signal,
      headers: { 'user-agent': USER_AGENT, ...headers },
      ...(body !== undefined ? { body } : {}),
    });

    const respHeaders: Record<string, string> = {};
    res.headers.forEach((v, k) => {
      respHeaders[k.toLowerCase()] = v;
    });

    // Read up to maxBytes.
    const reader = res.body?.getReader();
    let received = 0;
    let truncated = false;
    const chunks: Uint8Array[] = [];
    if (reader) {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          received += value.byteLength;
          if (received > maxBytes) {
            chunks.push(value.slice(0, value.byteLength - (received - maxBytes)));
            truncated = true;
            await reader.cancel();
            break;
          }
          chunks.push(value);
        }
      }
    }
    const responseBody = Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8');

    return { ok: res.ok, status: res.status, headers: respHeaders, body: responseBody, truncated, url: res.url };
  } finally {
    clearTimeout(timer);
  }
}

/** True when a 200 response is just the SPA's index.html fallback, not the real file we asked for. */
export function looksLikeHtml(headers: Record<string, string>, body: string): boolean {
  const ct = headers['content-type'] ?? '';
  if (ct.includes('text/html')) return true;
  const head = body.slice(0, 200).toLowerCase();
  return head.includes('<!doctype html') || head.includes('<html');
}
