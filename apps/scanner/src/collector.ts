import { chromium, type Browser } from 'playwright';
import { USER_AGENT } from './config';
import { isLikelyPrivateHost } from './ssrfGuard';

export interface CollectedScript {
  url: string;
  content: string;
}

export interface CollectResult {
  finalUrl: string;
  origin: string;
  status: number;
  responseHeaders: Record<string, string>;
  /** Raw Set-Cookie header values from the main response (one entry per cookie). */
  setCookies: string[];
  html: string;
  scripts: CollectedScript[];
  /** All script bodies + inline scripts concatenated — the haystack for secret/regex scans. */
  jsCombined: string;
  /** Distinct hosts the page talked to (used to spot Supabase/Firebase). */
  requestedHosts: string[];
  notes: string[];
}

const MAX_JS_BYTES = 8 * 1024 * 1024; // 8 MB cap across all scripts
const NAV_TIMEOUT_MS = 25_000;
const NETWORK_IDLE_MS = 8_000;

let browserPromise: Promise<Browser> | null = null;

/** Lazily launch one shared Chromium and reuse it across scans. */
async function getBrowser(): Promise<Browser> {
  if (!browserPromise) {
    browserPromise = chromium.launch({
      args: ['--no-sandbox', '--disable-dev-shm-usage'],
    });
  }
  return browserPromise;
}

export async function closeBrowser(): Promise<void> {
  if (browserPromise) {
    const b = await browserPromise;
    await b.close();
    browserPromise = null;
  }
}

function extractInlineScripts(html: string): string[] {
  const out: string[] = [];
  const re = /<script\b[^>]*>([\s\S]*?)<\/script>/gi;
  for (const m of html.matchAll(re)) {
    const code = m[1]?.trim();
    if (code) out.push(code);
  }
  return out;
}

export async function collect(targetUrl: string): Promise<CollectResult> {
  const notes: string[] = [];
  const browser = await getBrowser();
  const context = await browser.newContext({
    userAgent: USER_AGENT,
    ignoreHTTPSErrors: false,
    serviceWorkers: 'block',
  });
  const page = await context.newPage();

  const scripts: CollectedScript[] = [];
  const bodyPromises: Promise<void>[] = [];
  const requestedHosts = new Set<string>();
  let jsBytes = 0;

  // Second-layer SSRF guard + skip heavy resources we don't analyse.
  await context.route('**/*', (route) => {
    const req = route.request();
    let host = '';
    try {
      host = new URL(req.url()).hostname;
    } catch {
      return route.abort();
    }
    if (isLikelyPrivateHost(host)) return route.abort();
    const type = req.resourceType();
    if (type === 'image' || type === 'media' || type === 'font') return route.abort();
    return route.continue();
  });

  page.on('request', (req) => {
    try {
      requestedHosts.add(new URL(req.url()).hostname);
    } catch {
      /* ignore */
    }
  });

  page.on('response', (resp) => {
    const req = resp.request();
    const url = resp.url();
    const isJs = req.resourceType() === 'script' || /\.m?js(\?|$)/i.test(url);
    if (!isJs) return;
    if (jsBytes >= MAX_JS_BYTES) return;
    bodyPromises.push(
      resp
        .text()
        .then((text) => {
          if (jsBytes >= MAX_JS_BYTES) return;
          jsBytes += Buffer.byteLength(text);
          scripts.push({ url, content: text });
        })
        .catch(() => {
          /* body not retrievable — ignore */
        })
    );
  });

  let status = 0;
  let finalUrl = targetUrl;
  let responseHeaders: Record<string, string> = {};
  const setCookies: string[] = [];

  try {
    const resp = await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: NAV_TIMEOUT_MS });
    if (resp) {
      status = resp.status();
      finalUrl = resp.url();
      responseHeaders = resp.headers();
      // headersArray preserves every Set-Cookie separately (headers() collapses them).
      try {
        for (const { name, value } of await resp.headersArray()) {
          if (name.toLowerCase() === 'set-cookie') setCookies.push(value);
        }
      } catch {
        /* headersArray unavailable — fall back to the collapsed header below */
      }
      if (setCookies.length === 0 && responseHeaders['set-cookie']) {
        setCookies.push(...responseHeaders['set-cookie'].split('\n'));
      }
    }
  } catch (err) {
    notes.push(`Navigation issue: ${(err as Error).message}`);
  }

  // Give late-loaded chunks a chance, but don't hang forever.
  try {
    await page.waitForLoadState('networkidle', { timeout: NETWORK_IDLE_MS });
  } catch {
    notes.push('Page kept loading; results may be partial.');
  }

  let html = '';
  try {
    html = await page.content();
  } catch {
    /* ignore */
  }

  await Promise.allSettled(bodyPromises);
  await context.close();

  const inline = extractInlineScripts(html);
  const jsCombined = [...scripts.map((s) => s.content), ...inline].join('\n');

  let origin = '';
  try {
    origin = new URL(finalUrl).origin;
  } catch {
    /* ignore */
  }

  return {
    finalUrl,
    origin,
    status,
    responseHeaders,
    setCookies,
    html,
    scripts,
    jsCombined,
    requestedHosts: [...requestedHosts],
    notes,
  };
}
