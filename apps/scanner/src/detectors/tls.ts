import { connect as tlsConnect } from 'node:tls';
import type { Finding } from '@vibescan/findings';
import type { CollectResult } from '../collector';
import { safeFetch } from '../util/fetch';

/**
 * TLS-hygiene detector (the `infra` category).
 *
 * Three read-only checks against the target host:
 *  1. Certificate expiry — an expired cert greets every visitor with a full-page
 *     browser warning; one expiring within two weeks is about to.
 *  2. Legacy TLS — a server that still completes a TLS 1.0/1.1 handshake (both
 *     deprecated industry-wide in 2020) is exploitable on a shared network.
 *  3. HTTP→HTTPS redirect — if http:// is served instead of redirected, that first
 *     request is unencrypted and tamperable.
 *
 * All network IO is injectable so the detector is unit-testable offline; production
 * uses a node:tls handshake and a plain-HTTP fetch.
 */

const EXPIRY_WARN_DAYS = 14;
const HANDSHAKE_TIMEOUT_MS = 7_000;
const MS_PER_DAY = 24 * 60 * 60 * 1000;

export interface TlsInspection {
  /** Leaf certificate's expiry (`valid_to`), or null when it couldn't be read. */
  validTo: Date | null;
  /** True when the host completes a handshake using a legacy protocol (TLS 1.0 or 1.1). */
  legacyTlsAccepted: boolean;
}

export interface HttpRedirectResult {
  /** True when a plain-HTTP request is redirected to https://. */
  redirectsToHttps: boolean;
}

export interface DetectTlsOptions {
  /** Injectable TLS handshake probe (tests pass a mock; production uses node:tls). */
  inspectTls?: (host: string) => Promise<TlsInspection | null>;
  /** Injectable plain-HTTP redirect probe (tests pass a mock; production uses fetch). */
  checkHttpRedirect?: (host: string) => Promise<HttpRedirectResult | null>;
}

/** The hostname to handshake with, or null for non-web targets (code-paste scans). */
export function tlsHost(collected: CollectResult): string | null {
  const ref = collected.finalUrl || collected.origin;
  try {
    const host = new URL(ref).hostname;
    return host || null;
  } catch {
    return null;
  }
}

export async function detectTls(
  collected: CollectResult,
  opts: DetectTlsOptions = {}
): Promise<Finding[]> {
  const host = tlsHost(collected);
  if (!host) return [];
  const findings: Finding[] = [];
  const isHttps = collected.origin.startsWith('https://');

  // 1) + 2) Certificate expiry and legacy-protocol support (only meaningful over TLS).
  if (isHttps) {
    const inspect = opts.inspectTls ?? defaultInspectTls;
    const info = await inspect(host);
    if (info) {
      const expiryFinding = certExpiryFinding(host, info.validTo);
      if (expiryFinding) findings.push(expiryFinding);

      if (info.legacyTlsAccepted) {
        findings.push({
          type: 'tls_weak_version',
          severity: 'medium',
          category: 'infra',
          summary: `${host} still accepts deprecated TLS 1.0/1.1 connections.`,
          evidence: 'TLS 1.0/1.1 handshake accepted',
          params: { domain: host, versions: 'TLS 1.0 / 1.1' },
        });
      }
    }
  }

  // 3) Plain HTTP must redirect to HTTPS.
  const checkRedirect = opts.checkHttpRedirect ?? defaultCheckHttpRedirect;
  const redirect = await checkRedirect(host);
  if (redirect && !redirect.redirectsToHttps) {
    findings.push({
      type: 'no_https_redirect',
      severity: 'medium',
      category: 'infra',
      summary: `http://${host} is not redirected to HTTPS — the first request is sent unencrypted.`,
      params: { domain: host },
    });
  }

  return findings;
}

/** Build the cert-expiry finding (high if already expired, medium if expiring soon), or null. */
function certExpiryFinding(host: string, validTo: Date | null): Finding | null {
  if (!validTo || Number.isNaN(validTo.getTime())) return null;
  const days = Math.floor((validTo.getTime() - Date.now()) / MS_PER_DAY);
  if (days < 0) {
    const ago = Math.abs(days);
    return {
      type: 'tls_expiring',
      severity: 'high',
      category: 'infra',
      summary: `The HTTPS certificate for ${host} has expired (${ago} day(s) ago) — visitors get a security warning.`,
      evidence: `expired ${validTo.toISOString().slice(0, 10)}`,
      params: {
        domain: host,
        state: 'has expired',
        detail: `expired ${ago} day(s) ago, so every visitor now gets a "not private" browser warning`,
      },
    };
  }
  if (days < EXPIRY_WARN_DAYS) {
    return {
      type: 'tls_expiring',
      severity: 'medium',
      category: 'infra',
      summary: `The HTTPS certificate for ${host} expires in ${days} day(s).`,
      evidence: `expires ${validTo.toISOString().slice(0, 10)}`,
      params: {
        domain: host,
        state: 'expires very soon',
        detail: `expires in ${days} day(s); once it lapses every visitor gets a "not private" browser warning`,
      },
    };
  }
  return null;
}

// --- Default (production) probes --------------------------------------------

/** Open one TLS connection to read the cert, then a second forcing a legacy version. */
const defaultInspectTls = async (host: string): Promise<TlsInspection | null> => {
  const validTo = await readCertExpiry(host);
  const legacyTlsAccepted = await legacyHandshakeAccepted(host);
  if (validTo === undefined) return legacyTlsAccepted ? { validTo: null, legacyTlsAccepted } : null;
  return { validTo, legacyTlsAccepted };
};

/** Returns the cert expiry Date, `null` if the cert had no valid_to, or `undefined` on connect failure. */
function readCertExpiry(host: string): Promise<Date | null | undefined> {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v: Date | null | undefined) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(v);
    };
    const socket = tlsConnect(
      // rejectUnauthorized:false so we can still read an expired/self-signed cert.
      { host, port: 443, servername: host, rejectUnauthorized: false, timeout: HANDSHAKE_TIMEOUT_MS },
      () => {
        const cert = socket.getPeerCertificate();
        const validTo = cert && cert.valid_to ? new Date(cert.valid_to) : null;
        finish(validTo);
      }
    );
    socket.on('timeout', () => finish(undefined));
    socket.on('error', () => finish(undefined));
  });
}

/** True when the host completes a handshake restricted to TLS 1.0/1.1. */
function legacyHandshakeAccepted(host: string): Promise<boolean> {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v: boolean) => {
      if (done) return;
      done = true;
      try {
        socket.destroy();
      } catch {
        /* ignore */
      }
      resolve(v);
    };
    let socket: ReturnType<typeof tlsConnect>;
    try {
      socket = tlsConnect(
        {
          host,
          port: 443,
          servername: host,
          rejectUnauthorized: false,
          minVersion: 'TLSv1',
          maxVersion: 'TLSv1.1',
          timeout: HANDSHAKE_TIMEOUT_MS,
        },
        () => finish(true)
      );
    } catch {
      // Node built without legacy TLS support throws synchronously — treat as "not accepted".
      resolve(false);
      return;
    }
    socket.on('timeout', () => finish(false));
    socket.on('error', () => finish(false));
  });
}

/** Probe http://host/ and report whether it redirects to https. Returns null if unreachable. */
const defaultCheckHttpRedirect = async (host: string): Promise<HttpRedirectResult | null> => {
  try {
    const res = await safeFetch(`http://${host}/`, {
      method: 'GET',
      redirect: 'manual',
      timeoutMs: 7_000,
      maxBytes: 2_000,
    });
    const location = res.headers['location'] ?? '';
    const redirectsToHttps =
      res.status >= 300 && res.status < 400 && /^https:\/\//i.test(location);
    return { redirectsToHttps };
  } catch {
    // http:// not reachable at all (https-only host) — can't conclude, so stay silent.
    return null;
  }
};
