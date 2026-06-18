// node:dns has no built-in deadline, so a slow or filtered resolver can stall a
// single lookup for 20-30s (c-ares retries). DNS-driven detectors race every
// query against this hard cap so they stay responsive; a timeout surfaces as a
// DnsTimeoutError so callers can treat it as *inconclusive* rather than as
// "no record" (which would raise a false positive).

export const DNS_TIMEOUT_MS = 4_000;

export class DnsTimeoutError extends Error {
  constructor() {
    super('DNS lookup timed out');
    this.name = 'DnsTimeoutError';
  }
}

/** Race a DNS lookup against the deadline, rejecting with DnsTimeoutError on timeout. */
export function withDnsTimeout<T>(p: Promise<T>, ms: number = DNS_TIMEOUT_MS): Promise<T> {
  return Promise.race([
    p,
    new Promise<T>((_, reject) => setTimeout(() => reject(new DnsTimeoutError()), ms)),
  ]);
}
