// DNS for the scanner's DNS-driven detectors (CAA, subdomain-takeover, SPF/DMARC).
//
// We resolve over DNS-over-HTTPS (DoH) rather than node:dns on purpose. node:dns
// (c-ares) sends UDP/TCP queries to the system nameservers on port 53; on networks
// that filter outbound 53 (and the scanner's home-PC host is one — see the
// "slow DNS" note) every lookup stalls ~20-30s and then times out, which used to
// hang whole scans. DoH runs over port 443, so it works anywhere the scanner can
// reach the internet at all, and answers in well under a second.
//
// A query that can't be answered at all (both providers fail / time out) reports
// status -1, which callers treat as *inconclusive* — never as "no record", so a
// blocked or flaky resolver can't manufacture a false "missing CAA/SPF/DMARC".

export const DNS_TIMEOUT_MS = 4_000;

export class DnsTimeoutError extends Error {
  constructor() {
    super('DNS lookup timed out');
    this.name = 'DnsTimeoutError';
  }
}

// --- DNS-over-HTTPS client --------------------------------------------------

// Two independent providers: if the first is unreachable we fall through to the
// second before giving up (returning inconclusive).
const DOH_ENDPOINTS = ['https://dns.google/resolve', 'https://cloudflare-dns.com/dns-query'];

/** DNS record-type numbers we query. */
export const DNS_TYPE = { A: 1, AAAA: 28, CNAME: 5, TXT: 16, CAA: 257 } as const;

/** A DNS rcode of 3 = the name does not exist (NXDOMAIN). */
const RCODE_NXDOMAIN = 3;

interface DohAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

export interface DohResult {
  /** DNS rcode: 0=NOERROR, 3=NXDOMAIN; -1 = the query itself failed (network/timeout) → inconclusive. */
  status: number;
  answers: DohAnswer[];
}

/** Resolve one name/type over DoH (port 443). Tries each provider in turn. */
export async function dohQuery(name: string, type: number): Promise<DohResult> {
  for (const ep of DOH_ENDPOINTS) {
    try {
      const url = `${ep}?name=${encodeURIComponent(name)}&type=${type}`;
      const res = await fetch(url, {
        headers: { accept: 'application/dns-json' },
        signal: AbortSignal.timeout(DNS_TIMEOUT_MS),
      });
      if (!res.ok) continue;
      const j = (await res.json()) as { Status?: number; Answer?: DohAnswer[] };
      return {
        status: typeof j.Status === 'number' ? j.Status : -1,
        answers: Array.isArray(j.Answer) ? j.Answer : [],
      };
    } catch {
      // provider unreachable/timed out — try the next one
    }
  }
  return { status: -1, answers: [] }; // inconclusive
}

function dataOfType(r: DohResult, type: number): string[] {
  return r.answers.filter((a) => a.type === type).map((a) => a.data);
}

/** CNAME target(s) for a host. [] when there is none or the lookup was inconclusive. */
export async function dohResolveCname(host: string): Promise<string[]> {
  return dataOfType(await dohQuery(host, DNS_TYPE.CNAME), DNS_TYPE.CNAME);
}

/** Raw TXT record strings. Throws DnsTimeoutError when inconclusive (so callers skip, not false-report). */
export async function dohResolveTxtRaw(host: string): Promise<string[]> {
  const r = await dohQuery(host, DNS_TYPE.TXT);
  if (r.status === -1) throw new DnsTimeoutError();
  return dataOfType(r, DNS_TYPE.TXT).map(unquoteTxt);
}

/** Raw CAA record strings (presentation form, e.g. `0 issue "pki.goog"`). Throws when inconclusive. */
export async function dohResolveCaaRaw(host: string): Promise<string[]> {
  const r = await dohQuery(host, DNS_TYPE.CAA);
  if (r.status === -1) throw new DnsTimeoutError();
  return dataOfType(r, DNS_TYPE.CAA);
}

/** true = resolves to an A/AAAA address, false = NXDOMAIN, null = inconclusive / exists-but-no-address. */
export async function dohHostResolves(host: string): Promise<boolean | null> {
  const a = await dohQuery(host, DNS_TYPE.A);
  if (dataOfType(a, DNS_TYPE.A).length > 0) return true;
  const aaaa = await dohQuery(host, DNS_TYPE.AAAA);
  if (dataOfType(aaaa, DNS_TYPE.AAAA).length > 0) return true;
  // Only call it "does not exist" when both lookups returned a clean NXDOMAIN.
  if (a.status === RCODE_NXDOMAIN && aaaa.status === RCODE_NXDOMAIN) return false;
  return null;
}

/**
 * Normalise a DoH TXT `data` value to the raw record string: strip wrapping quotes
 * and rejoin the `" "` segments providers insert when splitting long records.
 */
function unquoteTxt(d: string): string {
  return d.replace(/^"/, '').replace(/"$/, '').replace(/"\s+"/g, '');
}
