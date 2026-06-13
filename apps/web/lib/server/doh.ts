// DNS-over-HTTPS client (Cloudflare). Used by the email and DNS tools instead
// of node:dns so we get consistent results across environments plus the AD
// (DNSSEC-validated) flag, which node's resolver does not surface.

export interface DohAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

export interface DohResponse {
  /** RCODE: 0 = NOERROR, 3 = NXDOMAIN. */
  Status: number;
  /** Authenticated Data — true when the resolver DNSSEC-validated the answer. */
  AD: boolean;
  Answer?: DohAnswer[];
  Authority?: DohAnswer[];
}

// Numeric DNS record types we query.
export const RECORD_TYPE = {
  A: 1,
  TXT: 16,
  MX: 15,
  CAA: 257,
  DNSKEY: 48,
  DS: 43,
} as const;

const ENDPOINT = 'https://cloudflare-dns.com/dns-query';

/** Query a record type for a name over DoH. Throws on transport failure. */
export async function dohQuery(name: string, type: number): Promise<DohResponse> {
  const url = `${ENDPOINT}?name=${encodeURIComponent(name)}&type=${type}&do=1`;
  const res = await fetch(url, {
    headers: { accept: 'application/dns-json' },
    signal: AbortSignal.timeout(8_000),
  });
  if (!res.ok) throw new Error(`DoH query failed (${res.status})`);
  return (await res.json()) as DohResponse;
}

/**
 * TXT records come back with each character-string wrapped in quotes and long
 * records split into multiple quoted chunks — join them into one clean string.
 */
export function unquoteTxt(data: string): string {
  const chunks = data.match(/"((?:[^"\\]|\\.)*)"/g);
  if (!chunks) return data.replace(/^"|"$/g, '');
  return chunks.map((c) => c.slice(1, -1).replace(/\\"/g, '"')).join('');
}
