// Server-only SSRF guard for the network tools (CORS, security.txt). A focused
// port of apps/scanner/src/ssrfGuard.ts: resolve the host and refuse anything
// pointing at private, loopback or otherwise internal infrastructure.
import dns from 'node:dns/promises';
import net from 'node:net';

export class SsrfError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SsrfError';
  }
}

function ipv4ToInt(ip: string): number {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) {
    return -1;
  }
  return ((parts[0]! << 24) >>> 0) + (parts[1]! << 16) + (parts[2]! << 8) + parts[3]!;
}

function inCidr(ipInt: number, base: string, bits: number): boolean {
  const baseInt = ipv4ToInt(base);
  if (baseInt < 0) return false;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}

// Private, loopback, link-local, reserved, CGNAT, test/benchmark, multicast.
const BLOCKED_V4: Array<[string, number]> = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.88.99.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
];

function isBlockedV4(ip: string): boolean {
  const ipInt = ipv4ToInt(ip);
  if (ipInt < 0) return true;
  if (ip === '255.255.255.255') return true;
  return BLOCKED_V4.some(([base, bits]) => inCidr(ipInt, base, bits));
}

function isBlockedV6(ip: string): boolean {
  const v = ip.toLowerCase();
  if (v === '::1' || v === '::') return true;
  if (v.startsWith('::ffff:') || v.startsWith('::')) {
    const tail = v.slice(v.lastIndexOf(':') + 1);
    if (tail.includes('.') && net.isIPv4(tail)) return isBlockedV4(tail);
  }
  if (v.startsWith('fc') || v.startsWith('fd')) return true;
  if (v.startsWith('fe8') || v.startsWith('fe9') || v.startsWith('fea') || v.startsWith('feb')) {
    return true;
  }
  return false;
}

export function isBlockedIp(ip: string): boolean {
  const fam = net.isIP(ip);
  if (fam === 4) return isBlockedV4(ip);
  if (fam === 6) return isBlockedV6(ip);
  return true;
}

const BLOCKED_HOSTNAMES = new Set(['localhost', 'localhost.localdomain', 'ip6-localhost']);

/**
 * Validate a user-supplied URL before a tool fetches it. Throws SsrfError for
 * anything pointing at private/internal infrastructure. Returns the parsed URL.
 */
export async function assertSafeUrl(rawUrl: string): Promise<URL> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new SsrfError('That does not look like a valid URL.');
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new SsrfError('Only http and https URLs are allowed.');
  }

  const host = url.hostname.toLowerCase().replace(/\.$/, '');
  if (BLOCKED_HOSTNAMES.has(host) || host.endsWith('.localhost') || host.endsWith('.internal')) {
    throw new SsrfError('Local or internal hosts are not allowed.');
  }

  if (net.isIP(host)) {
    if (isBlockedIp(host)) throw new SsrfError('Private/internal IP addresses are not allowed.');
    return url;
  }

  let resolved: Array<{ address: string }>;
  try {
    resolved = await dns.lookup(host, { all: true });
  } catch {
    throw new SsrfError('Could not resolve that domain. Check it and try again.');
  }

  if (resolved.length === 0) throw new SsrfError('Could not resolve that domain.');
  for (const { address } of resolved) {
    if (isBlockedIp(address)) {
      throw new SsrfError('That domain resolves to a private/internal address.');
    }
  }

  return url;
}

/**
 * Normalise free-form host input ("example.com", "https://example.com/x") to a
 * bare, lowercased hostname. Throws SsrfError on internal/invalid hosts.
 * Used by the DNS-based tools (email, dns) that look up records, not URLs.
 */
export function assertSafeHostname(raw: string): string {
  let host = raw.trim().toLowerCase();
  if (!host) throw new SsrfError('Please enter a domain.');
  // Strip a scheme/path if the user pasted a full URL.
  host = host.replace(/^[a-z]+:\/\//, '').split('/')[0]!.split('?')[0]!;
  host = host.replace(/^.*@/, ''); // tolerate an email-like input
  host = host.split(':')[0]!.replace(/\.$/, ''); // drop port + trailing dot

  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(host)) {
    throw new SsrfError('That does not look like a valid domain.');
  }
  if (BLOCKED_HOSTNAMES.has(host) || host.endsWith('.localhost') || host.endsWith('.internal')) {
    throw new SsrfError('Local or internal hosts are not allowed.');
  }
  return host;
}
