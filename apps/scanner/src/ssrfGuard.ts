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
  if (ipInt < 0) return true; // unparseable -> treat as unsafe
  if (ip === '255.255.255.255') return true;
  return BLOCKED_V4.some(([base, bits]) => inCidr(ipInt, base, bits));
}

function isBlockedV6(ip: string): boolean {
  const v = ip.toLowerCase();
  if (v === '::1' || v === '::') return true;
  // IPv4-mapped / -compatible (::ffff:a.b.c.d) — validate the embedded v4.
  if (v.startsWith('::ffff:') || v.startsWith('::')) {
    const tail = v.slice(v.lastIndexOf(':') + 1);
    if (tail.includes('.') && net.isIPv4(tail)) return isBlockedV4(tail);
  }
  // Unique local (fc00::/7) and link-local (fe80::/10).
  if (v.startsWith('fc') || v.startsWith('fd')) return true;
  if (v.startsWith('fe8') || v.startsWith('fe9') || v.startsWith('fea') || v.startsWith('feb')) {
    return true;
  }
  return false;
}

/** True if the IP must never be contacted by the scanner. */
export function isBlockedIp(ip: string): boolean {
  const fam = net.isIP(ip);
  if (fam === 4) return isBlockedV4(ip);
  if (fam === 6) return isBlockedV6(ip);
  return true; // not a valid IP -> unsafe
}

const BLOCKED_HOSTNAMES = new Set(['localhost', 'localhost.localdomain', 'ip6-localhost']);

/**
 * Validate a user-supplied URL before the scanner touches it.
 * Throws SsrfError for anything pointing at private/internal infrastructure.
 * Returns the parsed URL and the resolved public IPs.
 *
 * Note: there is a small TOCTOU/DNS-rebinding window between this check and the
 * actual navigation. The collector adds a per-request hostname guard as a second
 * layer; pinning resolved IPs end-to-end is a future hardening step.
 */
export async function assertSafeUrl(rawUrl: string): Promise<{ url: URL; ips: string[] }> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new SsrfError('That does not look like a valid URL.');
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new SsrfError('Only http and https URLs can be scanned.');
  }

  const host = url.hostname.toLowerCase().replace(/\.$/, '');
  if (BLOCKED_HOSTNAMES.has(host) || host.endsWith('.localhost') || host.endsWith('.internal')) {
    throw new SsrfError('Scanning local or internal hosts is not allowed.');
  }

  // If the host is already an IP literal, check it directly.
  if (net.isIP(host)) {
    if (isBlockedIp(host)) throw new SsrfError('Scanning private/internal IP addresses is not allowed.');
    return { url, ips: [host] };
  }

  let resolved: Array<{ address: string }>;
  try {
    resolved = await dns.lookup(host, { all: true });
  } catch {
    throw new SsrfError('Could not resolve that domain. Check the URL and try again.');
  }

  if (resolved.length === 0) throw new SsrfError('Could not resolve that domain.');

  for (const { address } of resolved) {
    if (isBlockedIp(address)) {
      throw new SsrfError('That domain resolves to a private/internal address and cannot be scanned.');
    }
  }

  return { url, ips: resolved.map((r) => r.address) };
}

/** Lightweight per-request guard used during page navigation (redirects, sub-resources). */
export function isLikelyPrivateHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (BLOCKED_HOSTNAMES.has(host) || host.endsWith('.localhost') || host.endsWith('.internal')) {
    return true;
  }
  if (net.isIP(host)) return isBlockedIp(host);
  return false;
}
