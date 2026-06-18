import {
  resolveCaa as dnsResolveCaa,
  resolveCname as dnsResolveCname,
  resolve4 as dnsResolve4,
  resolve6 as dnsResolve6,
} from 'node:dns/promises';
import type { Finding } from '@vibescan/findings';
import type { CollectResult } from '../collector';
import { safeFetch } from '../util/fetch';
import { withDnsTimeout, DnsTimeoutError } from '../util/dns';
import {
  scannedHost,
  apexGuess,
  ancestorsToApex,
  isPlatformSubdomain,
} from '../util/host';

/**
 * DNS-hygiene + subdomain-takeover detector (the `infra` category).
 *
 * Two read-only, DNS-driven checks. Both lean hard against false positives,
 * because a scary "your domain can be hijacked" headline must never fire on a
 * healthy site:
 *
 *  1. CAA record — a domain with no CAA record lets *any* certificate authority
 *     mint an HTTPS certificate for it. That removes a cheap, standard guard-rail
 *     against mis-issuance, so it is worth a gentle, low-severity nudge.
 *
 *  2. Dangling CNAME → subdomain takeover — the high-value, higher-logic check.
 *     A subdomain whose CNAME points at a third-party service slot that is no
 *     longer claimed (a deleted Heroku app, an unclaimed GitHub Pages site, a
 *     missing S3 bucket, a torn-down Azure resource) can be *re-registered by an
 *     attacker*, who then serves their own content from your domain — perfect for
 *     phishing, cookie theft, or abusing OAuth redirects. We only raise this when
 *     it is **confirmed** dangling (the service slot resolves to NXDOMAIN, or the
 *     live response carries the provider's documented "unclaimed" fingerprint).
 *     An unknown CNAME pointing at a name that no longer exists is reported only
 *     as a low "stale/dangling record — verify" note.
 *
 * All DNS + HTTP IO is injectable so the detector is fully unit-testable offline;
 * production uses node:dns/promises and the SSRF-guarded safeFetch.
 */

/** One takeover-prone hosting service and how to tell its slot is unclaimed. */
export interface TakeoverService {
  /** Human label shown in the finding, e.g. "GitHub Pages". */
  name: string;
  /** CNAME-target suffixes that route to this service (matched case-insensitively). */
  cnameSuffixes: string[];
  /**
   * When true, a deleted resource on this service makes its CNAME target itself
   * stop resolving (NXDOMAIN) — so an unresolvable target is proof the slot is free
   * (e.g. Azure, AWS resources addressed by their own hostname).
   */
  nxdomainTakeover: boolean;
  /** Documented "this slot is unclaimed" strings to look for in the live HTTP body. */
  fingerprints: string[];
}

/**
 * A conservative, well-established subset of the community "can-i-take-over-xyz"
 * fingerprints — only services with a documented, stable unclaimed-signature, to
 * keep false positives at essentially zero.
 */
export const TAKEOVER_SERVICES: TakeoverService[] = [
  {
    name: 'GitHub Pages',
    cnameSuffixes: ['github.io'],
    nxdomainTakeover: false,
    fingerprints: ["There isn't a GitHub Pages site here", 'For root URLs (like http://example.com/) you must provide an index.html file'],
  },
  {
    name: 'Heroku',
    cnameSuffixes: ['herokuapp.com', 'herokudns.com', 'herokussl.com'],
    nxdomainTakeover: false,
    fingerprints: ['No such app', 'herokucdn.com/error-pages/no-such-app.html'],
  },
  {
    name: 'Amazon S3',
    cnameSuffixes: ['amazonaws.com'],
    nxdomainTakeover: false,
    fingerprints: ['NoSuchBucket', 'The specified bucket does not exist'],
  },
  {
    name: 'Shopify',
    cnameSuffixes: ['myshopify.com'],
    nxdomainTakeover: false,
    fingerprints: ['Sorry, this shop is currently unavailable'],
  },
  {
    name: 'Fastly',
    cnameSuffixes: ['fastly.net'],
    nxdomainTakeover: false,
    fingerprints: ['Fastly error: unknown domain'],
  },
  {
    name: 'Surge.sh',
    cnameSuffixes: ['surge.sh'],
    nxdomainTakeover: false,
    fingerprints: ['project not found'],
  },
  {
    name: 'Bitbucket',
    cnameSuffixes: ['bitbucket.io'],
    nxdomainTakeover: false,
    fingerprints: ['Repository not found'],
  },
  {
    name: 'Microsoft Azure',
    cnameSuffixes: [
      'azurewebsites.net',
      'cloudapp.net',
      'cloudapp.azure.com',
      'trafficmanager.net',
      'blob.core.windows.net',
      'azureedge.net',
      'azure-api.net',
      'azurecontainer.io',
    ],
    nxdomainTakeover: true,
    fingerprints: ['404 Web Site not found'],
  },
  {
    name: 'Pantheon',
    cnameSuffixes: ['pantheonsite.io'],
    nxdomainTakeover: false,
    fingerprints: ['The gods are wise', '404 error unknown site'],
  },
];

/** Common subdomain labels we additionally probe under the registrable apex. */
const COMMON_SUBDOMAINS = [
  'www',
  'app',
  'api',
  'admin',
  'blog',
  'docs',
  'dev',
  'staging',
  'test',
  'cdn',
  'assets',
  'static',
  'mail',
  'shop',
  'status',
  'support',
  'portal',
  'dashboard',
];

/** A CAA resource record (only the tag values we care about). */
export interface CaaRecord {
  critical?: number;
  issue?: string;
  issuewild?: string;
  iodef?: string;
}

export interface DetectDnsOptions {
  /** Injectable CAA resolver (production: node:dns). Returns [] for "no CAA / no such name". */
  resolveCaa?: (host: string) => Promise<CaaRecord[]>;
  /** Injectable CNAME resolver. Returns the canonical target(s), or [] when there is no CNAME. */
  resolveCname?: (host: string) => Promise<string[]>;
  /** Whether a name resolves to an address: true=resolves, false=NXDOMAIN, null=inconclusive. */
  hostResolves?: (host: string) => Promise<boolean | null>;
  /** Fetch a host's live body for fingerprinting, or null if unreachable. */
  fetchBody?: (host: string) => Promise<string | null>;
  /** Override the set of hosts probed for takeover (tests pin this; production enumerates). */
  candidateHosts?: string[];
}

export async function detectDns(
  collected: CollectResult,
  opts: DetectDnsOptions = {}
): Promise<Finding[]> {
  const host = scannedHost(collected);
  if (!host) return [];

  const resolveCaa = opts.resolveCaa ?? defaultResolveCaa;
  const resolveCname = opts.resolveCname ?? defaultResolveCname;
  const hostResolves = opts.hostResolves ?? defaultHostResolves;
  const fetchBody = opts.fetchBody ?? defaultFetchBody;

  const findings: Finding[] = [];

  // --- 1) CAA record (skip platform subdomains — DNS isn't user-controlled) ---
  if (!isPlatformSubdomain(host)) {
    const apex = apexGuess(host);
    let hasCaa = false;
    let inconclusive = false;
    // A CAA record on any ancestor covers everything below it, so climb the tree.
    for (const name of ancestorsToApex(host)) {
      try {
        const records = await resolveCaa(name);
        if (records.length > 0) {
          hasCaa = true;
          break;
        }
      } catch {
        // A timed-out/failed lookup is inconclusive — never report "no CAA" off
        // a resolver that simply didn't answer (would be a false positive).
        inconclusive = true;
        break;
      }
    }
    if (!hasCaa && !inconclusive) {
      findings.push({
        type: 'caa_missing',
        severity: 'low',
        category: 'infra',
        summary: `${apex} has no CAA record — any certificate authority is allowed to issue HTTPS certificates for it.`,
        params: { domain: apex },
      });
    }
  }

  // --- 2) Dangling CNAME / subdomain takeover --------------------------------
  // Probe candidates concurrently: a slow/filtered resolver then bounds this by
  // the slowest single host, not the sum of ~18 sequential lookups (which on a
  // sluggish network blew past the whole scan budget).
  const candidates = [...new Set(opts.candidateHosts ?? candidateHosts(host))];
  const perCandidate = await Promise.all(
    candidates.map((cand) => checkCandidate(cand, host, collected, { resolveCname, hostResolves, fetchBody }))
  );
  findings.push(...perCandidate.flat());

  return findings;
}

/** Inspect one candidate host for a confirmed takeover or a dangling CNAME. */
async function checkCandidate(
  cand: string,
  host: string,
  collected: CollectResult,
  io: {
    resolveCname: NonNullable<DetectDnsOptions['resolveCname']>;
    hostResolves: NonNullable<DetectDnsOptions['hostResolves']>;
    fetchBody: NonNullable<DetectDnsOptions['fetchBody']>;
  }
): Promise<Finding[]> {
  let targets: string[];
  try {
    targets = await io.resolveCname(cand);
  } catch {
    return []; // resolver error — stay silent rather than risk a false alarm
  }
  if (!targets.length) return [];

  const service = matchTakeoverService(targets);
  if (service) {
    const { matched, svc } = service;
    const confirmed = await isUnclaimed(svc, matched, cand, host, collected, io.hostResolves, io.fetchBody);
    if (!confirmed) return [];
    return [{
      type: 'subdomain_takeover',
      severity: 'high',
      category: 'infra',
      summary: `${cand} points to an unclaimed ${svc.name} slot (${matched}) — an attacker can re-register it and serve content from your domain.`,
      evidence: `CNAME ${cand} → ${matched}`,
      params: { host: cand, service: svc.name, target: matched },
    }];
  }

  // No known service: a CNAME whose target no longer exists is a stale/dangling
  // record. Factually broken and a takeover candidate, but unconfirmed — low.
  const target = targets[0] ?? '';
  const resolves = await io.hostResolves(target);
  if (resolves === false) {
    return [{
      type: 'dangling_dns',
      severity: 'low',
      category: 'infra',
      summary: `${cand} has a CNAME to ${target}, which no longer exists — a stale/dangling DNS record worth removing or re-pointing.`,
      evidence: `CNAME ${cand} → ${target} (NXDOMAIN)`,
      params: { host: cand, target },
    }];
  }
  return [];
}

/** The takeover-prone candidate hosts: the scanned host plus common subdomains under its apex. */
export function candidateHosts(host: string): string[] {
  const apex = apexGuess(host);
  const set = new Set<string>([host]);
  for (const prefix of COMMON_SUBDOMAINS) set.add(`${prefix}.${apex}`);
  return [...set];
}

/** Find the first CNAME target that routes to a known takeover-prone service. */
function matchTakeoverService(
  targets: string[]
): { svc: TakeoverService; matched: string } | null {
  for (const raw of targets) {
    const target = raw.replace(/\.$/, '').toLowerCase();
    for (const svc of TAKEOVER_SERVICES) {
      if (svc.cnameSuffixes.some((s) => target === s || target.endsWith(`.${s}`))) {
        return { svc, matched: target };
      }
    }
  }
  return null;
}

/**
 * Confirm a service slot is actually unclaimed before raising the alarm:
 *  - NXDOMAIN-style services: the CNAME target itself no longer resolving is proof.
 *  - Otherwise: the live HTTP body must carry the provider's "unclaimed" fingerprint.
 * For the scanned host we reuse the body already fetched by the collector.
 */
async function isUnclaimed(
  svc: TakeoverService,
  target: string,
  cand: string,
  scanned: string,
  collected: CollectResult,
  hostResolves: NonNullable<DetectDnsOptions['hostResolves']>,
  fetchBody: NonNullable<DetectDnsOptions['fetchBody']>
): Promise<boolean> {
  if (svc.nxdomainTakeover) {
    const resolves = await hostResolves(target);
    if (resolves === false) return true;
  }
  if (!svc.fingerprints.length) return false;
  const body = cand === scanned ? collected.html : await fetchBody(cand);
  if (!body) return false;
  return svc.fingerprints.some((fp) => body.includes(fp));
}

// --- Default (production) resolvers -----------------------------------------

/** Real CAA resolver: swallow NXDOMAIN/ENODATA as "no CAA records"; rethrow timeouts as inconclusive. */
const defaultResolveCaa = async (host: string): Promise<CaaRecord[]> => {
  try {
    return (await withDnsTimeout(dnsResolveCaa(host))) as CaaRecord[];
  } catch (err) {
    if (err instanceof DnsTimeoutError) throw err; // inconclusive — caller skips
    return []; // NXDOMAIN/ENODATA = genuinely no CAA
  }
};

/** Real CNAME resolver: swallow NXDOMAIN/ENODATA/timeout as "no CNAME". */
const defaultResolveCname = async (host: string): Promise<string[]> => {
  try {
    return await withDnsTimeout(dnsResolveCname(host));
  } catch {
    return [];
  }
};

/** True if the name resolves to an A/AAAA address, false on NXDOMAIN, null if inconclusive. */
const defaultHostResolves = async (host: string): Promise<boolean | null> => {
  const v4 = await tryResolve(() => dnsResolve4(host));
  if (v4 === true) return true;
  const v6 = await tryResolve(() => dnsResolve6(host));
  if (v6 === true) return true;
  // Only call it "does not exist" when both lookups returned a clean NXDOMAIN.
  if (v4 === false && v6 === false) return false;
  return null; // a SERVFAIL/timeout on either — don't risk a false positive
};

/** Resolve helper: true=got records, false=NXDOMAIN/ENODATA, null=other (transient/timeout) error. */
async function tryResolve(fn: () => Promise<string[]>): Promise<boolean | null> {
  try {
    const addrs = await withDnsTimeout(fn());
    return addrs.length > 0;
  } catch (err) {
    if (err instanceof DnsTimeoutError) return null; // inconclusive, not NXDOMAIN
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOTFOUND' || code === 'ENODATA') return false;
    return null;
  }
}

/** Fetch a host's body (https first, then http) for fingerprinting, or null if unreachable. */
const defaultFetchBody = async (host: string): Promise<string | null> => {
  for (const scheme of ['https', 'http'] as const) {
    try {
      const res = await safeFetch(`${scheme}://${host}/`, {
        method: 'GET',
        redirect: 'follow',
        timeoutMs: 7_000,
        maxBytes: 16_000,
      });
      return res.body;
    } catch {
      // try the next scheme
    }
  }
  return null;
};
