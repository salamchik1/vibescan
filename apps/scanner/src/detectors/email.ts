import { resolveTxt as dnsResolveTxt } from 'node:dns/promises';
import type { Finding } from '@vibescan/findings';
import type { CollectResult } from '../collector';
import { isPlatformSubdomain } from '../util/host';
import { withDnsTimeout, DnsTimeoutError } from '../util/dns';

/**
 * Email-authentication detector (the `infra` category).
 *
 * Spoofing protection for a domain lives entirely in public DNS:
 *  - SPF   (a TXT record on the domain)        — which servers may send mail as you.
 *  - DMARC (a TXT record on _dmarc.<domain>)   — what inboxes do with mail that fails.
 *
 * A missing/permissive SPF, or a missing/monitor-only DMARC, means anyone can send
 * phishing that looks like it came from the domain. These are read-only DNS lookups
 * with near-zero false positives, so they make a cheap, high-signal new category.
 *
 * Both lookups go through an injectable resolver so the detector is unit-testable
 * offline (the production resolver is node:dns/promises).
 */

/** TXT resolver shape: returns one entry per record, each a list of string chunks. */
export type TxtResolver = (hostname: string) => Promise<string[][]>;

export interface DetectEmailOptions {
  /** Injectable DNS TXT resolver (tests pass a mock; production uses node:dns). */
  resolveTxt?: TxtResolver;
}

/**
 * Real resolver: collapse DNS's chunked TXT strings and swallow NXDOMAIN/ENODATA
 * as "no records". A timeout is rethrown so the caller can skip the check
 * (inconclusive) rather than report a false "missing SPF/DMARC".
 */
const defaultResolveTxt: TxtResolver = async (hostname) => {
  try {
    return await withDnsTimeout(dnsResolveTxt(hostname));
  } catch (err) {
    if (err instanceof DnsTimeoutError) throw err; // inconclusive — caller skips
    // ENOTFOUND / ENODATA / SERVFAIL — treat as "this name has no TXT records".
    return [];
  }
};

/** Join a TXT record's chunks into one string (DNS splits long strings into 255-char pieces). */
function joinTxt(record: string[]): string {
  return record.join('');
}

/**
 * The domain we test for email auth: the scanned host with a leading `www.` removed
 * (mail is sent from the bare domain, not its www host). Returns null for non-web
 * targets (code-paste scans, IPs) and for platform-issued subdomains (vercel.app,
 * github.io, …) where the user can't control DNS — so a DNS email check is either
 * meaningless or un-actionable.
 */
export function emailDomain(collected: CollectResult): string | null {
  let host = '';
  try {
    host = new URL(collected.finalUrl).hostname;
  } catch {
    try {
      host = new URL(collected.origin).hostname;
    } catch {
      return null;
    }
  }
  if (!host) return null;
  host = host.replace(/^www\./i, '').toLowerCase();
  // Must look like a real registrable name (a dot, no raw IP literal).
  if (!host.includes('.') || /^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return null;
  // Platform subdomains (*.vercel.app etc.): user can't set DNS, no mail sent — skip.
  if (isPlatformSubdomain(host)) return null;
  return host;
}

export async function detectEmail(
  collected: CollectResult,
  opts: DetectEmailOptions = {}
): Promise<Finding[]> {
  const domain = emailDomain(collected);
  if (!domain) return [];
  const resolve = opts.resolveTxt ?? defaultResolveTxt;
  const findings: Finding[] = [];

  // --- SPF: a TXT record on the domain starting with v=spf1 -------------------
  // A failed/timed-out lookup is inconclusive: skip the check rather than report a
  // false "missing" off a resolver that simply didn't answer.
  let txt: string[][];
  try {
    txt = await resolve(domain);
  } catch {
    return findings;
  }
  const spf = txt.map(joinTxt).find((r) => /^v=spf1\b/i.test(r.trim()));
  if (!spf) {
    findings.push({
      type: 'spf_missing',
      severity: 'medium',
      category: 'infra',
      summary: `${domain} has no SPF record — anyone can send email pretending to be your domain.`,
      params: {
        domain,
        reason: 'has no SPF record, so there is nothing stopping anyone from sending mail as you',
      },
    });
  } else if (isPermissiveSpf(spf)) {
    findings.push({
      type: 'spf_missing',
      severity: 'medium',
      category: 'infra',
      summary: `${domain} has an SPF record that allows any server to send as you (+all).`,
      evidence: spf.slice(0, 120),
      params: {
        domain,
        reason: 'publishes an SPF record ending in "+all", which authorises every server on the internet to send mail as you',
      },
    });
  }

  // --- DMARC: a TXT record on _dmarc.<domain> starting with v=DMARC1 ----------
  let dmarcTxt: string[][];
  try {
    dmarcTxt = await resolve(`_dmarc.${domain}`);
  } catch {
    return findings; // inconclusive lookup — skip rather than false-report
  }
  const dmarc = dmarcTxt.map(joinTxt).find((r) => /^v=DMARC1\b/i.test(r.trim()));
  if (!dmarc) {
    findings.push({
      type: 'dmarc_weak',
      severity: 'medium',
      category: 'infra',
      summary: `${domain} has no DMARC record — inboxes get no instructions for mail that forges your address.`,
      params: {
        domain,
        reason: 'has no DMARC record, so Gmail/Outlook get no instructions when an email fails authentication',
      },
    });
  } else if (dmarcPolicy(dmarc) === 'none') {
    findings.push({
      type: 'dmarc_weak',
      severity: 'low',
      category: 'infra',
      summary: `${domain} publishes DMARC at p=none (monitor only) — forged mail is still delivered.`,
      evidence: dmarc.slice(0, 120),
      params: {
        domain,
        reason: 'publishes a DMARC record but only at p=none (monitor-only), so forged mail is still delivered',
      },
    });
  }

  return findings;
}

/**
 * True when an SPF record ends in an "allow everyone" all-mechanism (`+all`, or a
 * bare `all` whose default qualifier is `+`). `-all`/`~all`/`?all` are fine.
 */
function isPermissiveSpf(record: string): boolean {
  const m = /(?:^|\s)([-~?+]?)all(?:\s|$)/i.exec(record.trim());
  if (!m) return false;
  const qualifier = m[1];
  return qualifier === '+' || qualifier === '';
}

/** Extract the lowercased DMARC policy (`p=` tag), or null if absent/unparseable. */
function dmarcPolicy(record: string): string | null {
  const m = /(?:^|;)\s*p\s*=\s*([a-z]+)/i.exec(record);
  return m?.[1] ? m[1].toLowerCase() : null;
}
