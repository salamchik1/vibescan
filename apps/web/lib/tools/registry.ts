/** Single source of truth for the tools listing and cross-tool navigation. */
export interface ToolMeta {
  slug: string;
  title: string;
  blurb: string;
  icon: string;
  /**
   * True when the tool sends your input to our server to reach the network
   * (DNS, TLS, HTTP). Used to show an accurate privacy note instead of the
   * "runs entirely in your browser" one.
   */
  server?: boolean;
}

export const TOOLS: ToolMeta[] = [
  {
    slug: 'jwt',
    title: 'JWT Debugger',
    blurb: 'Decode a token and flag alg:none, never-expiring tokens and sensitive claims.',
    icon: '🪪',
  },
  {
    slug: 'csp',
    title: 'CSP Evaluator',
    blurb: 'Grade a Content-Security-Policy A–F and see exactly what weakens it.',
    icon: '🛡️',
  },
  {
    slug: 'password',
    title: 'Password Strength',
    blurb: 'Estimate entropy and crack time, and catch common, predictable patterns.',
    icon: '🔑',
  },
  {
    slug: 'hash',
    title: 'Hash Generator',
    blurb: 'MD5, SHA-1, SHA-256, SHA-384 and SHA-512 of any text, instantly.',
    icon: '#️⃣',
  },
  {
    slug: 'sri',
    title: 'SRI Hash Generator',
    blurb: 'Build Subresource Integrity tags for your scripts and stylesheets.',
    icon: '🔗',
  },
  {
    slug: 'base64',
    title: 'Base64 Encoder / Decoder',
    blurb: 'Convert text to and from base64, with a URL-safe option.',
    icon: '🔤',
  },
  {
    slug: 'secret-scanner',
    title: 'Secret Scanner',
    blurb: 'Paste code, .env or config and find leaked API keys, tokens and DB passwords.',
    icon: '🔍',
  },
  {
    slug: 'cors',
    title: 'CORS Tester',
    blurb: 'Probe a URL with a forged Origin to catch reflected-origin + credentials misconfigs.',
    icon: '🌐',
    server: true,
  },
  {
    slug: 'ssl',
    title: 'SSL Certificate Checker',
    blurb: 'Inspect a site’s TLS certificate: expiry, issuer, chain and protocol support.',
    icon: '🔏',
    server: true,
  },
  {
    slug: 'email',
    title: 'Email Security Checker',
    blurb: 'Check a domain’s SPF, DMARC and MX records for spoofing protection gaps.',
    icon: '📧',
    server: true,
  },
  {
    slug: 'dns',
    title: 'DNS Security Checker',
    blurb: 'Verify DNSSEC validation and CAA records that lock down who can issue certs.',
    icon: '🧭',
    server: true,
  },
  {
    slug: 'security-txt',
    title: 'security.txt Validator',
    blurb: 'Fetch and validate /.well-known/security.txt against RFC 9116.',
    icon: '📄',
    server: true,
  },
  {
    slug: 'breach',
    title: 'Data Breach Checker',
    blurb: 'See if an email address appears in known breaches, via Have I Been Pwned.',
    icon: '🚨',
    server: true,
  },
];

export function toolBySlug(slug: string): ToolMeta | undefined {
  return TOOLS.find((t) => t.slug === slug);
}
