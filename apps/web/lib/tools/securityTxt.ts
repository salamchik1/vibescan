// security.txt (RFC 9116) parser + validator. Pure functions: the server route
// fetches the file and hands the text here, so the rules stay testable and free
// of any network/runtime concerns.
import type { Check } from '../../components/tools/CheckRow';

export interface SecurityTxtResult {
  /** Where the file was found. */
  url: string;
  /** Found at the canonical /.well-known/ location (vs. the legacy root path). */
  wellKnown: boolean;
  servedOverHttps: boolean;
  fields: { name: string; value: string }[];
  signed: boolean;
  expires: string | null;
  /** null when there is no Expires field. */
  expired: boolean | null;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  summary: string;
  checks: Check[];
  /** First ~4 KB of the raw file. */
  raw: string;
}

interface Field {
  name: string;
  value: string;
}

/** Parse the body into fields, ignoring comments, blank lines and PGP armor. */
export function parseSecurityTxt(body: string): { fields: Field[]; signed: boolean } {
  const signed = /-----BEGIN PGP SIGNED MESSAGE-----/.test(body);
  const fields: Field[] = [];
  for (const line of body.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-----') || trimmed.startsWith('Hash:')) {
      continue;
    }
    const idx = trimmed.indexOf(':');
    if (idx <= 0) continue;
    const name = trimmed.slice(0, idx).trim();
    const value = trimmed.slice(idx + 1).trim();
    if (!/^[A-Za-z-]+$/.test(name)) continue; // skip armored signature gibberish
    fields.push({ name, value });
  }
  return { fields, signed };
}

function getAll(fields: Field[], name: string): string[] {
  const lower = name.toLowerCase();
  return fields.filter((f) => f.name.toLowerCase() === lower).map((f) => f.value);
}

/** Validate parsed fields against RFC 9116 and build the result. */
export function validateSecurityTxt(opts: {
  url: string;
  wellKnown: boolean;
  servedOverHttps: boolean;
  body: string;
}): SecurityTxtResult {
  const { fields, signed } = parseSecurityTxt(opts.body);
  const checks: Check[] = [];

  const contacts = getAll(fields, 'Contact');
  const expiresValues = getAll(fields, 'Expires');
  const langs = getAll(fields, 'Preferred-Languages');

  // Location (well-known + https).
  checks.push(
    opts.wellKnown
      ? {
          id: 'location',
          label: 'Canonical location',
          status: 'pass',
          detail: 'Served from /.well-known/security.txt as required by RFC 9116.',
        }
      : {
          id: 'location',
          label: 'Canonical location',
          status: 'warn',
          detail: 'Found at /security.txt. RFC 9116 requires the /.well-known/security.txt path.',
        }
  );
  checks.push(
    opts.servedOverHttps
      ? { id: 'https', label: 'Served over HTTPS', status: 'pass', detail: 'The file is served over HTTPS.' }
      : { id: 'https', label: 'Served over HTTPS', status: 'fail', detail: 'The file must be served over HTTPS.' }
  );

  // Contact (required, ≥1).
  if (contacts.length === 0) {
    checks.push({
      id: 'contact',
      label: 'Contact',
      status: 'fail',
      detail: 'No Contact field. At least one is required — a mailto:, https: or tel: URI.',
    });
  } else {
    const allUri = contacts.every((c) => /^(mailto:|https?:|tel:)/i.test(c));
    checks.push({
      id: 'contact',
      label: 'Contact',
      status: allUri ? 'pass' : 'warn',
      detail: allUri
        ? `${contacts.length} contact method(s) provided.`
        : 'Contact values should be URIs (mailto:, https: or tel:).',
    });
  }

  // Expires (exactly one, in the future).
  let expires: string | null = null;
  let expired: boolean | null = null;
  if (expiresValues.length === 0) {
    checks.push({
      id: 'expires',
      label: 'Expires',
      status: 'fail',
      detail: 'No Expires field. RFC 9116 requires exactly one so stale files are obvious.',
    });
  } else {
    expires = expiresValues[0]!;
    const when = new Date(expires);
    if (Number.isNaN(when.getTime())) {
      checks.push({
        id: 'expires',
        label: 'Expires',
        status: 'fail',
        detail: `Expires value "${expires}" is not a valid ISO 8601 / RFC 3339 timestamp.`,
      });
    } else {
      expired = when.getTime() < Date.now();
      if (expiresValues.length > 1) {
        checks.push({
          id: 'expires',
          label: 'Expires',
          status: 'warn',
          detail: 'More than one Expires field. RFC 9116 allows only one.',
        });
      } else {
        checks.push({
          id: 'expires',
          label: 'Expires',
          status: expired ? 'fail' : 'pass',
          detail: expired
            ? `Expired on ${when.toUTCString()}. Update the file with a future date.`
            : `Valid until ${when.toUTCString()}.`,
        });
      }
    }
  }

  // Signature (recommended).
  checks.push(
    signed
      ? { id: 'sig', label: 'Digital signature', status: 'pass', detail: 'The file carries a PGP signature.' }
      : {
          id: 'sig',
          label: 'Digital signature',
          status: 'warn',
          detail: 'Not signed. Signing with PGP (and a Canonical field) lets researchers verify authenticity.',
        }
  );

  // Preferred-Languages (at most one).
  if (langs.length > 1) {
    checks.push({
      id: 'langs',
      label: 'Preferred-Languages',
      status: 'warn',
      detail: 'Only one Preferred-Languages field is allowed; list multiple languages comma-separated.',
    });
  }

  // Recommended extras (informational nudge).
  const recommended = ['Encryption', 'Policy', 'Acknowledgments', 'Canonical'];
  const missingRec = recommended.filter((r) => getAll(fields, r).length === 0);
  if (missingRec.length > 0) {
    checks.push({
      id: 'recommended',
      label: 'Recommended fields',
      status: 'info',
      detail: `Consider adding: ${missingRec.join(', ')}.`,
    });
  }

  // Grade.
  const fail = checks.filter((c) => c.status === 'fail').length;
  const warn = checks.filter((c) => c.status === 'warn').length;
  let grade: SecurityTxtResult['grade'];
  if (fail === 0 && warn === 0) grade = 'A';
  else if (fail === 0 && warn <= 2) grade = 'B';
  else if (fail <= 1) grade = 'C';
  else if (fail <= 2) grade = 'D';
  else grade = 'F';

  const summary =
    grade === 'A'
      ? 'A complete, valid security.txt.'
      : fail > 0
        ? `${fail} requirement(s) not met — see the failed checks below.`
        : 'Valid, with a few recommended improvements.';

  return {
    url: opts.url,
    wellKnown: opts.wellKnown,
    servedOverHttps: opts.servedOverHttps,
    fields,
    signed,
    expires,
    expired,
    grade,
    summary,
    checks,
    raw: opts.body.slice(0, 4096),
  };
}
