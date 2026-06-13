// CSP evaluator. Builds on the scanner's analyzeCsp() weakness check
// (apps/scanner/src/detectors/owasp.ts) and turns it into a graded A–F report
// covering the directives that matter most for XSS and clickjacking defence.

export type CheckStatus = 'pass' | 'warn' | 'fail';
export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';

export interface CspCheck {
  id: string;
  label: string;
  status: CheckStatus;
  detail: string;
  /** Points removed from 100 when this check is not a pass. */
  weight: number;
}

export interface CspReport {
  valid: boolean;
  grade: Grade;
  score: number;
  directives: { name: string; value: string }[];
  checks: CspCheck[];
}

/** Parse a raw policy string into a directive map (lowercased names). */
function parse(csp: string): Map<string, string[]> {
  const map = new Map<string, string[]>();
  for (const part of csp.split(';')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const [name, ...tokens] = trimmed.split(/\s+/);
    map.set(name.toLowerCase(), tokens.map((t) => t.toLowerCase()));
  }
  return map;
}

/** The effective source list for scripts: script-src, else default-src. */
function scriptSources(map: Map<string, string[]>): string[] | null {
  return map.get('script-src') ?? map.get('default-src') ?? null;
}

function gradeFor(score: number): Grade {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 45) return 'D';
  return 'F';
}

export function evaluateCsp(raw: string): CspReport {
  const csp = raw.trim();
  if (!csp) {
    return { valid: false, grade: 'F', score: 0, directives: [], checks: [] };
  }

  const map = parse(csp);
  const directives = Array.from(map.entries()).map(([name, tokens]) => ({
    name,
    value: tokens.join(' '),
  }));

  const scripts = scriptSources(map);
  const hasNonceOrHash = scripts?.some((s) => s.startsWith("'nonce-") || s.startsWith("'sha")) ?? false;
  const hasStrictDynamic = scripts?.includes("'strict-dynamic'") ?? false;
  const checks: CspCheck[] = [];

  // 1) Is script execution constrained at all?
  if (!scripts) {
    checks.push({
      id: 'script-src',
      label: 'Restricts where scripts load from',
      status: 'fail',
      weight: 35,
      detail: 'No script-src or default-src directive, so scripts from anywhere are allowed.',
    });
  } else {
    checks.push({
      id: 'script-src',
      label: 'Restricts where scripts load from',
      status: 'pass',
      weight: 35,
      detail: `Controlled by ${map.has('script-src') ? 'script-src' : 'default-src'}.`,
    });

    // 2) unsafe-inline (the big one) — neutralised if a nonce/hash + strict-dynamic is present.
    if (scripts.includes("'unsafe-inline'")) {
      const mitigated = hasNonceOrHash && hasStrictDynamic;
      checks.push({
        id: 'unsafe-inline',
        label: "Blocks inline scripts ('unsafe-inline')",
        status: mitigated ? 'warn' : 'fail',
        weight: 30,
        detail: mitigated
          ? "'unsafe-inline' is present but ignored by modern browsers because a nonce/hash with 'strict-dynamic' is set. Old browsers still honour it."
          : "'unsafe-inline' lets any injected <script> run — this largely cancels the CSP's XSS protection.",
      });
    } else {
      checks.push({
        id: 'unsafe-inline',
        label: "Blocks inline scripts ('unsafe-inline')",
        status: 'pass',
        weight: 30,
        detail: "No 'unsafe-inline' in the script source list.",
      });
    }

    // 3) unsafe-eval
    checks.push(
      scripts.includes("'unsafe-eval'")
        ? {
            id: 'unsafe-eval',
            label: "Blocks eval() ('unsafe-eval')",
            status: 'fail',
            weight: 15,
            detail: "'unsafe-eval' allows eval()/new Function(), a common XSS sink.",
          }
        : {
            id: 'unsafe-eval',
            label: "Blocks eval() ('unsafe-eval')",
            status: 'pass',
            weight: 15,
            detail: "No 'unsafe-eval' in the script source list.",
          }
    );

    // 4) wildcard / insecure schemes as a script source
    const wildcard = scripts.includes('*');
    const insecureScheme = scripts.some((s) => s === 'http:' || s === 'data:' || s === 'https:');
    if (wildcard || insecureScheme) {
      checks.push({
        id: 'wildcard',
        label: 'No wildcard or scheme-wide script sources',
        status: 'fail',
        weight: 20,
        detail: wildcard
          ? 'A bare * lets scripts load from any host.'
          : 'A scheme source like https:, http: or data: lets scripts load from any host on that scheme.',
      });
    } else {
      checks.push({
        id: 'wildcard',
        label: 'No wildcard or scheme-wide script sources',
        status: 'pass',
        weight: 20,
        detail: 'Script sources are restricted to specific hosts/nonces.',
      });
    }
  }

  // 5) object-src locked down (legacy plugin XSS vector)
  const objectSrc = map.get('object-src') ?? map.get('default-src');
  checks.push(
    objectSrc && objectSrc.includes("'none'")
      ? {
          id: 'object-src',
          label: "object-src 'none'",
          status: 'pass',
          weight: 8,
          detail: 'Plugins/embeds are blocked.',
        }
      : {
          id: 'object-src',
          label: "object-src 'none'",
          status: 'warn',
          weight: 8,
          detail: "Set object-src 'none' to block Flash/embed-based injection.",
        }
  );

  // 6) base-uri (stops <base> tag hijacking of relative script URLs)
  checks.push(
    map.has('base-uri')
      ? {
          id: 'base-uri',
          label: 'base-uri set',
          status: 'pass',
          weight: 7,
          detail: 'A <base> tag cannot be injected to redirect relative URLs.',
        }
      : {
          id: 'base-uri',
          label: 'base-uri set',
          status: 'warn',
          weight: 7,
          detail: "Add base-uri 'none' (or 'self') to stop <base>-tag hijacking.",
        }
  );

  // 7) frame-ancestors (clickjacking)
  checks.push(
    map.has('frame-ancestors')
      ? {
          id: 'frame-ancestors',
          label: 'frame-ancestors set (anti-clickjacking)',
          status: 'pass',
          weight: 10,
          detail: 'Controls who may embed your page in a frame.',
        }
      : {
          id: 'frame-ancestors',
          label: 'frame-ancestors set (anti-clickjacking)',
          status: 'warn',
          weight: 10,
          detail: "Add frame-ancestors 'none' or 'self' to prevent clickjacking.",
        }
  );

  // 8) nonce/hash usage (modern best practice) — informational bonus check.
  checks.push(
    hasNonceOrHash
      ? {
          id: 'nonce',
          label: 'Uses nonces or hashes for inline scripts',
          status: 'pass',
          weight: 5,
          detail: 'Inline scripts are allow-listed individually — the strongest approach.',
        }
      : {
          id: 'nonce',
          label: 'Uses nonces or hashes for inline scripts',
          status: 'warn',
          weight: 5,
          detail: 'Per-response nonces or content hashes are the safest way to allow needed inline scripts.',
        }
  );

  // Score: full credit for passes, half credit for warnings, none for fails.
  const total = checks.reduce((s, c) => s + c.weight, 0);
  const earned = checks.reduce(
    (s, c) => s + (c.status === 'pass' ? c.weight : c.status === 'warn' ? c.weight / 2 : 0),
    0
  );
  const score = Math.round((earned / total) * 100);

  return { valid: true, grade: gradeFor(score), score, directives, checks };
}
