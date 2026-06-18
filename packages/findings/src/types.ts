// Shared contract between the scanner (produces findings) and the web app
// (renders them). One source of truth — change a finding's meaning in one place.

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type Category = 'secrets' | 'database' | 'auth' | 'owasp' | 'infra' | 'code' | 'dependencies';

/**
 * Vibe-coding platforms we tailor fix prompts for. `generic` is the
 * platform-agnostic, step-by-step track for everything else.
 */
export type Platform =
  | 'lovable'
  | 'bolt'
  | 'replit'
  | 'base44'
  | 'v0'
  | 'cursor'
  | 'generic';

export type Verdict = 'red' | 'yellow' | 'green';

/** How a scan was started: against a live URL, against pasted source code, or
 *  against a cloned public Git repository. */
export type ScanMode = 'url' | 'code' | 'repo';

/** Letter grade, A (best) through F (worst). */
export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';

/** Per-category A–F score, shown as a row of grade badges on the report. */
export interface CategoryGrade {
  category: Category;
  grade: Grade;
  /** 0..100 for this category alone (higher is safer). */
  score: number;
  /** How many findings landed in this category. */
  findings: number;
}

/**
 * A developed, copy-pasteable code sample for a specific stack — the "real code"
 * companion to the short fix prompt. Rendered as a labelled, copyable code block.
 */
export interface CodeExample {
  /** Stack/label shown on the tab or heading, e.g. "Supabase (SQL)", "Next.js (App Router)". */
  stack: string;
  /** Language hint for display, e.g. "ts", "sql", "bash", "json". */
  language: string;
  /** The code itself. May contain {{placeholders}} filled from finding.params. */
  code: string;
  /** Optional one-line note shown above the block. */
  note?: string;
}

export type FindingType =
  | 'secret_exposed'
  | 'database_url_exposed'
  | 'supabase_rls_open'
  | 'supabase_storage_public'
  | 'firebase_rules_open'
  | 'auth_unprotected_route'
  | 'auth_client_only'
  | 'bola_idor'
  // JWT weaknesses (the `auth` category). Derived offline from tokens present in
  // the scanned code — no network calls, nothing forged or sent live.
  | 'jwt_alg_none'
  | 'jwt_weak_secret'
  | 'jwt_expired'
  | 'graphql_introspection'
  | 'cors_misconfig'
  | 'insecure_cookie'
  | 'missing_security_headers'
  | 'weak_csp'
  | 'mixed_content'
  | 'exposed_env_file'
  | 'exposed_git'
  | 'exposed_backup'
  | 'exposed_config_file'
  | 'exposed_sourcemap'
  | 'clickjacking'
  // Email + TLS hygiene (the `infra` category). Derived from DNS TXT records and
  // a TLS handshake to the target host — not from its page JS.
  | 'spf_missing'
  | 'dmarc_weak'
  | 'tls_expiring'
  | 'tls_weak_version'
  | 'no_https_redirect'
  // Repository (source-code) scan finding types. A secret found in the git
  // history gets its own type (`secret_committed`) so its explanation can talk
  // about commits and history purging rather than "public JavaScript".
  | 'secret_committed'
  | 'sast_finding'
  | 'vulnerable_dependency';

/**
 * Result of a live, read-only check against the provider that issued a secret.
 * `active`     — the provider accepted the key: it works *right now* and is exploitable.
 * `inactive`   — the provider rejected the key (401/invalid): already revoked or rotated.
 * `unverified` — we could not reach the provider or it answered ambiguously; treat as live.
 */
export type VerificationStatus = 'active' | 'inactive' | 'unverified';

export interface SecretVerification {
  status: VerificationStatus;
  /** The read-only endpoint we queried, shown for transparency (e.g. "GET api.openai.com/v1/models"). */
  checkedEndpoint?: string;
  /** Safe, secret-free note about what the live check found. Never contains the key itself. */
  detail?: string;
  /** ISO timestamp of the liveness check. */
  checkedAt?: string;
}

/** One concrete problem found on the scanned site. Values are already masked. */
export interface Finding {
  type: FindingType;
  /** Severity for THIS instance — may differ from the catalog default
   *  (e.g. an unprotected route is `high` when confirmed, `medium` when only suspected). */
  severity: Severity;
  category: Category;
  /** Short, instance-specific line, e.g. "Stripe secret key (sk_live_****abcd)". */
  summary: string;
  /** Masked snippet or URL path that triggered the finding (safe to display). */
  evidence?: string;
  /** Placeholders consumed by the fix prompt, e.g. { table: "users", provider: "Stripe" }. */
  params?: Record<string, string>;
  /** For exposed secrets: whether a read-only liveness check confirmed the key still works. */
  verification?: SecretVerification;
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ScanResult {
  url: string;
  /** Whether this scan ran against a live URL or pasted code. Defaults to 'url' when absent. */
  mode?: ScanMode;
  /** ISO timestamp of when the scan finished. */
  scannedAt: string;
  /** 0..100 — higher is safer. */
  score: number;
  verdict: Verdict;
  counts: SeverityCounts;
  /** A–F breakdown per category (secrets / database / auth / owasp). */
  categoryGrades?: CategoryGrade[];
  findings: Finding[];
  durationMs: number;
  /** Non-fatal notes (e.g. "site was slow, deep checks skipped"). */
  notes?: string[];
  scannerVersion: string;
}
