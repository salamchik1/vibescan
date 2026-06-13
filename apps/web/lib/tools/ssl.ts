// Shared types for the SSL certificate checker (server route ↔ client component).
import type { Check } from '../../components/tools/CheckRow';

export interface SslResult {
  host: string;
  port: number;
  /** Negotiated TLS protocol, e.g. "TLSv1.3". */
  protocol: string | null;
  cipher: string | null;
  subject: string;
  /** Subject Alternative Names. */
  altNames: string[];
  issuer: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  /** Whether the cert covers the host we connected to. */
  hostnameMatches: boolean;
  /** Whether Node trusted the chain (authorized + no error). */
  trusted: boolean;
  authorizationError: string | null;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  summary: string;
  checks: Check[];
}
