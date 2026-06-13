// Shared types for the email security checker (server route ↔ client component).
import type { Check } from '../../components/tools/CheckRow';

export interface EmailResult {
  domain: string;
  mx: string[];
  spf: string | null;
  dmarc: string | null;
  /** DMARC policy: none | quarantine | reject (parsed from p=). */
  dmarcPolicy: string | null;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  summary: string;
  checks: Check[];
}
